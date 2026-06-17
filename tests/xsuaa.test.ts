/**
 * Tests for the XSUAA scope helpers + the @sap/xssec-backed token verifier.
 *
 * Ported from arc-1 `tests/unit/server/xsuaa.test.ts` (the `qualifyXsuaaScopes`
 * describe block) and extended with direct coverage of `createXsuaaTokenVerifier`
 * — arc-1 only exercised XSUAA via mocked chained-verifier inputs, so the package
 * mocks `@sap/xssec` to drive the verifier's scope extraction + AuthInfo mapping.
 *
 * `@sap/xssec` is consumed as `import xssec from '@sap/xssec'; const { XsuaaService } = xssec;`,
 * so the mock supplies a default export with an `XsuaaService` class.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mock @sap/xssec (default-export + destructure interop, SPEC §12) ──
// A controllable security context per test. The verifier calls
// `new XsuaaService(...).createSecurityContext(token, { jwt })` then
// `checkLocalScope`, `getClientId`, `getLogonName`, `getEmail`, `token.payload.exp`.
const securityContextState: {
  scopes: Set<string>;
  clientId: string;
  logonName?: string;
  email?: string;
  exp?: number;
} = { scopes: new Set(), clientId: 'sb-stub' };

const createSecurityContextMock = vi.fn(async () => ({
  checkLocalScope: (scope: string) => securityContextState.scopes.has(scope),
  getClientId: () => securityContextState.clientId,
  getLogonName: () => securityContextState.logonName,
  getEmail: () => securityContextState.email,
  token: { payload: { exp: securityContextState.exp } },
}));

const xsuaaServiceCtor = vi.fn();

vi.mock('@sap/xssec', () => {
  class XsuaaService {
    constructor(creds: unknown) {
      xsuaaServiceCtor(creds);
    }
    createSecurityContext = createSecurityContextMock;
  }
  return { default: { XsuaaService } };
});

// Import AFTER the mock is registered.
const { createXsuaaTokenVerifier, qualifyXsuaaScopes, RESERVED_OAUTH_SCOPES } = await import('../src/index.js');

import { makeCapturingLogger } from './helpers/test-logger.js';

const CREDS = {
  clientid: 'sb-arc1!t1',
  clientsecret: 'stub-secret-40-chars-long-AAAAAAAAAAAAAAAA',
  url: 'https://stub.authentication.eu10.hana.ondemand.com',
  xsappname: 'arc1-mcp!t498139',
  uaadomain: 'authentication.eu10.hana.ondemand.com',
};

describe('qualifyXsuaaScopes', () => {
  const APP = 'arc1-mcp!t498139';

  it('prefixes bare MCP scopes with the xsappname', () => {
    expect(qualifyXsuaaScopes(['read', 'write', 'admin'], APP)).toEqual([
      `${APP}.read`,
      `${APP}.write`,
      `${APP}.admin`,
    ]);
  });

  it('does NOT prefix reserved OIDC scopes (openid/profile/email/offline_access)', () => {
    expect(qualifyXsuaaScopes(['openid', 'read', 'profile', 'email', 'offline_access'], APP)).toEqual([
      'openid',
      `${APP}.read`,
      'profile',
      'email',
      'offline_access',
    ]);
    for (const reserved of RESERVED_OAUTH_SCOPES) {
      expect(qualifyXsuaaScopes([reserved], APP)).toEqual([reserved]);
    }
  });

  it('leaves already-qualified scopes (containing a dot) untouched', () => {
    expect(qualifyXsuaaScopes(['uaa.user', `${APP}.read`], APP)).toEqual(['uaa.user', `${APP}.read`]);
  });

  it('drops empty entries (Copilot Studio sends scope="" -> [""])', () => {
    expect(qualifyXsuaaScopes(['', 'read', ''], APP)).toEqual([`${APP}.read`]);
  });

  it('RESERVED_OAUTH_SCOPES contains exactly the four OIDC/UAA reserved scopes', () => {
    expect([...RESERVED_OAUTH_SCOPES].sort()).toEqual(['email', 'offline_access', 'openid', 'profile']);
  });
});

describe('createXsuaaTokenVerifier (@sap/xssec mocked)', () => {
  beforeEach(() => {
    createSecurityContextMock.mockClear();
    xsuaaServiceCtor.mockClear();
    securityContextState.scopes = new Set();
    securityContextState.clientId = 'sb-stub';
    securityContextState.logonName = undefined;
    securityContextState.email = undefined;
    securityContextState.exp = undefined;
  });

  it('constructs the XsuaaService with the binding credentials', () => {
    createXsuaaTokenVerifier(CREDS);
    expect(xsuaaServiceCtor).toHaveBeenCalledWith({
      clientid: CREDS.clientid,
      clientsecret: CREDS.clientsecret,
      url: CREDS.url,
      xsappname: CREDS.xsappname,
      uaadomain: CREDS.uaadomain,
    });
  });

  it('maps granted local scopes + clientId + user claims into AuthInfo', async () => {
    securityContextState.scopes = new Set(['read', 'write']);
    securityContextState.clientId = 'sb-arc1!t1';
    securityContextState.logonName = 'ALICE';
    securityContextState.email = 'alice@example.com';
    securityContextState.exp = 1_900_000_000;

    const verify = createXsuaaTokenVerifier(CREDS);
    const info = await verify('the-jwt');

    expect(createSecurityContextMock).toHaveBeenCalledWith('the-jwt', { jwt: 'the-jwt' });
    expect(info.token).toBe('the-jwt');
    expect(info.clientId).toBe('sb-arc1!t1');
    expect(info.scopes).toEqual(['read', 'write']);
    expect(info.expiresAt).toBe(1_900_000_000);
    expect(info.extra).toMatchObject({ userName: 'ALICE', email: 'alice@example.com' });
  });

  it('only collects the 7 known MCP scopes (ignores unrelated local scopes)', async () => {
    securityContextState.scopes = new Set([
      'read',
      'data',
      'sql',
      'transports',
      'git',
      'admin',
      'write',
      'somethingelse',
    ]);
    const verify = createXsuaaTokenVerifier(CREDS);
    const info = await verify('jwt');
    expect(info.scopes.sort()).toEqual(['admin', 'data', 'git', 'read', 'sql', 'transports', 'write']);
    expect(info.scopes).not.toContain('somethingelse');
  });

  it('applies the injected expandScopes hook to the extracted scopes', async () => {
    securityContextState.scopes = new Set(['write']);
    const expandScopes = vi.fn((s: string[]) => [...new Set([...s, 'read'])]);
    const verify = createXsuaaTokenVerifier(CREDS, { expandScopes });
    const info = await verify('jwt');
    expect(expandScopes).toHaveBeenCalledWith(['write']);
    expect(info.scopes.sort()).toEqual(['read', 'write']);
  });

  it('leaves expiresAt undefined when the token payload has no numeric exp', async () => {
    securityContextState.scopes = new Set(['read']);
    securityContextState.exp = undefined;
    const verify = createXsuaaTokenVerifier(CREDS);
    const info = await verify('jwt');
    expect(info.expiresAt).toBeUndefined();
  });

  // ── M2: configurable acceptedScopes ──
  it('collects a non-arc-1 scope (e.g. "Viewer") when acceptedScopes is set to it', async () => {
    securityContextState.scopes = new Set(['Viewer']);
    // Default accepted set never probes "Viewer" → empty scopes.
    const defaultVerify = createXsuaaTokenVerifier(CREDS);
    expect((await defaultVerify('jwt')).scopes).toEqual([]);
    // acceptedScopes:['Viewer'] → checkLocalScope('Viewer') is probed and granted.
    const viewerVerify = createXsuaaTokenVerifier(CREDS, { acceptedScopes: ['Viewer'] });
    expect((await viewerVerify('jwt')).scopes).toEqual(['Viewer']);
  });

  // ── S3: never log email / userName (PII) ──
  it('does not log email or userName (PII) at debug', async () => {
    securityContextState.scopes = new Set(['read']);
    securityContextState.clientId = 'sb-arc1!t1';
    securityContextState.logonName = 'ALICE';
    securityContextState.email = 'alice@example.com';

    const logger = makeCapturingLogger();
    const verify = createXsuaaTokenVerifier(CREDS, { logger });
    await verify('jwt');

    const allEntries = [...logger.debugs, ...logger.infos, ...logger.warns, ...logger.errors];
    for (const entry of allEntries) {
      const serialized = `${entry.message} ${JSON.stringify(entry.data ?? {})}`;
      expect(serialized).not.toContain('alice@example.com');
      expect(serialized).not.toContain('ALICE');
    }
    const verified = logger.debugs.find((e) => /XSUAA token verified/.test(e.message));
    expect(verified?.data).toMatchObject({ hasEmail: true, hasUserName: true, scopeCount: 1 });
    expect(verified?.data).not.toHaveProperty('email');
    expect(verified?.data).not.toHaveProperty('userName');
  });
});

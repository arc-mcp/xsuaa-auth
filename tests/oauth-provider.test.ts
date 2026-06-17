/**
 * XsuaaProxyOAuthProvider + createXsuaaOAuthProvider (SPEC §6).
 *
 * Ported from the `createXsuaaOAuthProvider` describe block in arc-1
 * `tests/unit/server/xsuaa.test.ts`. Adaptations for the package:
 *   - the provider/factory are imported from `@arc-mcp/xsuaa-auth`,
 *   - the dcr-signing-source assertions use the package's generic log text + the
 *     injected logger (arc-1's `dcrSigningSource: 'env'` is `'override'` here, and
 *     the message no longer mentions `ARC1_DCR_SIGNING_SECRET`),
 *   - `@sap/xssec` is mocked (the factory builds an XsuaaService verifier).
 *
 * The provider extends the real SDK `ProxyOAuthServerProvider`; the overrides
 * (authorize / exchange* / revoke) are exercised with a stubbed global `fetch` and
 * a stub stateCodec, exactly as arc-1 does.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@sap/xssec', () => {
  class XsuaaService {
    createSecurityContext = vi.fn();
  }
  return { default: { XsuaaService } };
});

const { XsuaaProxyOAuthProvider, createXsuaaOAuthProvider } = await import('../src/index.js');
import type { OAuthStateCodec } from '../src/index.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const STUB_XSUAA_CREDS = {
  clientid: 'sb-stub!t1',
  clientsecret: 'stub-xsuaa-clientsecret-40-chars-long-AAAA',
  url: 'https://stub.authentication.eu10.hana.ondemand.com',
  xsappname: 'arc1',
  uaadomain: 'authentication.eu10.hana.ondemand.com',
  verificationkey: '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----',
};

function mockFetchResponse({
  ok,
  status,
  json,
  text = '',
}: {
  ok: boolean;
  status: number;
  json?: unknown;
  text?: string;
}): Response {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(json),
    text: vi.fn().mockResolvedValue(text),
  } as unknown as Response;
}

type AnyProvider = {
  authorize: (...args: unknown[]) => Promise<void>;
  exchangeAuthorizationCode: (...args: unknown[]) => Promise<Record<string, unknown>>;
  exchangeRefreshToken: (...args: unknown[]) => Promise<Record<string, unknown>>;
  revokeToken: (...args: unknown[]) => Promise<void>;
};

function createTestProxyProvider({
  callbackUrl = 'https://arc1.example.com/oauth/callback',
  stateToken = 'mcp-state-token',
}: { callbackUrl?: string; stateToken?: string } = {}): {
  provider: AnyProvider;
  stateCodec: { encode: ReturnType<typeof vi.fn> };
} {
  const stateCodec = { encode: vi.fn().mockReturnValue(stateToken) };
  const provider = new XsuaaProxyOAuthProvider(
    STUB_XSUAA_CREDS,
    vi.fn() as never,
    { getClient: vi.fn() } as never,
    callbackUrl,
    stateCodec as unknown as OAuthStateCodec,
  );
  return { provider: provider as unknown as AnyProvider, stateCodec };
}

describe('createXsuaaOAuthProvider', () => {
  it('returns the provider, client store, and state codec', () => {
    const result = createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com');
    expect(result.provider).toBeDefined();
    expect(result.clientStore).toBeDefined();
    expect(result.stateCodec).toBeDefined();
  });

  it('defaults to dcrSigningSource: "xsuaa" when dcrSigningSecret is omitted', () => {
    const logger = makeCapturingLogger();
    createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com', { logger });
    const evt = logger.infos.find((i) => /XSUAA OAuth provider created/.test(i.message));
    expect(evt?.data).toMatchObject({ dcrSigningSource: 'xsuaa' });
  });

  it('uses dcrSigningSource: "override" when a valid dcrSigningSecret is provided', () => {
    const logger = makeCapturingLogger();
    createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com', {
      dcrSigningSecret: 'a-real-32-byte-secret-string-OK!',
      logger,
    });
    expect(logger.infos.find((i) => /XSUAA OAuth provider created/.test(i.message))?.data).toMatchObject({
      dcrSigningSource: 'override',
    });
    expect(logger.has('info', /dedicated signing secret/)).toBe(true);
  });

  it('falls back to xsuaa source when dcrSigningSecret is empty string (with warn)', () => {
    const logger = makeCapturingLogger();
    const result = createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com', {
      dcrSigningSecret: '',
      logger,
    });
    expect(result.clientStore).toBeDefined();
    expect(logger.has('warn', /empty or whitespace-only/)).toBe(true);
    expect(logger.infos.find((i) => /XSUAA OAuth provider created/.test(i.message))?.data).toMatchObject({
      dcrSigningSource: 'xsuaa',
    });
  });

  it('falls back to xsuaa source when dcrSigningSecret is whitespace-only (with warn)', () => {
    const logger = makeCapturingLogger();
    createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com', {
      dcrSigningSecret: '   \t  ',
      logger,
    });
    expect(logger.has('warn', /empty or whitespace-only/)).toBe(true);
    expect(logger.infos.find((i) => /XSUAA OAuth provider created/.test(i.message))?.data).toMatchObject({
      dcrSigningSource: 'xsuaa',
    });
  });

  it('emits the TTL-disabled INFO line when dcrTtlSeconds <= 0', () => {
    const logger = makeCapturingLogger();
    createXsuaaOAuthProvider(STUB_XSUAA_CREDS, 'https://arc1.example.com', { dcrTtlSeconds: 0, logger });
    expect(logger.has('info', /DCR client_id TTL is disabled/)).toBe(true);
  });
});

describe('XsuaaProxyOAuthProvider', () => {
  it('authorize redirects to XSUAA with the bound client id, callback URI, qualified scopes, and opaque state', async () => {
    const { provider, stateCodec } = createTestProxyProvider({
      callbackUrl: 'https://arc1.example.com/base/oauth/callback',
    });
    const redirect = vi.fn();

    await provider.authorize(
      { client_id: 'local-client-id', redirect_uris: ['https://client.example.com/callback'] },
      {
        state: 'client+state/with/slash',
        scopes: ['openid', 'read', 'uaa.user', ''],
        codeChallenge: 'challenge-123',
        redirectUri: 'https://client.example.com/callback',
        resource: new URL('https://arc1.example.com/mcp'),
      },
      { redirect },
    );

    const url = new URL(redirect.mock.calls[0]?.[0] as string);
    expect(`${url.origin}${url.pathname}`).toBe(`${STUB_XSUAA_CREDS.url}/oauth/authorize`);
    expect(url.searchParams.get('client_id')).toBe(STUB_XSUAA_CREDS.clientid);
    expect(url.searchParams.get('redirect_uri')).toBe('https://arc1.example.com/base/oauth/callback');
    expect(url.searchParams.get('code_challenge')).toBe('challenge-123');
    // openid stays unqualified; read → arc1.read; uaa.user already qualified; '' dropped.
    expect(url.searchParams.get('scope')).toBe('openid arc1.read uaa.user');
    expect(url.searchParams.get('resource')).toBe('https://arc1.example.com/mcp');
    expect(url.searchParams.get('state')).toBe('mcp-state-token');
    expect(stateCodec.encode).toHaveBeenCalledWith({
      clientState: 'client+state/with/slash',
      clientRedirectUri: 'https://client.example.com/callback',
      clientId: 'local-client-id',
    });
  });

  it('exchanges authorization codes with XSUAA credentials and the proxy callback URI', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockFetchResponse({
        ok: true,
        status: 200,
        json: {
          access_token: 'access-token',
          expires_in: 3600,
          refresh_token: 'refresh-token',
          scope: 'openid arc1.read',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const { provider } = createTestProxyProvider();

    const token = await provider.exchangeAuthorizationCode(
      { client_id: 'local-client-id' },
      'auth-code',
      'verifier',
      'https://client.example.com/callback',
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = new URLSearchParams(init.body as string);
    expect(url).toBe(`${STUB_XSUAA_CREDS.url}/oauth/token`);
    expect(init.method).toBe('POST');
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('auth-code');
    expect(body.get('code_verifier')).toBe('verifier');
    expect(body.get('client_id')).toBe(STUB_XSUAA_CREDS.clientid);
    expect(body.get('client_secret')).toBe(STUB_XSUAA_CREDS.clientsecret);
    // The token-exchange redirect_uri must match the authorize-time one (the proxy callback).
    expect(body.get('redirect_uri')).toBe('https://arc1.example.com/oauth/callback');
    expect(token).toMatchObject({
      access_token: 'access-token',
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: 'refresh-token',
      scope: 'openid arc1.read',
    });
  });

  it('throws a concise error when XSUAA authorization-code exchange fails', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockFetchResponse({ ok: false, status: 502, text: 'bad gateway' }));
    vi.stubGlobal('fetch', fetchMock);
    const logger = makeCapturingLogger();
    const provider = new XsuaaProxyOAuthProvider(
      STUB_XSUAA_CREDS,
      vi.fn() as never,
      { getClient: vi.fn() } as never,
      'https://arc1.example.com/oauth/callback',
      { encode: vi.fn() } as unknown as OAuthStateCodec,
      logger,
    ) as unknown as AnyProvider;

    await expect(provider.exchangeAuthorizationCode({ client_id: 'local-client-id' }, 'auth-code')).rejects.toThrow(
      'XSUAA token exchange failed: 502',
    );
    expect(logger.errors.find((e) => /XSUAA token exchange failed/.test(e.message))?.data).toMatchObject({
      status: 502,
    });
  });

  it('exchanges refresh tokens with XSUAA credentials', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockFetchResponse({
        ok: true,
        status: 200,
        json: { access_token: 'fresh-access', token_type: 'bearer', refresh_token: 'fresh-refresh' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const { provider } = createTestProxyProvider();

    const token = await provider.exchangeRefreshToken({ client_id: 'local-client-id' }, 'old-refresh');

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = new URLSearchParams(init.body as string);
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('old-refresh');
    expect(body.get('client_id')).toBe(STUB_XSUAA_CREDS.clientid);
    expect(token).toMatchObject({ access_token: 'fresh-access', refresh_token: 'fresh-refresh' });
  });

  it('warns but does not throw when revocation returns a non-2xx response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockFetchResponse({ ok: false, status: 400, text: 'bad token' }));
    vi.stubGlobal('fetch', fetchMock);
    const logger = makeCapturingLogger();
    const provider = new XsuaaProxyOAuthProvider(
      STUB_XSUAA_CREDS,
      vi.fn() as never,
      { getClient: vi.fn() } as never,
      'https://arc1.example.com/oauth/callback',
      { encode: vi.fn() } as unknown as OAuthStateCodec,
      logger,
    ) as unknown as AnyProvider;

    await provider.revokeToken({ client_id: 'local-client-id' }, { token: 'tok', token_type_hint: 'access_token' });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = new URLSearchParams(init.body as string);
    expect(url).toBe(`${STUB_XSUAA_CREDS.url}/oauth/revoke`);
    expect(init.headers).toMatchObject({
      Authorization: `Basic ${Buffer.from(`${STUB_XSUAA_CREDS.clientid}:${STUB_XSUAA_CREDS.clientsecret}`).toString('base64')}`,
    });
    expect(body.get('token')).toBe('tok');
    expect(body.get('token_type_hint')).toBe('access_token');
    expect(logger.warns.find((w) => /XSUAA token revocation failed/.test(w.message))?.data).toMatchObject({
      status: 400,
    });
  });

  it('logs revocation network errors without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));
    const logger = makeCapturingLogger();
    const provider = new XsuaaProxyOAuthProvider(
      STUB_XSUAA_CREDS,
      vi.fn() as never,
      { getClient: vi.fn() } as never,
      'https://arc1.example.com/oauth/callback',
      { encode: vi.fn() } as unknown as OAuthStateCodec,
      logger,
    ) as unknown as AnyProvider;

    await expect(provider.revokeToken({ client_id: 'local-client-id' }, { token: 'tok' })).resolves.toBeUndefined();
    expect(logger.warns.find((w) => /XSUAA token revocation error/.test(w.message))?.data).toMatchObject({
      error: 'network down',
    });
  });
});

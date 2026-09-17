/** Real SAP signature/expiry/audience validation; only remote JWKS retrieval is stubbed. */

import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import xssec from '@sap/xssec';
import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createChainedTokenVerifier, createXsuaaTokenVerifier, XsuaaUserTokenRequiredError } from '../src/index.js';
import { InvalidTokenError, requireBearerAuth } from '../src/internal/sdk.js';
import * as attributes from '../src/xsuaa-user-attributes.js';
import { expectMalformedVerifier, malformedScopes } from './helpers/malformed-verifier.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

const CREDS = {
  clientid: 'sb-first-app!t123',
  clientsecret: 'test-only-secret',
  xsappname: 'first-app!t123',
  url: 'https://tenant.authentication.example.invalid',
  uaadomain: 'authentication.example.invalid',
};

describe('new verifier options with real @sap/xssec 4.x validation', () => {
  let key: CryptoKey;
  let unrelatedKey: CryptoKey;
  const fetchJwks = vi.spyOn(xssec.XsuaaService.prototype, 'fetchJwks');

  beforeAll(async () => {
    const pair = await generateKeyPair('RS256');
    key = pair.privateKey;
    unrelatedKey = (await generateKeyPair('RS256')).privateKey;
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'pr677-verification-test', alg: 'RS256', use: 'sig' };
    fetchJwks.mockResolvedValue({ keys: [jwk] });
  });

  afterAll(() => fetchJwks.mockRestore());

  async function token(
    payload: Record<string, unknown> = {},
    signingKey?: CryptoKey,
    audience: string | string[] = CREDS.xsappname,
  ) {
    return new SignJWT({
      grant_type: 'authorization_code',
      origin: 'ias-test',
      user_name: 'test-user',
      user_id: 'synthetic-test-user-id',
      cid: CREDS.clientid,
      client_id: CREDS.clientid,
      zid: 'pr677-local-verification-zone',
      scope: [`${CREDS.xsappname}.read`],
      'xs.user.attributes': { arc1_targets: ['A4H/001'] },
      ...payload,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'pr677-verification-test' })
      .setIssuer(`${CREDS.url}/oauth/token`)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(typeof payload.exp === 'number' ? payload.exp : '5m')
      .sign(signingKey ?? key);
  }

  const verifier = () =>
    createXsuaaTokenVerifier(CREDS, { userAttributeNames: ['arc1_targets'], requireUserToken: true });

  it.each(malformedScopes)(
    'rejects malformed XSUAA expanded scopes directly and in the chain: $label',
    async ({ scopes }) => {
      const jwt = await token();
      const logger = makeCapturingLogger();
      const verify = createXsuaaTokenVerifier(CREDS, { expandScopes: () => scopes as string[], logger });
      const fallback = vi.fn().mockResolvedValue({ token: jwt, clientId: 'fallback', scopes: ['admin'] });
      await expectMalformedVerifier(verify, jwt);
      await expectMalformedVerifier(createChainedTokenVerifier({}, verify, fallback, { logger }), jwt);
      expect(fallback).not.toHaveBeenCalled();
      expect(logger.warns).toContainEqual({
        message: 'Verifier integration failure',
        data: { method: 'XSUAA', reason: 'malformed_auth_info' },
      });
      expect(JSON.stringify(logger)).not.toContain(jwt);
      expect(JSON.stringify(logger)).not.toContain('A4H/001');
    },
  );

  it('keeps a raw throwing scope callback as an ordinary XSUAA failure', async () => {
    const jwt = await token();
    const verify = createXsuaaTokenVerifier(CREDS, {
      expandScopes: () => {
        throw new Error('callback failed');
      },
    });
    const fallback = vi.fn().mockResolvedValue({ token: jwt, clientId: 'fallback', scopes: ['read'] });
    expect((await createChainedTokenVerifier({}, verify, fallback)(jwt)).scopes).toEqual(['read']);
    expect(fallback).toHaveBeenCalledOnce();
  });

  it.each(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'])(
    'validates signed user fixture with %s grant',
    async (grant_type) => {
      const result = await verifier()(await token({ grant_type }));
      expect(result.scopes).toEqual(['read']);
      expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/001'] });
      expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'valid' });
    },
  );

  it('uses the SDK verified ext_cxt accessor precedence', async () => {
    const result = await verifier()(await token({ ext_cxt: { 'xs.user.attributes': { arc1_targets: ['A4H/100'] } } }));
    expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/100'] });
  });

  it('records missing for a falsy scalar collapsed by SAP getAttribute()', async () => {
    const result = await verifier()(await token({ 'xs.user.attributes': { arc1_targets: '' } }));
    expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'missing' });
  });

  it('rejects a wrong signature before reading its user grants', async () => {
    await expect(verifier()(await token({}, unrelatedKey))).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects an expired signed token before extracting attributes', async () => {
    await expect(verifier()(await token({ exp: Math.floor(Date.now() / 1_000) - 3_600 }))).rejects.toBeInstanceOf(
      InvalidTokenError,
    );
  });

  it('rejects a valid signed token issued only for another app', async () => {
    const other = { ...CREDS, clientid: 'sb-other-app!t456', xsappname: 'other-app!t456' };
    const otherVerifier = createXsuaaTokenVerifier(other, {
      userAttributeNames: ['arc1_targets'],
      requireUserToken: true,
    });
    await expect(otherVerifier(await token())).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('does not treat another app local scopes as this app scopes', async () => {
    const result = await verifier()(await token({ scope: ['other-app!t456.admin', 'other-app!t456.read'] }));
    expect(result.scopes).toEqual([]);
  });

  it.each([false, true])('preserves SAP multi-audience null client IDs (user options=%s)', async (enabled) => {
    const check = enabled ? verifier() : createXsuaaTokenVerifier(CREDS);
    const jwt = await token({}, undefined, [CREDS.xsappname, 'uaa']);
    const direct = await check(jwt);
    expect(direct.clientId).toBeNull();
    expect(direct.scopes).toEqual(['read']);
    const oidc = vi.fn().mockResolvedValue({ token: jwt, clientId: 'other', scopes: ['admin'] });
    const chain = createChainedTokenVerifier({}, check, oidc);
    const chained = await chain(jwt);
    expect(chained.clientId).toBeNull();
    expect(chained.scopes).toEqual(['read']);
    expect((await chain(await token())).clientId).toBe(CREDS.xsappname);
    const app = express();
    app.get('/mcp', requireBearerAuth({ verifier: { verifyAccessToken: chain } }), (_req, res) =>
      res.json({ ok: true }),
    );
    expect((await request(app).get('/mcp').set('Authorization', `Bearer ${jwt}`)).status).toBe(200);
    expect(oidc).not.toHaveBeenCalled();
  });

  it('rejects a validated client-credentials token even with forged-looking user hints and admin', async () => {
    await expect(
      verifier()(
        await token({
          grant_type: 'client_credentials',
          scope: [`${CREDS.xsappname}.admin`],
          email: 'user@example.invalid',
        }),
      ),
    ).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
  });

  it('rejects a validated unknown-grant token as a principal failure, not an invalid signature', async () => {
    await expect(verifier()(await token({ grant_type: 'unknown' }))).rejects.toBeInstanceOf(
      XsuaaUserTokenRequiredError,
    );
  });

  it.each(
    ['both', 'attributes only', 'principal only'].flatMap((mode) =>
      ['wrong signature', 'expired', 'wrong audience'].map((failure) => ({ mode, failure })),
    ),
  )('validates an unsupported machine before classification: $failure, $mode', async ({ mode, failure }) => {
    const jwt = await token(
      { grant_type: 'client_credentials', ...(failure === 'expired' ? { exp: 1 } : {}) },
      failure === 'wrong signature' ? unrelatedKey : key,
    );
    const check = createXsuaaTokenVerifier(
      failure === 'wrong audience' ? { ...CREDS, clientid: 'other!t456', xsappname: 'other!t456' } : CREDS,
      {
        ...(mode !== 'attributes only' ? { requireUserToken: true } : {}),
        ...(mode !== 'principal only' ? { userAttributeNames: ['arc1_targets'] } : {}),
      },
    );
    const classify = vi.spyOn(xssec.XsuaaSecurityContext.prototype, 'getGrantType');
    const extract = vi.spyOn(attributes, 'extractXsuaaUserAttributes');
    try {
      await expect(check(jwt)).rejects.toBeInstanceOf(InvalidTokenError);
      expect(classify).not.toHaveBeenCalled();
      expect(extract).not.toHaveBeenCalled();
    } finally {
      classify.mockRestore();
      extract.mockRestore();
    }
  });

  it.each(['attributes only', 'principal only', 'neither'])(
    'accepts a valid user with %s without coupling the options',
    async (mode) => {
      const result = await createXsuaaTokenVerifier(
        CREDS,
        mode === 'attributes only'
          ? { userAttributeNames: ['arc1_targets'] }
          : mode === 'principal only'
            ? { requireUserToken: true }
            : {},
      )(await token());
      expect(result.scopes).toEqual(['read']);
      if (mode === 'attributes only') {
        expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/001'] });
        expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'valid' });
      } else {
        expect(result.extra).not.toHaveProperty('xsuaaUserAttributes');
        expect(result.extra).not.toHaveProperty('xsuaaUserAttributeStatus');
      }
    },
  );

  it.each(['direct', 'chained'])('maps a verified forbidden principal to HTTP 403 (%s)', async (mode) => {
    const jwt = await token({ grant_type: 'client_credentials' });
    const check = verifier();
    const oidc = vi.fn().mockResolvedValue({ token: jwt, scopes: ['read'], clientId: 'other' });
    const verifyAccessToken = mode === 'direct' ? check : createChainedTokenVerifier({}, check, oidc);
    const app = express();
    app.get('/mcp', requireBearerAuth({ verifier: { verifyAccessToken } }), (_req, res) => res.sendStatus(200));
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    try {
      const response = await request(server).get('/mcp').set('Authorization', `Bearer ${jwt}`);
      expect(response.status).toBe(403);
      expect(response.body.error).toBe('forbidden');
      expect(response.headers['www-authenticate']).toContain('error="forbidden"');
      expect(oidc).not.toHaveBeenCalled();
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it.each(['interactive', 'machine'])(
    'does not make the MCP %s client reauthorize a forbidden principal',
    async (mode) => {
      const jwt = await token({ grant_type: 'client_credentials' });
      const app = express();
      app.post(
        '/mcp',
        requireBearerAuth({ verifier: { verifyAccessToken: verifier() }, requiredScopes: ['read'] }),
        (_req, res) => res.sendStatus(202),
      );
      const server = app.listen(0, '127.0.0.1');
      await new Promise<void>((resolve) => server.once('listening', resolve));
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Missing local test listener');
      const url = new URL(`http://127.0.0.1:${address.port}/mcp`);
      const redirectToAuthorization = vi.fn();
      const saveTokens = vi.fn();
      const fetchToken = vi.fn(() => new URLSearchParams({ grant_type: 'client_credentials' }));
      const transportFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        // Exercise actual middleware and transport. Never contact an external AS.
        if (String(input) === url.href) return fetch(input, init);
        return new Response(null, { status: 404 });
      });
      const transport = new StreamableHTTPClientTransport(url, {
        authProvider: {
          redirectUrl: mode === 'interactive' ? 'http://127.0.0.1/callback' : undefined,
          clientMetadata: { redirect_uris: ['http://127.0.0.1/callback'] },
          clientInformation: () => ({ client_id: 'test-client' }),
          tokens: () => ({ access_token: jwt, token_type: 'Bearer' }),
          saveTokens,
          redirectToAuthorization,
          saveCodeVerifier: vi.fn(),
          codeVerifier: () => 'test-verifier',
          prepareTokenRequest: fetchToken,
        },
        fetch: transportFetch,
      });
      try {
        await transport.start();
        // SDK 1.18 reports HTTP failures as plain Error (newer peers add .code).
        await expect(transport.send({ jsonrpc: '2.0', method: 'notifications/test' })).rejects.toThrow(/forbidden/);
        expect(transportFetch).toHaveBeenCalledTimes(1);
        expect(redirectToAuthorization).not.toHaveBeenCalled();
        expect(saveTokens).not.toHaveBeenCalled();
        expect(fetchToken).not.toHaveBeenCalled();
      } finally {
        await transport.close();
        await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
      }
    },
  );

  it('keeps an ordinary missing-scope challenge as insufficient_scope', async () => {
    const app = express();
    app.get(
      '/mcp',
      requireBearerAuth({ verifier: { verifyAccessToken: verifier() }, requiredScopes: ['admin'] }),
      (_req, res) => res.sendStatus(200),
    );
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    try {
      const response = await request(server)
        .get('/mcp')
        .set('Authorization', `Bearer ${await token()}`);
      expect(response.status).toBe(403);
      expect(response.body.error).toBe('insufficient_scope');
      // Older supported peers omit the optional scope parameter in this header.
      expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it.each(
    ['creating security context', 'principal rejected', 'token verified'].flatMap((stage) =>
      [false, true].map((asyncFailure) => ({ stage, asyncFailure })),
    ),
  )(
    'a failing diagnostic logger cannot change principal enforcement at $stage (async=$asyncFailure)',
    async ({ stage, asyncFailure }) => {
      const logger = {
        ...makeCapturingLogger(),
        debug: vi.fn((message: string) => {
          if (message.includes(stage)) {
            const error = new Error('diagnostic sink unavailable');
            if (asyncFailure) return Promise.reject(error);
            throw error;
          }
        }),
      };
      const check = createXsuaaTokenVerifier(CREDS, { requireUserToken: true, logger });
      const jwt = await token({ grant_type: 'client_credentials' });
      const oidc = vi.fn().mockResolvedValue({ token: jwt, clientId: 'other', scopes: ['admin'] });
      const chain = createChainedTokenVerifier({}, check, oidc);
      await expect(chain(jwt)).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
      expect(oidc).not.toHaveBeenCalled();
      expect((await check(await token())).scopes).toEqual(['read']);
    },
  );

  it.each([false, true])('never grants inherited local scopes, with options enabled=%s', async (enabled) => {
    const jwt = await token({ scope: undefined });
    const control = await token();
    const check = enabled ? verifier() : createXsuaaTokenVerifier(CREDS);
    Object.defineProperty(Object.prototype, 'scope', { value: [`${CREDS.xsappname}.admin`], configurable: true });
    try {
      expect((await check(jwt)).scopes).toEqual([]);
      expect((await check(control)).scopes).toEqual(['read']);
    } finally {
      Reflect.deleteProperty(Object.prototype, 'scope');
    }
  });

  it.each(['direct', 'chained'])('preserves HTTP 200/401 for valid/invalid tokens (%s)', async (mode) => {
    const check = verifier();
    const verifyAccessToken = mode === 'direct' ? check : createChainedTokenVerifier({}, check);
    const app = express();
    app.get('/mcp', requireBearerAuth({ verifier: { verifyAccessToken } }), (_req, res) => res.sendStatus(200));
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    try {
      const accepted = await request(server)
        .get('/mcp')
        .set('Authorization', `Bearer ${await token()}`);
      expect(accepted.status).toBe(200);
      const rejected = await request(server)
        .get('/mcp')
        .set('Authorization', `Bearer ${await token({}, unrelatedKey)}`);
      expect(rejected.status).toBe(401);
      expect(rejected.body.error).toBe('invalid_token');
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it('does not classify unverified machine claims to deny an independent verifier', async () => {
    const jwt = await token({ grant_type: 'client_credentials' }, unrelatedKey);
    const authenticatedElsewhere = { token: jwt, clientId: 'independent-app', scopes: [] };
    const alternative = vi.fn().mockResolvedValue(authenticatedElsewhere);
    const chain = createChainedTokenVerifier({}, verifier(), alternative);
    expect(await chain(jwt)).toBe(authenticatedElsewhere);
    expect(alternative).toHaveBeenCalledWith(jwt);
  });

  it('logs a fixed principal-denial reason without attributes or user identifiers', async () => {
    const logger = makeCapturingLogger();
    const check = createXsuaaTokenVerifier(CREDS, { requireUserToken: true, logger });
    const jwt = await token({ grant_type: 'client_credentials', 'xs.user.attributes': { arc1_targets: ['SECRET'] } });
    await expect(check(jwt)).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
    expect(logger.debugs).toContainEqual({
      message: 'XSUAA principal rejected',
      data: { code: 'XSUAA_USER_TOKEN_REQUIRED' },
    });
    const logged = JSON.stringify(logger);
    for (const secret of [jwt, 'test-user', 'ias-test', 'arc1_targets', 'SECRET']) expect(logged).not.toContain(secret);
  });

  it.each(['attribute name', 'root claim', 'extension claim', 'extension container'])(
    'does not promote inherited %s to signed grants',
    async (level) => {
      const payload = {
        'xs.user.attributes': level === 'attribute name' ? {} : undefined,
        ...(level === 'extension claim' ? { ext_cxt: {} } : {}),
      };
      const jwt = await token(payload);
      const name =
        level === 'attribute name'
          ? 'arc1_targets'
          : level === 'extension container'
            ? 'ext_cxt'
            : 'xs.user.attributes';
      const value =
        level === 'attribute name'
          ? ['*']
          : level === 'extension container'
            ? { 'xs.user.attributes': { arc1_targets: ['*'] } }
            : { arc1_targets: ['*'] };
      Object.defineProperty(Object.prototype, name, { value, configurable: true });
      try {
        const result = await verifier()(jwt);
        expect(result.extra?.xsuaaUserAttributes).toEqual({});
        expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'missing' });
      } finally {
        Reflect.deleteProperty(Object.prototype, name);
      }
    },
  );

  it.each(
    [['grant_type'], ['origin'], ['user_name'], ['grant_type', 'origin', 'user_name']].map((fields) => ({ fields })),
  )('does not classify inherited $fields as signed user evidence', async ({ fields }) => {
    const jwt = await token(Object.fromEntries(fields.map((field) => [field, undefined])));
    const valid = await token();
    await expect(verifier()(jwt)).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
    for (const field of fields) {
      const inherited = field === 'grant_type' ? 'authorization_code' : 'inherited-user-evidence';
      Object.defineProperty(Object.prototype, field, { value: inherited, configurable: true });
    }
    try {
      await expect(verifier()(jwt)).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
      const extracted = await createXsuaaTokenVerifier(CREDS, { userAttributeNames: ['arc1_targets'] })(jwt);
      expect(extracted.extra?.xsuaaUserAttributes).toEqual({});
      expect(extracted.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'missing' });
      const ownEvidence = await verifier()(valid);
      expect(ownEvidence.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/001'] });
    } finally {
      for (const field of fields) Reflect.deleteProperty(Object.prototype, field);
    }
  });

  it.each([['value'], 'value', false, 42].map((container) => ({ container })))(
    'rejects malformed attribute container $container',
    async ({ container }) => {
      const result = await createXsuaaTokenVerifier(CREDS, { userAttributeNames: ['0'], requireUserToken: true })(
        await token({ 'xs.user.attributes': container }),
      );
      expect(result.extra?.xsuaaUserAttributes).toEqual({});
      expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ 0: 'invalid' });
    },
  );

  it.each([
    { ext_cxt: null, expected: ['A4H/001'], status: 'valid' },
    { ext_cxt: {}, expected: ['A4H/001'], status: 'valid' },
    { ext_cxt: { unrelated: 'value' }, expected: ['A4H/001'], status: 'valid' },
    { ext_cxt: { 'xs.user.attributes': null }, expected: ['A4H/001'], status: 'valid' },
    { ext_cxt: { 'xs.user.attributes': {} }, expected: undefined, status: 'missing' },
    { ext_cxt: { 'xs.user.attributes': false }, expected: undefined, status: 'invalid' },
    { ext_cxt: [], expected: undefined, status: 'invalid' },
    { ext_cxt: 'invalid', expected: undefined, status: 'invalid' },
  ])('pins extension precedence for $ext_cxt', async ({ ext_cxt, expected, status }) => {
    const result = await verifier()(await token({ ext_cxt }));
    expect(result.extra?.xsuaaUserAttributes).toEqual(expected ? { arc1_targets: expected } : {});
    expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: status });
  });

  it('documents audience delegation without claiming same-client attribute provenance', async () => {
    const foreign = 'sb-other-app!t456';
    const result = await verifier()(
      await token({
        cid: foreign,
        client_id: foreign,
        azp: foreign,
        scope: [],
        'xs.user.attributes': { arc1_targets: ['*'] },
      }),
    );
    expect(result.clientId).toBe(foreign);
    expect(result.scopes).toEqual([]);
    expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['*'] });
  });
});

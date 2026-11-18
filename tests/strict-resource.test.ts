import xssec from '@sap/xssec';
import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createChainedTokenVerifier,
  createXsuaaOAuthProvider,
  createXsuaaTokenVerifier,
  OAuthStateCodec,
  setupHttpAuth,
  XsuaaProxyOAuthProvider,
  XsuaaResourceMismatchError,
} from '../src/index.js';
import { mcpAuthRouter } from '../src/internal/sdk.js';
import { consentFields, responseCookies } from './helpers/oauth-consent.js';

const credentials = {
  clientid: 'sb-resource-test!t123',
  clientsecret: 'fixture-only-resource-secret',
  xsappname: 'resource-test!t123',
  url: 'https://stub.invalid',
  uaadomain: 'stub.invalid',
};
const resourceA = 'https://one.invalid/mcp';

describe('opt-in XSUAA resource isolation', () => {
  let signingKey: CryptoKey;
  const fetchJwks = vi.spyOn(xssec.XsuaaService.prototype, 'fetchJwks');

  beforeAll(async () => {
    const pair = await generateKeyPair('RS256');
    signingKey = pair.privateKey;
    fetchJwks.mockResolvedValue({
      keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'strict-resource-fixture', alg: 'RS256', use: 'sig' }],
    });
  });
  afterAll(() => fetchJwks.mockRestore());

  async function token(audience: string | string[]) {
    return new SignJWT({
      grant_type: 'authorization_code',
      origin: 'fixture',
      user_name: 'fixture-user',
      user_id: 'fixture-id',
      cid: credentials.clientid,
      client_id: credentials.clientid,
      zid: 'fixture-zone',
      scope: [`${credentials.xsappname}.read`],
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'strict-resource-fixture' })
      .setIssuer(`${credentials.url}/oauth/token`)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
  }

  function app(host: string, strictResource: boolean) {
    const server = express();
    const guard = setupHttpAuth(server, {
      xsuaa: { credentials, appUrl: `https://${host}`, strictResource, requiredScopes: ['read'] },
      apiKeys: [{ key: 'fixture-api-key', scopes: ['read'] }],
      required: true,
    });
    server.get('/mcp', guard, (req, res) => res.json({ scopes: req.auth?.scopes, resource: req.auth?.resource }));
    return server;
  }

  it('rejects a signed token for another MCP URL while preserving the legacy default and API keys', async () => {
    const jwt = await token([credentials.xsappname, resourceA]);
    const one = await request(app('one.invalid', true)).get('/mcp').set('Authorization', `Bearer ${jwt}`);
    const two = await request(app('two.invalid', true)).get('/mcp').set('Authorization', `Bearer ${jwt}`);
    const legacy = await request(app('two.invalid', false)).get('/mcp').set('Authorization', `Bearer ${jwt}`);
    const apiKey = await request(app('two.invalid', true)).get('/mcp').set('Authorization', 'Bearer fixture-api-key');
    expect(one.status).toBe(200);
    expect(one.body.resource).toBe(resourceA);
    expect(two.status).toBe(401);
    expect(two.body.error).toBe('invalid_token');
    expect(legacy.status).toBe(200);
    expect(apiKey.status).toBe(200);
  });

  it('fails closed for an application-only audience and never tries another verifier after a resource mismatch', async () => {
    const jwt = await token(credentials.xsappname);
    const fallback = vi.fn().mockResolvedValue({ token: jwt, clientId: 'fallback', scopes: ['admin'] });
    const verify = createChainedTokenVerifier(
      {},
      createXsuaaTokenVerifier(credentials, { expectedResource: resourceA }),
      fallback,
    );
    await expect(verify(jwt)).rejects.toBeInstanceOf(XsuaaResourceMismatchError);
    expect(fallback).not.toHaveBeenCalled();
    const response = await request(app('one.invalid', true)).get('/mcp').set('Authorization', `Bearer ${jwt}`);
    expect(response.status).toBe(401);
  });

  it('rejects invalid strict-mode configuration at startup', () => {
    expect(() => app('one.invalid', 'false' as unknown as boolean)).toThrow('xsuaa.strictResource must be a boolean');
    expect(() => createXsuaaTokenVerifier(credentials, { expectedResource: 'https://one.invalid/mcp?x=1' })).toThrow(
      'expectedResource must be a canonical HTTPS URL',
    );
    expect(() =>
      createXsuaaOAuthProvider(credentials, 'https://proxy.invalid', { expectedResource: resourceA }),
    ).toThrow('expectedResource must use the appUrl origin');
  });
});

describe('strict OAuth proxy resource binding', () => {
  const appUrl = 'https://proxy.invalid';
  const first = `${appUrl}/a/mcp`;
  const second = `${appUrl}/b/mcp`;
  const redirectUri = 'https://client.invalid/cb';

  function provider(expectedResource: string) {
    return createXsuaaOAuthProvider(credentials, appUrl, { expectedResource });
  }

  it('requires its own resource on authorize and forwards it on code and refresh exchange', async () => {
    const auth = provider(first);
    const server = express();
    server.use(mcpAuthRouter({ provider: auth.provider, issuerUrl: new URL(appUrl) }));
    const registered = await request(server)
      .post('/register')
      .send({ client_name: 'Fixture', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' });
    expect(registered.status).toBe(201);
    const params = {
      client_id: registered.body.client_id,
      redirect_uri: redirectUri,
      response_type: 'code',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
    };
    for (const resource of [undefined, second]) {
      const response = await request(server)
        .get('/authorize')
        .query({ ...params, resource });
      expect(response.status).toBe(302);
      expect(new URL(response.headers.location).searchParams.get('error')).toBe('invalid_target');
    }
    const page = await request(server)
      .get('/authorize')
      .query({ ...params, resource: first });
    expect(page.status).toBe(200);
    const approved = await request(server)
      .post('/authorize')
      .set('Origin', appUrl)
      .set('Cookie', responseCookies(page))
      .type('form')
      .send({ ...consentFields(page.text), consent_action: 'approve' });
    expect(approved.status).toBe(302);
    expect(new URL(approved.headers.location).searchParams.get('resource')).toBe(first);

    const client = await auth.clientStore.getClient(registered.body.client_id);
    if (!client) throw new Error('Fixture registration missing');
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      const form = new URLSearchParams(init.body as string);
      expect(form.get('resource')).toBe(first);
      return Response.json(
        form.get('grant_type') === 'authorization_code'
          ? { access_token: 'fixture-access', refresh_token: 'fixture-refresh' }
          : { access_token: 'fixture-renewed' },
      );
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const code = auth.stateCodec.authorizationCodes.encode('fixture-code', client.client_id, redirectUri);
      const issued = await auth.provider.exchangeAuthorizationCode(client, code, 'v'.repeat(64), redirectUri);
      expect(issued.refresh_token).toMatch(/^mcp-refresh-/);
      await auth.provider.exchangeRefreshToken(client, issued.refresh_token ?? '');
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('rejects another resource’s signed state, code, and refresh envelope before XSUAA', async () => {
    const a = provider(first);
    const b = provider(second);
    const client = await a.clientStore.getClient(credentials.clientid);
    if (!client) throw new Error('Fixture client missing');
    const state = a.stateCodec.encode({ clientId: client.client_id, clientRedirectUri: redirectUri });
    expect(b.stateCodec.decode(state)).toMatchObject({ kind: 'error', reason: 'bad_signature' });
    const code = a.stateCodec.authorizationCodes.encode('fixture-code', client.client_id, redirectUri);
    const fetchMock = vi
      .fn()
      .mockResolvedValue(Response.json({ access_token: 'fixture-access', refresh_token: 'fixture-refresh' }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      await expect(b.provider.exchangeAuthorizationCode(client, code, 'v'.repeat(64), redirectUri)).rejects.toThrow();
      const issued = await a.provider.exchangeAuthorizationCode(client, code, 'v'.repeat(64), redirectUri);
      await expect(b.provider.exchangeRefreshToken(client, issued.refresh_token ?? '')).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('does not trust an unbound verifier supplied to the direct provider constructor', async () => {
    const stateCodec = new OAuthStateCodec(credentials.clientsecret, { resourceBinding: first });
    const direct = new XsuaaProxyOAuthProvider(
      credentials,
      async (value) => ({ token: value, clientId: credentials.clientid, scopes: [] }),
      provider(first).clientStore,
      `${appUrl}/oauth/callback`,
      stateCodec,
      undefined,
      { expectedResource: first },
    );
    await expect(direct.verifyAccessToken('fixture-token')).rejects.toBeInstanceOf(XsuaaResourceMismatchError);
  });
});

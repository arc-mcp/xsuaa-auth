import express from 'express';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createXsuaaOAuthProvider } from '../src/index.js';
import { mcpAuthRouter } from '../src/internal/sdk.js';

const credentials = {
  clientid: 'sb-refresh-test!t1',
  clientsecret: 'synthetic-secret-for-refresh-binding-tests',
  url: 'https://identity.example',
  xsappname: 'test!t1',
  uaadomain: 'identity.example',
};
const appUrl = 'https://proxy.example';
const redirectUri = 'https://client.example/callback';

function buildApp(options: Parameters<typeof createXsuaaOAuthProvider>[2] = {}, binding = credentials) {
  const auth = createXsuaaOAuthProvider(binding, appUrl, options);
  const app = express();
  app.use(mcpAuthRouter({ provider: auth.provider, issuerUrl: new URL(appUrl) }));
  return { app, ...auth };
}

async function register(app: express.Express, name: string, method = 'none'): Promise<ClientCredentials> {
  const result = await request(app)
    .post('/register')
    .send({
      client_name: name,
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: method,
      grant_types: ['authorization_code', 'refresh_token'],
    });
  expect(result.status).toBe(201);
  return { client_id: result.body.client_id, client_secret: result.body.client_secret };
}

type ClientCredentials = { client_id: string; client_secret?: string };

async function issue(auth: ReturnType<typeof buildApp>, client: ClientCredentials) {
  // Model the code minted by the browser-validated callback; exercise the real
  // SDK token route and provider, stubbing only the external XSUAA service.
  const code = auth.stateCodec.authorizationCodes.encode('upstream-code', client.client_id, redirectUri);
  const response = await request(auth.app)
    .post('/token')
    .type('form')
    .send({
      ...client,
      grant_type: 'authorization_code',
      code,
      code_verifier: 'v'.repeat(64),
      redirect_uri: redirectUri,
    });
  expect(response.status).toBe(200);
  return response.body.refresh_token as string;
}

function refresh(app: express.Express, client: ClientCredentials, token: string) {
  return request(app)
    .post('/token')
    .type('form')
    .send({
      ...client,
      grant_type: 'refresh_token',
      refresh_token: token,
    });
}

function upstream() {
  const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
    const params = new URLSearchParams(init.body as string);
    expect(params.get('client_id')).toBe(credentials.clientid);
    expect(params.get('client_secret')).toBe(credentials.clientsecret);
    if (params.get('grant_type') === 'authorization_code') {
      return Response.json({ access_token: 'initial-access', refresh_token: 'upstream-refresh' });
    }
    expect(params.get('refresh_token')).toBe('upstream-refresh');
    return Response.json({ access_token: 'renewed-access', scope: 'test!t1.read' });
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('refresh-token client binding through the SDK router', () => {
  it.each(['public DCR', 'confidential manual'])(
    'rejects a %s client refresh token presented by another public client before XSUAA',
    async (kind) => {
      const auth = buildApp();
      const owner =
        kind === 'public DCR'
          ? await register(auth.app, 'Owner')
          : {
              client_id: credentials.clientid,
              client_secret: credentials.clientsecret,
            };
      const other = await register(auth.app, 'Other');
      const fetchMock = upstream();
      const token = await issue(auth, owner);
      fetchMock.mockClear();
      const rejected = await refresh(auth.app, other, token);
      expect(rejected.status).toBe(400);
      expect(rejected.body.error).toBe('invalid_grant');
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each(['public', 'confidential', 'manual'])(
    'allows the issuing %s client to refresh without another approval',
    async (kind) => {
      const auth = buildApp();
      const owner =
        kind === 'manual'
          ? { client_id: credentials.clientid, client_secret: credentials.clientsecret }
          : await register(auth.app, 'Owner', kind === 'public' ? 'none' : 'client_secret_post');
      const fetchMock = upstream();
      const token = await issue(auth, owner);
      const renewed = await refresh(auth.app, owner, token);
      expect(renewed.status).toBe(200);
      expect(renewed.body.access_token).toBe('renewed-access');
      expect(renewed.body.scope).toBe('test!t1.read');
      expect(renewed.body.refresh_token).toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(2);
    },
  );

  it('rejects raw, extracted and tampered refresh tokens, including for the manual client', async () => {
    const auth = buildApp();
    const owner = await register(auth.app, 'Owner');
    const fetchMock = upstream();
    const token = await issue(auth, owner);
    const payload = JSON.parse(Buffer.from(token.slice('mcp-refresh-'.length).split('.')[0], 'base64url').toString());
    expect(payload.token).toBe('upstream-refresh');
    fetchMock.mockClear();
    for (const client of [owner, { client_id: credentials.clientid, client_secret: credentials.clientsecret }]) {
      for (const invalid of [
        'upstream-refresh',
        payload.token,
        `${token}tampered`,
        `mcp-refresh-${'x'.repeat(33_000)}`,
      ]) {
        const response = await refresh(auth.app, client, invalid);
        expect(response.status).toBe(400);
        expect(response.body.error).toBe('invalid_grant');
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('binds rotated tokens and lets the owner use the replacement across instances', async () => {
    const auth = buildApp();
    const owner = await register(auth.app, 'Owner');
    const other = await register(auth.app, 'Other');
    const fetchMock = upstream();
    const initial = await issue(auth, owner);
    fetchMock.mockResolvedValueOnce(Response.json({ access_token: 'renewed', refresh_token: 'rotated-upstream' }));
    const rotated = await refresh(auth.app, owner, initial);
    expect(rotated.status).toBe(200);
    expect(rotated.body.refresh_token).toMatch(/^mcp-refresh-/);
    expect(rotated.body.refresh_token).not.toBe(initial);
    fetchMock.mockClear();
    const restarted = buildApp();
    expect((await refresh(restarted.app, other, rotated.body.refresh_token)).body.error).toBe('invalid_grant');
    expect(fetchMock).not.toHaveBeenCalled();
    fetchMock.mockImplementationOnce(async (_url, init) => {
      expect(new URLSearchParams(init.body as string).get('refresh_token')).toBe('rotated-upstream');
      return Response.json({ access_token: 'after-rotation' });
    });
    expect((await refresh(restarted.app, owner, rotated.body.refresh_token)).body.access_token).toBe('after-rotation');
  });

  it('uses the dedicated signing secret across binding-secret rotation and DCR disabling', async () => {
    const options = { dcrSigningSecret: 'dedicated-synthetic-refresh-signing-secret' };
    const auth = buildApp(options);
    const owner = await register(auth.app, 'Owner');
    const fetchMock = upstream();
    const token = await issue(auth, owner);
    const restarted = buildApp(
      { ...options, dcrEnabled: false },
      { ...credentials, clientsecret: 'new-binding-secret' },
    );
    fetchMock.mockImplementationOnce(async (_url, init) => {
      const fields = new URLSearchParams(init.body as string);
      expect(fields.get('refresh_token')).toBe('upstream-refresh');
      expect(fields.get('client_secret')).toBe('new-binding-secret');
      return Response.json({ access_token: 'after-restart' });
    });
    expect((await refresh(restarted.app, owner, token)).body.access_token).toBe('after-restart');
  });

  it('enforces binding for direct provider callers and after signing-secret rotation', async () => {
    const auth = buildApp();
    const owner = await register(auth.app, 'Owner');
    const fetchMock = upstream();
    const token = await issue(auth, owner);
    const client = { client_id: 'different-client', redirect_uris: [] };
    fetchMock.mockClear();
    await expect(auth.provider.exchangeRefreshToken(client, token)).rejects.toMatchObject({
      errorCode: 'invalid_grant',
    });
    const changed = buildApp({ dcrSigningSecret: 'changed-synthetic-signing-secret' });
    await expect(changed.provider.exchangeRefreshToken({ ...client, ...owner }, token)).rejects.toMatchObject({
      errorCode: 'invalid_grant',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([undefined, 'refresh_token', 'access_token'])('unwraps refresh revocation with hint %s', async (hint) => {
    const auth = buildApp();
    const owner = await register(auth.app, 'Owner');
    const fetchMock = upstream();
    const token = await issue(auth, owner);
    fetchMock.mockReset().mockResolvedValue(new Response(null, { status: 200 }));
    const revoked = await request(auth.app)
      .post('/revoke')
      .type('form')
      .send({
        ...owner,
        token,
        token_type_hint: hint,
      });
    expect(revoked.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${credentials.url}/oauth/revoke`);
    const fields = new URLSearchParams(init.body as string);
    expect(fields.get('token')).toBe('upstream-refresh');
    expect(fields.get('token_type_hint')).toBe('refresh_token');
    expect(init.headers).toHaveProperty(
      'Authorization',
      `Basic ${Buffer.from(`${credentials.clientid}:${credentials.clientsecret}`).toString('base64')}`,
    );
  });

  it('does not forward invalid local envelopes on revocation and preserves raw access-token revocation', async () => {
    const auth = buildApp();
    const owner = await register(auth.app, 'Owner');
    const other = await register(auth.app, 'Other');
    const fetchMock = upstream();
    const token = await issue(auth, owner);
    fetchMock.mockReset().mockResolvedValue(new Response(null, { status: 200 }));
    for (const invalid of [token, `${token}tampered`, 'mcp-refresh-invalid']) {
      const response = await request(auth.app)
        .post('/revoke')
        .type('form')
        .send({
          ...other,
          token: invalid,
          token_type_hint: 'access_token',
        });
      expect(response.status).toBe(200);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    const response = await request(auth.app)
      .post('/revoke')
      .type('form')
      .send({
        ...owner,
        token: 'raw-access-token',
        token_type_hint: 'access_token',
      });
    expect(response.status).toBe(200);
    expect(new URLSearchParams(fetchMock.mock.calls[0][1].body as string).get('token')).toBe('raw-access-token');
  });
});

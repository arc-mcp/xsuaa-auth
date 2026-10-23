import { createHash } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOAuthCallbackHandler } from '../src/callback.js';
import { type AuthOptions, createXsuaaOAuthProvider, OAuthStateCodec, setupHttpAuth } from '../src/index.js';
import { mcpAuthRouter } from '../src/internal/sdk.js';
import { consentFields, responseCookies } from './helpers/oauth-consent.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

const credentials = {
  clientid: 'sb-test!t1',
  clientsecret: 'synthetic-test-secret-for-oauth-consent',
  url: 'https://identity.example',
  xsappname: 'test!t1',
  uaadomain: 'identity.example',
};
const appUrl = 'https://proxy.example';
const verifier = 'v'.repeat(64);
const challenge = createHash('sha256').update(verifier).digest('base64url');

function buildApp(options: Partial<NonNullable<AuthOptions['xsuaa']>> = {}) {
  const app = express();
  const logger = makeCapturingLogger();
  setupHttpAuth(app, { xsuaa: { credentials, appUrl, ...options } }, logger);
  return { app, logger };
}

function authorization(clientId: string, redirectUri = 'https://attacker.example/cb') {
  return {
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'client+state/with=padding',
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function begin(app: express.Express, redirectUri = 'https://client.example/cb', clientName = 'Test client') {
  const registration = await request(app)
    .post('/register')
    .send({
      client_name: clientName,
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: 'none',
    });
  expect(registration.status).toBe(201);
  const params = authorization(registration.body.client_id, redirectUri);
  const page = await request(app).get('/authorize').query(params);
  expect(page.status).toBe(200);
  return { registration, params, page, fields: consentFields(page.text), cookies: responseCookies(page) };
}

function approve(app: express.Express, flow: Awaited<ReturnType<typeof begin>>, changes: Record<string, string> = {}) {
  return request(app)
    .post('/authorize')
    .set('Origin', appUrl)
    .set('Cookie', flow.cookies)
    .type('form')
    .send({ ...flow.fields, consent_action: 'approve', ...changes });
}

describe('OAuth proxy client consent', () => {
  it('stops the reported DCR attack before forwarding a victim to XSUAA', async () => {
    const { app } = buildApp();
    const registration = await request(app)
      .post('/register')
      .send({
        client_name: 'Attacker-controlled client',
        redirect_uris: ['https://attacker.example/cb'],
        token_endpoint_auth_method: 'none',
      });
    expect(registration.status).toBe(201);
    const response = await request(app).get('/authorize').query(authorization(registration.body.client_id));
    expect(response.status).toBe(200);
    expect(response.headers.location).toBeUndefined();
    expect(response.text).toContain('Attacker-controlled client');
    expect(response.text).toContain('attacker.example');
  });

  it('preserves scoped confidential manual-client sign-in and rejects modified permissions', async () => {
    const { provider, clientStore, stateCodec } = createXsuaaOAuthProvider(credentials, appUrl);
    const client = await clientStore.getClient(credentials.clientid);
    if (!client) throw new Error('Missing manual client fixture');
    // SDK 1.18 additionally validates requested scopes against client metadata.
    // This models an explicitly scoped manual client on every supported peer.
    client.scope = 'read write';
    const app = express();
    app.get('/oauth/callback', createOAuthCallbackHandler(stateCodec, clientStore));
    app.use(mcpAuthRouter({ provider, issuerUrl: new URL(appUrl) }));
    const redirectUri = 'https://claude.ai/api/mcp/auth_callback';
    const params = {
      ...authorization(credentials.clientid, redirectUri),
      scope: 'read write',
      resource: `${appUrl}/mcp`,
    };
    const page = await request(app).get('/authorize').query(params);
    expect(page.status).toBe(200);
    expect(page.text).toContain('read, write');
    const fields = consentFields(page.text);
    const post = (changes: Record<string, string> = {}) =>
      request(app)
        .post('/authorize')
        .set('Origin', appUrl)
        .set('Cookie', responseCookies(page))
        .type('form')
        .send({ ...fields, consent_action: 'approve', ...changes });
    expect((await post({ scope: 'read' })).status).toBe(403);
    const approved = await post();
    expect(approved.status).toBe(302);
    const upstream = new URL(approved.headers.location);
    expect(upstream.searchParams.get('scope')).toBe('test!t1.read test!t1.write');
    expect(upstream.searchParams.get('resource')).toBe(`${appUrl}/mcp`);
    const callback = await request(app)
      .get('/oauth/callback')
      .set('Cookie', responseCookies(approved))
      .query({ state: upstream.searchParams.get('state'), code: 'manual-code' });
    expect(callback.status).toBe(302);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'manual-access' }))));
    const token = await request(app)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        client_id: credentials.clientid,
        client_secret: credentials.clientsecret,
        code: new URL(callback.headers.location).searchParams.get('code'),
        redirect_uri: redirectUri,
        code_verifier: verifier,
      });
    expect(token.status).toBe(200);
    expect(token.body.access_token).toBe('manual-access');
  });

  it('adds redirect hosts without adding callback paths or query values to the audit', async () => {
    const { app, logger } = buildApp();
    await request(app)
      .post('/register')
      .send({
        redirect_uris: ['https://client.example/cb?private=DO_NOT_LOG', 'http://localhost:6274/callback'],
        token_endpoint_auth_method: 'none',
      });
    const audit = logger.audit.find((event) => event.event === 'oauth_client_registered');
    expect(audit).toMatchObject({ redirectUriHosts: ['client.example', 'localhost:6274'] });
    expect(JSON.stringify(audit)).not.toContain('DO_NOT_LOG');
  });

  it('rejects raw codes and codes bound to another client or redirect before contacting XSUAA', async () => {
    const { app } = buildApp();
    const first = await begin(app);
    const second = await begin(app, first.params.redirect_uri, 'Different client');
    const approved = await approve(app, first);
    const callback = await request(app)
      .get('/oauth/callback')
      .set('Cookie', responseCookies(approved))
      .query({ state: new URL(approved.headers.location).searchParams.get('state'), code: 'upstream-code' });
    expect(callback.status).toBe(302);
    const wrapped = new URL(callback.headers.location).searchParams.get('code');
    const exchange = vi.fn();
    vi.stubGlobal('fetch', exchange);
    for (const override of [
      { code: 'upstream-code' },
      { client_id: second.registration.body.client_id },
      { redirect_uri: 'https://other.example/cb' },
      { code: `${wrapped}tampered` },
    ]) {
      const result = await request(app)
        .post('/token')
        .type('form')
        .send({
          grant_type: 'authorization_code',
          client_id: first.registration.body.client_id,
          redirect_uri: first.params.redirect_uri,
          code: wrapped,
          code_verifier: verifier,
          ...override,
        });
      expect(result.status).toBe(400);
      expect(result.body.error).toBe('invalid_grant');
    }
    expect(exchange).not.toHaveBeenCalled();
  });

  it.each([
    'https://client.example/cb',
    'http://localhost:6274/cb',
    'http://127.0.0.1:39001/cb',
    'http://[::1]:3000/cb',
    'cursor://anysphere.cursor-mcp/cb',
    'vscode://vscode.microsoft-authentication/cb',
  ])('completes an approved public PKCE flow for %s', async (redirectUri) => {
    const { app } = buildApp();
    const flow = await begin(app, redirectUri);
    const approved = await approve(app, flow);
    expect(approved.status).toBe(302);
    const upstream = new URL(approved.headers.location);
    expect(upstream.origin).toBe(credentials.url);
    expect(upstream.searchParams.get('client_id')).toBe(credentials.clientid);
    expect(upstream.searchParams.get('redirect_uri')).toBe(`${appUrl}/oauth/callback`);
    expect(upstream.searchParams.has('scope')).toBe(false);
    expect(upstream.searchParams.get('code_challenge')).toBe(challenge);
    const callback = await request(app)
      .get('/oauth/callback')
      .set('Cookie', responseCookies(approved))
      .query({ state: upstream.searchParams.get('state'), code: 'approved-code' });
    expect(callback.status).toBe(302);
    const target = new URL(callback.headers.location);
    expect(target.searchParams.get('state')).toBe(flow.params.state);
    expect(target.searchParams.get('code')).toMatch(/^mcp-code-/);
    expect(callback.headers['set-cookie']).toEqual(
      expect.arrayContaining([expect.stringContaining('Expires=Thu, 01 Jan 1970')]),
    );

    const exchange = vi.fn(async (_url: string, init: RequestInit) => {
      const fields = new URLSearchParams(init.body as string);
      expect(fields.get('code')).toBe('approved-code');
      expect(
        createHash('sha256')
          .update(fields.get('code_verifier') ?? '')
          .digest('base64url'),
      ).toBe(challenge);
      expect(fields.get('redirect_uri')).toBe(`${appUrl}/oauth/callback`);
      return new Response(JSON.stringify({ access_token: 'synthetic-access', token_type: 'bearer' }));
    });
    vi.stubGlobal('fetch', exchange);
    const token = await request(app)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        client_id: flow.registration.body.client_id,
        code: target.searchParams.get('code'),
        code_verifier: verifier,
        redirect_uri: redirectUri,
      });
    expect(token.status).toBe(200);
    expect(token.body.access_token).toBe('synthetic-access');
    expect(exchange).toHaveBeenCalledOnce();
  });

  it.each(['GET', 'POST'])('initial %s requests cannot approve through query parameters', async (method) => {
    const { app } = buildApp();
    const flow = await begin(app);
    const params = { ...flow.params, consent_action: 'approve', consent_proof: flow.fields.consent_proof };
    const response =
      method === 'GET'
        ? await request(app).get('/authorize').query(params)
        : await request(app).post('/authorize').type('form').send(flow.params);
    expect(response.status).toBe(200);
    expect(response.headers.location).toBeUndefined();
  });

  it.each(['missing', 'forged', 'cross-browser', 'cross-origin', 'missing-origin', 'duplicate-cookie', 'expired'])(
    'rejects %s consent approval',
    async (attack) => {
      const { app } = buildApp();
      const flow = await begin(app);
      const fields = { ...flow.fields, consent_action: 'approve' };
      if (attack === 'missing') delete fields.consent_proof;
      if (attack === 'forged') fields.consent_proof = `${Math.floor(Date.now() / 1000) + 600}.${'x'.repeat(43)}`;
      if (attack === 'expired') {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(Date.now() + 601_000);
      }
      let req = request(app).post('/authorize').type('form');
      if (attack !== 'cross-browser')
        req = req.set('Cookie', attack === 'duplicate-cookie' ? [...flow.cookies, ...flow.cookies] : flow.cookies);
      if (attack !== 'missing-origin')
        req = req.set('Origin', attack === 'cross-origin' ? 'https://attacker.example' : appUrl);
      const response = await req.send(fields);
      expect(response.status).toBe(403);
      expect(response.headers.location).toBeUndefined();
    },
  );

  it.each([
    ['scope', 'admin'],
    ['state', 'different'],
    ['resource', `${appUrl}/different`],
    ['code_challenge', 'x'.repeat(43)],
    ['redirect_uri', 'https://other.example/cb'],
  ])('rejects approval after modifying %s', async (field, value) => {
    const { app } = buildApp();
    const flow = await begin(app);
    const response = await approve(app, flow, { [field]: value });
    if (response.status === 302 && field === 'scope') {
      // SDK 1.18 rejects requested scopes absent from client metadata before
      // calling the provider. Later SDKs delegate this check to the provider.
      const target = new URL(response.headers.location);
      expect(target.searchParams.get('error')).toBe('invalid_scope');
      expect(target.searchParams.has('code')).toBe(false);
    } else {
      expect([400, 403]).toContain(response.status);
      expect(response.headers.location).toBeUndefined();
    }
  });

  it('cannot move approval between client IDs, even with the same redirect', async () => {
    const { app } = buildApp();
    const first = await begin(app, 'https://client.example/cb', 'First');
    const second = await begin(app, 'https://client.example/cb', 'Second');
    const response = await approve(app, first, { client_id: second.registration.body.client_id });
    expect(response.status).toBe(403);
  });

  it.each([{ code: 'VICTIM_CODE' }, { error: 'access_denied', error_description: 'VICTIM_ERROR' }])(
    'rejects attacker-approved upstream state when it returns in another browser: %j',
    async (result) => {
      const { app } = buildApp();
      const flow = await begin(app, 'https://attacker.example/cb');
      const approved = await approve(app, flow);
      const state = new URL(approved.headers.location).searchParams.get('state');
      const other = await begin(app);
      const otherApproved = await approve(app, other);
      for (const cookies of [[], flow.cookies, responseCookies(otherApproved)]) {
        const callback = await request(app)
          .get('/oauth/callback')
          .set('Cookie', cookies)
          .query({ state, ...result });
        expect(callback.status).toBe(400);
        expect(callback.headers.location).toBeUndefined();
        expect(callback.text).not.toContain('VICTIM_');
      }
    },
  );

  it('rejects legacy signed state even for an existing client', async () => {
    const { app } = buildApp();
    const flow = await begin(app);
    const state = new OAuthStateCodec(credentials.clientsecret).encode({
      clientId: flow.registration.body.client_id,
      clientRedirectUri: flow.params.redirect_uri,
      clientState: flow.params.state,
    });
    const response = await request(app)
      .get('/oauth/callback')
      .set('Cookie', flow.cookies)
      .query({ state, code: 'SECRET' });
    expect(response.status).toBe(400);
    expect(response.headers.location).toBeUndefined();
  });

  it('supports a different instance at each step and concurrent browser tabs', async () => {
    const a = buildApp().app;
    const b = buildApp().app;
    const one = await begin(a);
    const two = await begin(a, 'https://second.example/cb');
    const pendingCookies = [...one.cookies, ...two.cookies];
    const approvedOne = await approve(b, { ...one, cookies: pendingCookies });
    const approvedTwo = await approve(b, { ...two, cookies: pendingCookies });
    const cookies = [...responseCookies(approvedOne), ...responseCookies(approvedTwo)];
    for (const response of [approvedOne, approvedTwo]) {
      expect(response.status).toBe(302);
      const state = new URL(response.headers.location).searchParams.get('state');
      const callback = await request(a).get('/oauth/callback').set('Cookie', cookies).query({ state, code: 'CODE' });
      expect(callback.status).toBe(302);
    }
  });

  it('supports manual-client approval on a fresh instance without a caller-supplied form parser', async () => {
    const a = buildApp().app;
    const b = buildApp().app;
    const redirectUri = 'https://global.consent.azure-apim.net/redirect/new-client';
    const page = await request(a).get('/authorize').query(authorization(credentials.clientid, redirectUri));
    expect(page.status).toBe(200);
    const approved = await request(b)
      .post('/authorize')
      .set('Origin', appUrl)
      .set('Cookie', responseCookies(page))
      .type('form')
      .send({ ...consentFields(page.text), consent_action: 'approve' });
    expect(approved.status).toBe(302);
    expect(new URL(approved.headers.location).origin).toBe(credentials.url);
  });

  it('bounds callback lifetime even when legacy state expiration is disabled', async () => {
    const { app } = buildApp({ stateTtlSeconds: 0 });
    const flow = await begin(app);
    const approved = await approve(app, flow);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 601_000);
    const state = new URL(approved.headers.location).searchParams.get('state');
    const callback = await request(app)
      .get('/oauth/callback')
      .set('Cookie', responseCookies(approved))
      .query({ state, code: 'CODE' });
    expect(callback.status).toBe(400);
    expect(callback.headers.location).toBeUndefined();
  });

  it('denial never forwards to XSUAA or sets an approved callback cookie', async () => {
    const { app } = buildApp();
    const flow = await begin(app);
    const denied = await approve(app, flow, { consent_action: 'deny' });
    expect(denied.status).toBe(303);
    expect(new URL(denied.headers.location).searchParams.get('error')).toBe('access_denied');
    expect(responseCookies(denied)).toEqual([]);
  });

  it('escapes untrusted names and protects the consent page without breaking popups', async () => {
    const { app } = buildApp();
    const flow = await begin(app, 'https://client.example/cb?x=%22', '<script>alert(1)</script>');
    expect(flow.page.text).not.toContain('<script>');
    expect(flow.page.text).toContain('&lt;script&gt;');
    expect(flow.page.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(flow.page.headers['x-frame-options']).toBe('DENY');
    expect(flow.page.headers['cache-control']).toBe('no-store');
    expect(flow.page.headers['referrer-policy']).toBe('origin');
    expect(flow.page.headers['content-security-policy']).not.toContain('form-action');
    expect(flow.page.headers['cross-origin-opener-policy']).toBeUndefined();
    expect(flow.page.headers['set-cookie'][0]).toMatch(/^__Host-/);
    expect(flow.page.headers['set-cookie'][0]).toContain('HttpOnly; Secure; SameSite=Lax');
    expect(flow.page.headers['set-cookie'][0]).not.toContain('Domain=');
    expect(responseCookies(flow.page).some((cookie) => cookie.includes('mcp-oauth-state-'))).toBe(false);
  });

  it('can disable new registrations while preserving XSUAA and existing clients', async () => {
    const a = buildApp().app;
    const flow = await begin(a);
    const b = buildApp({ dcrEnabled: false }).app;
    const metadata = await request(b).get('/.well-known/oauth-authorization-server');
    expect(metadata.body.registration_endpoint).toBeUndefined();
    expect(
      (
        await request(b)
          .post('/register')
          .send({ redirect_uris: ['https://attacker.example/cb'] })
      ).status,
    ).toBe(404);
    expect((await approve(b, flow)).status).toBe(302);
  });

  it.each(['http://127.0.0.1:33418/', 'https://vscode.dev/redirect', 'https://workspace.example/callback'])(
    'keeps approval and denial for an allowlisted DCR return address: %s',
    async (redirectUri) => {
      const { app } = buildApp({ dcrRedirectUriPatterns: [redirectUri] });
      const flow = await begin(app, redirectUri, 'Allowed client');
      expect(flow.page.headers.location).toBeUndefined();
      expect(flow.cookies.some((cookie) => cookie.includes('mcp-oauth-state-'))).toBe(false);
      const denied = await approve(app, flow, { consent_action: 'deny' });
      expect(denied.status).toBe(303);
      expect(new URL(denied.headers.location).searchParams.get('error')).toBe('access_denied');
      const next = await begin(app, redirectUri, 'Allowed client');
      const approved = await approve(app, next);
      expect(approved.status).toBe(302);
      expect(new URL(approved.headers.location).origin).toBe(credentials.url);
      expect(responseCookies(approved).some((cookie) => cookie.includes('mcp-oauth-state-'))).toBe(true);
    },
  );

  it('rejects configuration whose callback cannot receive the approval cookie', () => {
    expect(() =>
      createXsuaaOAuthProvider(credentials, appUrl, { callbackUrl: 'https://different.example/oauth/callback' }),
    ).toThrow(/share.*origin/);
  });

  it.each(['http://proxy.example', 'http://0.0.0.0:8080'])(
    'rejects a non-loopback HTTP public URL at startup: %s',
    (publicUrl) => {
      expect(() => createXsuaaOAuthProvider(credentials, publicUrl)).toThrow(/secure public origin/);
    },
  );

  it.each(['http://localhost:8080', 'http://127.0.0.1:8080'])(
    'supports a loopback HTTP public URL for development: %s',
    async (publicUrl) => {
      const { app } = buildApp({ appUrl: publicUrl });
      const flow = await begin(app);
      expect(flow.page.text).toContain(`${publicUrl}/authorize`);
      expect(flow.page.headers['set-cookie'].join(';')).not.toContain('Secure');
    },
  );
});

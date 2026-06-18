/**
 * OAuth callback handler — the #214 callback proxy second half (SPEC §6).
 *
 * Ported from arc-1 `tests/unit/server/oauth-callback.test.ts`, importing the
 * package's `createOAuthCallbackHandler` / `OAuthStateCodec` / `StatelessDcrClientStore`.
 * The store's default client_id prefix is `mcp-`. Driven with supertest over a real
 * express app (the arc-1 pattern).
 */

import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createOAuthCallbackHandler, OAuthStateCodec, StatelessDcrClientStore } from '../src/index.js';

const SECRET = 'callback-test-signing-secret-1234567890';
const TEST_CLIENT_ID = 'mcp-test-client';

function buildApp(codec: OAuthStateCodec): express.Express {
  const app = express();
  app.get('/oauth/callback', createOAuthCallbackHandler(codec));
  return app;
}

function buildAppWithStore(codec: OAuthStateCodec, store: StatelessDcrClientStore): express.Express {
  const app = express();
  app.get('/oauth/callback', createOAuthCallbackHandler(codec, store));
  return app;
}

/** Parse a Location header's `state` the way an OAuth client (VS Code) does:
 *  WHATWG URL search params, where `+` decodes to space and `%2B` to `+`. */
function clientParsedState(location: string): string | null {
  return new URL(location).searchParams.get('state');
}

describe('createOAuthCallbackHandler — issue #214 round-trip', () => {
  it('redirects to the client with the ORIGINAL "+" state recoverable (the fix)', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const clientState = '6QadZ5GFXGvZ649+OuQi+Q==';
    const token = codec.encode({ clientState, clientRedirectUri: 'http://127.0.0.1:33418/', clientId: TEST_CLIENT_ID });

    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'AUTHCODE123', state: token });

    expect(res.status).toBe(302);
    const loc = res.headers.location as string;
    expect(loc.startsWith('http://127.0.0.1:33418/')).toBe(true);
    expect(new URL(loc).searchParams.get('code')).toBe('AUTHCODE123');
    // KEY ASSERTION: `+` survived as `%2B` on the wire.
    expect(loc).toContain('state=6QadZ5GFXGvZ649%2BOuQi%2BQ%3D%3D');
    expect(clientParsedState(loc)).toBe(clientState);
  });

  it('emits %2B (not literal +) in the Location header', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({
      clientState: 'a+b+c==',
      clientRedirectUri: 'http://localhost:1/cb',
      clientId: TEST_CLIENT_ID,
    });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'x', state: token });
    const loc = res.headers.location as string;
    const stateSegment = loc.split('state=')[1] ?? '';
    expect(stateSegment).not.toContain('+');
    expect(stateSegment).toContain('%2B');
  });

  it('renders a self-hosted error page (no 302 to a possibly-dead loopback) on OAuth error', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({
      clientState: 'st+ate==',
      clientRedirectUri: 'http://127.0.0.1:5/cb',
      clientId: TEST_CLIENT_ID,
    });
    const res = await request(buildApp(codec))
      .get('/oauth/callback')
      .query({ error: 'access_denied', error_description: 'user cancelled', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).toContain('access_denied');
    expect(res.text).toContain('user cancelled');
    expect(res.text).toContain('http://127.0.0.1:5/cb');
    expect(res.text).toContain('error=access_denied');
  });

  it('redirects the error (not a terminal page) for a hosted HTTPS callback', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({
      clientState: 'st+ate==',
      clientRedirectUri: 'https://claude.ai/api/mcp/auth_callback',
      clientId: TEST_CLIENT_ID,
    });
    const res = await request(buildApp(codec))
      .get('/oauth/callback')
      .query({ error: 'invalid_scope', error_description: 'no scopes', state: token });
    expect(res.status).toBe(302);
    const u = new URL(res.headers.location as string);
    expect(u.origin + u.pathname).toBe('https://claude.ai/api/mcp/auth_callback');
    expect(u.searchParams.get('error')).toBe('invalid_scope');
    expect(u.searchParams.get('error_description')).toBe('no scopes');
    expect(u.searchParams.get('state')).toBe('st+ate==');
    expect(u.searchParams.get('code')).toBeNull();
  });

  it('adds an actionable role-collection hint for invalid_scope', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({ clientRedirectUri: 'http://127.0.0.1:5/cb', clientId: TEST_CLIENT_ID });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({
      error: 'invalid_scope',
      error_description: 'is invalid. not allowed any of the requested scopes',
      state: token,
    });
    expect(res.status).toBe(400);
    expect(res.text).toContain('role collection');
  });

  it('HTML-escapes a malicious error_description (no XSS)', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({ clientRedirectUri: 'http://127.0.0.1:5/cb', clientId: TEST_CLIENT_ID });
    const res = await request(buildApp(codec))
      .get('/oauth/callback')
      .query({ error: 'invalid_request', error_description: '<script>alert(1)</script>', state: token });
    expect(res.status).toBe(400);
    expect(res.text).not.toContain('<script>alert(1)</script>');
    expect(res.text).toContain('&lt;script&gt;');
  });

  it('round-trips a state with no "+" unchanged', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({
      clientState: 'mElKiL3xesnEy0LnXDyKvA==',
      clientRedirectUri: 'http://localhost:1/cb',
      clientId: TEST_CLIENT_ID,
    });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'c', state: token });
    expect(clientParsedState(res.headers.location as string)).toBe('mElKiL3xesnEy0LnXDyKvA==');
  });

  it('omits state when the client did not send one', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({ clientRedirectUri: 'http://localhost:1/cb', clientId: TEST_CLIENT_ID });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'c', state: token });
    expect(new URL(res.headers.location as string).searchParams.has('state')).toBe(false);
  });

  it('returns 400 (not a 302 with empty code=) for a valid state but neither code nor error', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const token = codec.encode({
      clientState: 'st+ate==',
      clientRedirectUri: 'http://127.0.0.1:33418/',
      clientId: TEST_CLIENT_ID,
    });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).toContain('Authentication failed');
  });

  it('returns 400 (no open redirect) for an invalid/forged state token', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const res = await request(buildApp(codec))
      .get('/oauth/callback')
      .query({ code: 'c', state: 'forged.AAAAAAAAAAAAAAAAAAAAAA' });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).toContain('Authentication failed');
  });

  it('returns 400 for an expired state token', async () => {
    const codec = new OAuthStateCodec(SECRET, { ttlSeconds: 1 });
    const token = codec.encode({
      clientState: 'x',
      clientRedirectUri: 'http://localhost:1/cb',
      clientId: TEST_CLIENT_ID,
      now: 1_000_000_000_000,
    });
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'c', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('returns 400 when no state is provided at all', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const res = await request(buildApp(codec)).get('/oauth/callback').query({ code: 'c' });
    expect(res.status).toBe(400);
  });
});

describe('createOAuthCallbackHandler — client-binding validation (auth-code interception defense)', () => {
  const buildStore = () => new StatelessDcrClientStore('xsuaa-client', 'xsuaa-secret', SECRET);

  it('forwards the code when redirect_uri IS registered for the state client_id', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const registered = await store.registerClient({ redirect_uris: ['https://app.example.com/cb'] });
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://app.example.com/cb',
      clientId: registered.client_id,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'CODE1', state: token });
    expect(res.status).toBe(302);
    const u = new URL(res.headers.location as string);
    expect(u.origin + u.pathname).toBe('https://app.example.com/cb');
    expect(u.searchParams.get('code')).toBe('CODE1');
  });

  it('returns 400 (code NOT leaked) when redirect_uri is NOT registered for the client_id', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const registered = await store.registerClient({ redirect_uris: ['https://app.example.com/cb'] });
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://attacker.example/cb',
      clientId: registered.client_id,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'STOLEN', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).toContain('Authentication failed');
    expect(res.text).not.toContain('STOLEN');
  });

  it('returns 400 when the state references an unknown/forged client_id', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://app.example.com/cb',
      clientId: 'mcp-bogus.AAAAAAAAAAAAAAAAAAAAAA',
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'CODE1', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('blocks the error-forwarding path too when redirect_uri is unregistered', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const registered = await store.registerClient({ redirect_uris: ['https://app.example.com/cb'] });
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://attacker.example/cb',
      clientId: registered.client_id,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ error: 'access_denied', error_description: 'denied', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  // ── Shared pre-registered XSUAA default client (Manual-mode clients) ──
  const DEFAULT_CLIENT_ID = 'xsuaa-client';

  it('forwards the code for the default client when redirect_uri is allowlisted', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://global.consent.azure-apim.net/redirect/contoso',
      clientId: DEFAULT_CLIENT_ID,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'CODE1', state: token });
    expect(res.status).toBe(302);
    expect((res.headers.location as string).startsWith('https://global.consent.azure-apim.net/redirect/contoso')).toBe(
      true,
    );
    expect(new URL(res.headers.location as string).searchParams.get('code')).toBe('CODE1');
  });

  it('returns 400 (code NOT leaked) for the default client when redirect_uri is not allowlisted', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'https://attacker.example/cb',
      clientId: DEFAULT_CLIENT_ID,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'STOLEN', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).not.toContain('STOLEN');
  });

  it('returns 400 (code NOT leaked) for a userinfo-smuggled localhost redirect on the default client', async () => {
    const codec = new OAuthStateCodec(SECRET);
    const store = buildStore();
    const token = codec.encode({
      clientState: 'abc',
      clientRedirectUri: 'http://localhost:x@evil.com/cb',
      clientId: DEFAULT_CLIENT_ID,
    });
    const res = await request(buildAppWithStore(codec, store))
      .get('/oauth/callback')
      .query({ code: 'STOLEN', state: token });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.text).not.toContain('STOLEN');
  });
});

/**
 * setupHttpAuth facade (SPEC §6).
 *
 *  - api-key-only mode: returns bearer middleware, mounts NO OAuth router/callback
 *    (the SDK metadata endpoints 404).
 *  - xsuaa mode: mounts /authorize, /oauth/callback, and the SDK .well-known
 *    metadata; returns bearer middleware. Asserted by driving the express app with
 *    supertest (the OAuth metadata + the callback proxy answer; the bare app would 404).
 *  - required:true + no method → throws.
 *  - default (required falsy) + no method → returns undefined and warns.
 *  - sets NO Cross-Origin-Opener-Policy.
 *
 * `@sap/xssec` is mocked so `createXsuaaTokenVerifier` can construct an XsuaaService
 * at factory time without a real binding (no token is verified in these tests).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@sap/xssec', () => {
  class XsuaaService {
    createSecurityContext = vi.fn();
  }
  return { default: { XsuaaService } };
});

const express = (await import('express')).default;
const request = (await import('supertest')).default;
const { setupHttpAuth } = await import('../src/index.js');

import type { Express } from 'express';
import { type CapturingLogger, makeCapturingLogger } from './helpers/test-logger.js';

const XSUAA_CREDS = {
  clientid: 'sb-arc1!t1',
  clientsecret: 'stub-secret-40-chars-long-AAAAAAAAAAAAAAAA',
  url: 'https://stub.authentication.eu10.hana.ondemand.com',
  xsappname: 'arc1!t1',
  uaadomain: 'authentication.eu10.hana.ondemand.com',
};
const APP_URL = 'https://arc1.example.com';

function freshApp(): { app: Express; logger: CapturingLogger } {
  return { app: express(), logger: makeCapturingLogger() };
}

afterEach(() => {
  vi.clearAllMocks();
});

describe('setupHttpAuth — no method configured', () => {
  it('throws when required:true and no auth method is set', () => {
    const { app, logger } = freshApp();
    expect(() => setupHttpAuth(app, { required: true }, logger)).toThrow(/no authentication method configured/);
  });

  it('returns undefined and warns loudly when no method is set (default open)', () => {
    const { app, logger } = freshApp();
    const mw = setupHttpAuth(app, {}, logger);
    expect(mw).toBeUndefined();
    expect(logger.has('warn', /\/mcp is OPEN/)).toBe(true);
  });
});

describe('setupHttpAuth — api-key-only mode', () => {
  it('returns bearer middleware and mounts NO OAuth router (metadata 404s)', async () => {
    const { app, logger } = freshApp();
    const mw = setupHttpAuth(app, { apiKeys: [{ key: 'k', scopes: ['read'] }] }, logger);
    expect(typeof mw).toBe('function');

    // No OAuth router → the SDK metadata endpoint is not mounted.
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(404);
    // And no callback route either.
    const cb = await request(app).get('/oauth/callback').query({ code: 'x' });
    expect(cb.status).toBe(404);
  });

  it('the returned middleware rejects an unauthenticated /mcp request (401)', async () => {
    const { app, logger } = freshApp();
    const mw = setupHttpAuth(app, { apiKeys: 'solo-key' }, logger);
    if (!mw) throw new Error('expected bearer middleware');
    app.post('/mcp', mw, (_req, res) => res.json({ ok: true }));
    const res = await request(app).post('/mcp').send({ jsonrpc: '2.0', method: 'ping', id: 1 });
    expect(res.status).toBe(401);
  });
});

describe('setupHttpAuth — xsuaa mode', () => {
  function buildXsuaaApp(): { app: Express; logger: CapturingLogger } {
    const { app, logger } = freshApp();
    app.use(express.urlencoded({ extended: true }));
    setupHttpAuth(
      app,
      {
        xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL, scopesSupported: ['read', 'write'], resourceName: 'ARC-1' },
      },
      logger,
    );
    return { app, logger };
  }

  it('mounts the SDK OAuth authorization-server metadata (.well-known)', async () => {
    const { app } = buildXsuaaApp();
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    // Endpoints advertised by mcpAuthRouter, derived from appUrl.
    expect(res.body.authorization_endpoint).toBe(`${APP_URL}/authorize`);
    expect(res.body.token_endpoint).toBe(`${APP_URL}/token`);
    // The DCR store exposes registerClient → registration endpoint is advertised.
    expect(res.body.registration_endpoint).toBe(`${APP_URL}/register`);
  });

  it('mounts the protected-resource metadata for /mcp', async () => {
    const { app } = buildXsuaaApp();
    const res = await request(app).get('/.well-known/oauth-protected-resource/mcp');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe(`${APP_URL}/mcp`);
  });

  it('mounts the /oauth/callback proxy (returns the terminal 400 page on a forged state, not 404)', async () => {
    const { app } = buildXsuaaApp();
    const res = await request(app).get('/oauth/callback').query({ code: 'c', state: 'forged.AAAAAAAAAAAAAAAAAAAAAA' });
    // 400 (handler ran) — proves the route is mounted; a missing route would be 404.
    expect(res.status).toBe(400);
    expect(res.text).toContain('Authentication failed');
  });

  it('mounts /authorize (the SDK authorize handler runs — 400 on a bad request, not 404)', async () => {
    const { app } = buildXsuaaApp();
    const res = await request(app).get('/authorize'); // missing client_id/redirect_uri → handler 400s
    expect(res.status).not.toBe(404);
  });

  it('returns bearer middleware that 401s an unauthenticated /mcp', async () => {
    const { app, logger } = freshApp();
    app.use(express.urlencoded({ extended: true }));
    const mw = setupHttpAuth(app, { xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL } }, logger);
    expect(typeof mw).toBe('function');
    if (!mw) throw new Error('expected bearer middleware');
    app.post('/mcp', mw, (_req, res) => res.json({ ok: true }));
    const res = await request(app).post('/mcp').send({ jsonrpc: '2.0', method: 'ping', id: 1 });
    expect(res.status).toBe(401);
  });

  it('answers 400 invalid_client_metadata for a DCR redirect outside dcrRedirectUriPatterns', async () => {
    const { app, logger } = freshApp();
    setupHttpAuth(
      app,
      { xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL, dcrRedirectUriPatterns: ['http://127.0.0.1:*/**'] } },
      logger,
    );
    const register = (redirect_uris: string[]) =>
      request(app).post('/register').send({ client_name: 'test', redirect_uris, token_endpoint_auth_method: 'none' });

    const rejected = await register(['https://attacker.example/cb']);
    expect(rejected.status).toBe(400);
    expect(rejected.body.error).toBe('invalid_client_metadata');
    expect((await register(['http://127.0.0.1:33418/'])).status).toBe(201);
  });

  it('logs "XSUAA OAuth proxy enabled"', () => {
    const { logger } = buildXsuaaApp();
    expect(logger.has('info', /XSUAA OAuth proxy enabled/)).toBe(true);
  });

  describe('POST /token with a refresh token XSUAA rejects', () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    async function refreshWithXsuaaAnswer(status: number, body: string) {
      const { app, logger } = buildXsuaaApp();
      const reg = await request(app)
        .post('/register')
        .send({
          client_name: 'test',
          redirect_uris: ['http://localhost:53682/callback'],
          token_endpoint_auth_method: 'none',
        });
      expect(reg.status).toBe(201);
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({ ok: false, status, text: vi.fn().mockResolvedValue(body) } as unknown as Response),
      );
      const res = await request(app)
        .post('/token')
        .type('form')
        .send({ grant_type: 'refresh_token', refresh_token: 'revoked-refresh', client_id: reg.body.client_id });
      return { res, logger };
    }

    it('answers 400 invalid_grant when XSUAA reports a revoked refresh token (401 invalid_token)', async () => {
      const { res, logger } = await refreshWithXsuaaAnswer(
        401,
        '{"error":"invalid_token","error_description":"The token expired, was revoked, or the token ID is incorrect."}',
      );
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_grant');
      expect(logger.has('warn', /XSUAA refresh token rejected/)).toBe(true);
    });

    it.each(['<html>Service Unavailable</html>', '{"error":"invalid_token"}'])(
      'still answers 500 server_error for an upstream 503: %s',
      async (body) => {
        const { res, logger } = await refreshWithXsuaaAnswer(503, body);
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('server_error');
        expect(logger.has('error', /XSUAA refresh token exchange failed/)).toBe(true);
      },
    );
  });
});

describe('setupHttpAuth — CORS + COOP', () => {
  it('applies CORS for an allowed origin and sets NO Cross-Origin-Opener-Policy', async () => {
    const { app, logger } = freshApp();
    const mw = setupHttpAuth(app, { apiKeys: 'k', allowedOrigins: ['https://claude.ai'] }, logger);
    app.get('/health', (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/health').set('Origin', 'https://claude.ai');
    expect(res.headers['access-control-allow-origin']).toBe('https://claude.ai');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    expect(res.headers['cross-origin-opener-policy']).toBeUndefined();
    expect(typeof mw).toBe('function');
    expect(logger.has('info', /CORS enabled/)).toBe(true);
  });

  it('does not reflect a disallowed origin', async () => {
    const { app, logger } = freshApp();
    setupHttpAuth(app, { apiKeys: 'k', allowedOrigins: ['https://claude.ai'] }, logger);
    app.get('/health', (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/health').set('Origin', 'https://evil.example.com');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

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

  it('logs "XSUAA OAuth proxy enabled"', () => {
    const { logger } = buildXsuaaApp();
    expect(logger.has('info', /XSUAA OAuth proxy enabled/)).toBe(true);
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

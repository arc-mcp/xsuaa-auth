/**
 * Built-in exact-match CORS applier (SPEC §6 — no `cors` dep, no restrictive COOP).
 *
 * `applyCors` is an internal building block (not re-exported from `.`), imported
 * here from `../src/cors.js`. Ported from the CORS slice of arc-1's
 * `http-security-headers.test.ts`, minus the helmet bits (the package owns no
 * helmet — broad hardening is consumer-owned). Driven with supertest.
 */

import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyCors } from '../src/cors.js';

function buildApp(allowedOrigins: string[]): express.Express {
  const app = express();
  app.set('trust proxy', 1);
  applyCors(app, allowedOrigins);
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.post('/mcp', (_req, res) => {
    res.json({ jsonrpc: '2.0', result: 'ok', id: 1 });
  });
  return app;
}

describe('applyCors — allowed origin', () => {
  it('reflects the exact origin (not wildcard) with credentials + MCP headers', async () => {
    const res = await request(buildApp(['https://app.example.com']))
      .get('/health')
      .set('Origin', 'https://app.example.com');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    expect(res.headers['access-control-allow-methods']).toContain('POST');
    expect(res.headers['access-control-allow-headers']?.toLowerCase()).toContain('authorization');
    expect(res.headers['access-control-allow-headers']?.toLowerCase()).toContain('mcp-session-id');
    expect(res.headers['access-control-expose-headers']?.toLowerCase()).toContain('mcp-session-id');
    expect(res.headers.vary).toContain('Origin');
  });

  it('answers an OPTIONS preflight from an allowed origin with 204', async () => {
    const res = await request(buildApp(['https://app.example.com']))
      .options('/mcp')
      .set('Origin', 'https://app.example.com')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,authorization,mcp-session-id');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('reflects only the exact origin from a multi-origin allowlist', async () => {
    const app = buildApp(['https://a.example.com', 'https://b.example.com']);
    const resA = await request(app).get('/health').set('Origin', 'https://a.example.com');
    const resB = await request(app).get('/health').set('Origin', 'https://b.example.com');
    const resC = await request(app).get('/health').set('Origin', 'https://c.example.com');
    expect(resA.headers['access-control-allow-origin']).toBe('https://a.example.com');
    expect(resB.headers['access-control-allow-origin']).toBe('https://b.example.com');
    expect(resC.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('applyCors — disallowed / absent origin', () => {
  it('emits no Access-Control-Allow-Origin for a disallowed origin', async () => {
    const res = await request(buildApp(['https://app.example.com']))
      .get('/health')
      .set('Origin', 'https://evil.example.com');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('a disallowed-origin OPTIONS falls through (not the 204 CORS short-circuit)', async () => {
    // No matching CORS branch → next() runs; there is no OPTIONS route, so express
    // does not answer it 204. The point is simply that no ACAO header is set.
    const res = await request(buildApp(['https://app.example.com']))
      .options('/mcp')
      .set('Origin', 'https://evil.example.com')
      .set('Access-Control-Request-Method', 'POST');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.status).not.toBe(204);
  });

  it('passes through requests with no Origin header (same-origin / curl) without CORS headers', async () => {
    const res = await request(buildApp(['https://app.example.com'])).get('/health');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('applyCors — COOP must NOT be set (popup OAuth)', () => {
  it('sets no Cross-Origin-Opener-Policy header (allowed origin)', async () => {
    const res = await request(buildApp(['https://app.example.com']))
      .get('/health')
      .set('Origin', 'https://app.example.com');
    expect(res.headers['cross-origin-opener-policy']).toBeUndefined();
  });

  it('sets no Cross-Origin-Opener-Policy header (no allowlist)', async () => {
    const res = await request(buildApp([])).get('/health');
    expect(res.headers['cross-origin-opener-policy']).toBeUndefined();
  });
});

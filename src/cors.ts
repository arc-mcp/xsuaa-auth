/**
 * Built-in CORS applier for browser-based MCP clients (no `cors` npm dependency).
 *
 * Mirrors arc-1's `applySecurityMiddleware` CORS values: an exact-match origin
 * allowlist with `credentials: true`, the MCP request/response headers, and a 204
 * preflight answer. Disallowed origins simply get no CORS headers (the browser
 * then blocks the response), matching arc-1's exact-origin reflection.
 *
 * Deliberately sets NO `Cross-Origin-Opener-Policy` — popup-based OAuth (Copilot
 * Studio, claude.ai) breaks under `COOP: same-origin`. Broader hardening
 * (helmet CSP/HSTS) stays consumer-owned.
 */

import type { Express } from 'express';

const ALLOW_METHODS = 'GET,POST,DELETE,OPTIONS';
const ALLOW_HEADERS = 'Content-Type, Authorization, mcp-session-id';
// `WWW-Authenticate` is not CORS-safelisted; a browser client needs it to read the challenge.
const EXPOSE_HEADERS = 'mcp-session-id, WWW-Authenticate';

/**
 * Apply an exact-match CORS handler to `app`. When a request's `Origin` is in
 * `allowedOrigins`, the response reflects that origin with `credentials: true`
 * and the MCP CORS headers; an `OPTIONS` preflight is answered with 204.
 * Requests with no `Origin` (same-origin, curl, server-to-server) and requests
 * from disallowed origins pass through without CORS headers.
 */
export function applyCors(app: Express, allowedOrigins: readonly string[]): void {
  const allowed = new Set(allowedOrigins);

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (typeof origin === 'string' && origin.length > 0 && allowed.has(origin)) {
      // Reflect the exact origin (required when credentials are allowed — `*`
      // is invalid with `Access-Control-Allow-Credentials: true`).
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', ALLOW_METHODS);
      // A preflight gets the headers it asked for: the origin is already allowlisted, and
      // SDK v2 clients send `Mcp-Method`, `Mcp-Name` and per-tool `Mcp-Param-*` headers
      // that a fixed list cannot name.
      res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] ?? ALLOW_HEADERS);
      res.setHeader('Access-Control-Expose-Headers', EXPOSE_HEADERS);
      // `Vary` so caches don't serve one origin's (or one preflight's) CORS headers to another.
      res.setHeader('Vary', 'Origin, Access-Control-Request-Headers');

      if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
      }
    }
    next();
  });
}

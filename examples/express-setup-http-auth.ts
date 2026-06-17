/**
 * Minimal runnable example: protect an MCP server's `/mcp` endpoint with
 * `setupHttpAuth` using BOTH an API key and XSUAA OAuth.
 *
 * Run it (after `npm run build` in the package root, with the package installed
 * or linked into this example's project):
 *
 *   # API-key only (no XSUAA binding needed):
 *   ARC_API_KEY=dev-secret-key npx tsx examples/express-setup-http-auth.ts
 *
 *   # API-key + XSUAA (on Cloud Foundry, bound to an XSUAA service):
 *   #   the XSUAA credentials + app URL come straight from the CF environment.
 *   npx tsx examples/express-setup-http-auth.ts
 *
 * Then:
 *   curl -H 'Authorization: Bearer dev-secret-key' http://localhost:3000/mcp   # 200-ish
 *   curl http://localhost:3000/mcp                                             # 401
 *
 * This example intentionally stops at "auth works": it does not wire a real MCP
 * transport. The package contributes the auth middleware + OAuth router; the MCP
 * server (e.g. @modelcontextprotocol/sdk's StreamableHTTPServerTransport) is
 * yours to mount on `/mcp` behind the returned `bearer` middleware.
 */

import { type AuthOptions, type Logger, loadXsuaaCredentials, resolveAppUrl, setupHttpAuth } from '@arc-mcp/xsuaa-auth';
import express from 'express';

// A tiny console logger matching the package's structural Logger contract
// (argument order is `(message, data)`). In production, inject your own
// (pino users pass a ~3-line adapter — see the README).
const logger: Logger = {
  debug: (m, d) => console.debug(m, d ?? ''),
  info: (m, d) => console.info(m, d ?? ''),
  warn: (m, d) => console.warn(m, d ?? ''),
  error: (m, d) => console.error(m, d ?? ''),
};

const app = express();
// The OAuth router and the /authorize shim read JSON / form bodies.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Build the auth options. API key is always on here; XSUAA is added only when an
// XSUAA service is bound (so this example also runs locally without one).
const options: AuthOptions = {
  // A single static key. For multiple keys with different scopes, pass an
  // ApiKeyEntry[]: [{ key: '...', scopes: ['read'] }, { key: '...', scopes: ['read','write'] }]
  apiKeys: process.env.ARC_API_KEY ?? 'dev-secret-key',

  // CORS allowlist for browser MCP clients (omit for native clients).
  allowedOrigins: ['https://claude.ai'],

  // Fail closed: throw if somehow no auth method ends up configured.
  required: true,
};

// Add XSUAA OAuth iff the app is bound to an XSUAA service on Cloud Foundry.
if (process.env.VCAP_SERVICES) {
  options.xsuaa = {
    // Layer-0 plug-and-play: parse the bound XSUAA credentials + the public
    // app URL straight from the CF environment — no hand-parsed binding.
    credentials: loadXsuaaCredentials(),
    appUrl: resolveAppUrl(process.env, { publicUrlEnvVar: 'PUBLIC_URL', port: 3000 }),
    clientIdPrefix: 'example-',
    resourceName: 'Example MCP Server',
    // Keep these in sync with your xs-security.json oauth2-configuration.redirect-uris.
    // The shipped defaults already cover Claude, Cursor, VS Code, MCP Inspector.
  };
}

// Wire the auth onto `app`. Returns the bearer middleware for `/mcp`
// (or `undefined` if no method is configured and `required` is falsy).
const bearer = setupHttpAuth(app, options, logger);

// Protect the MCP endpoint with the returned bearer middleware.
if (bearer) {
  app.all('/mcp', bearer, (_req, res) => {
    // Replace this stub with your real MCP transport handler.
    res.json({ ok: true, message: 'authenticated — mount your MCP transport here' });
  });
}

// A public health endpoint (no auth) so you can confirm the server is up.
app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  logger.info('Example MCP auth server listening', { url: `http://localhost:${port}` });
});

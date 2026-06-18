/**
 * Plug-and-play HTTP-auth facade.
 *
 * Composes the building blocks following arc-1's `startHttpServer` auth-wiring,
 * but WITHOUT arc-1's Copilot `/authorize` JSON-RPC bypass or reverse-proxy
 * base-path metadata overrides (those stay in arc-1 via the building blocks).
 *
 * For the standard XSUAA flow it: applies CORS (if `allowedOrigins` set), builds
 * the chained verifier, creates the XSUAA OAuth provider, mounts the `/authorize`
 * `ensureRedirectUri` (pattern-gated) shim + `/oauth/callback` proxy + the SDK
 * `mcpAuthRouter`, and returns the `requireBearerAuth` middleware for `/mcp`.
 *
 * For api-key/OIDC-only deployments (no `options.xsuaa`) it builds the chained
 * verifier and returns bearer middleware WITHOUT mounting the OAuth router /
 * callback — mirroring arc-1's non-XSUAA `createStandardVerifier` path.
 *
 * When NO auth method is configured: throws if `options.required`, else logs a
 * loud warning and returns `undefined` (open access). Sets NO restrictive COOP
 * header (popup OAuth requires COOP unset).
 */

import type { Express, RequestHandler } from 'express';
import { createOAuthCallbackHandler } from './callback.js';
import { applyCors } from './cors.js';
import { mcpAuthRouter, requireBearerAuth } from './internal/sdk.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import { createXsuaaOAuthProvider } from './oauth-provider.js';
import type { ApiKeyEntry, ExpandScopes, Verifier } from './types.js';
import { createChainedTokenVerifier, createOidcVerifier } from './verifiers.js';
import type { XsuaaCredentials } from './xsuaa.js';
import { createXsuaaTokenVerifier } from './xsuaa.js';

/**
 * Facade configuration. See SPEC §6.
 */
export interface AuthOptions {
  /** API keys (single string or `ApiKeyEntry[]`). */
  apiKeys?: string | ApiKeyEntry[];
  /** XSUAA OAuth proxy config. When omitted, the OAuth router/callback are not mounted. */
  xsuaa?: {
    credentials: XsuaaCredentials;
    appUrl: string;
    clientIdPrefix?: string;
    dcrKdfLabel?: string;
    stateKdfLabel?: string;
    resourceName?: string;
    scopesSupported?: string[];
    requiredScopes?: string[];
    redirectUriPatterns?: readonly string[];
    defaultRedirectUris?: readonly string[];
    dcrTtlSeconds?: number;
    stateTtlSeconds?: number;
    dcrSigningSecret?: string;
    /**
     * This server's own OAuth callback URL sent to XSUAA as the redirect_uri
     * (issue #214 callback proxy). Must match a `redirectUriPatterns` entry. When
     * omitted, defaults to `${appUrl}/oauth/callback`.
     */
    callbackUrl?: string;
  };
  /** OIDC / Entra ID verifier config. */
  oidc?: {
    issuer: string;
    audience: string;
    clockToleranceSec?: number;
    algorithms?: string[];
    /** Override the primary scope-claim name (default `scope`). */
    scopeClaim?: string;
    /** Scope names recognised on a verified OIDC token (others are dropped).
     *  Defaults to `xsuaa.scopesSupported`, else the built-in arc-1 set. Set
     *  this for an OIDC-only deployment whose IdP emits custom scope names
     *  (without also having to configure `xsuaa`). */
    acceptedScopes?: string[];
    /** Scopes granted when a verified OIDC token carries no accepted scope.
     *  Defaults to `[]` (fail closed). Set `['read']` to opt into legacy
     *  read-only fallback under IdP scope-claim misconfiguration. */
    fallbackScopes?: string[];
  };
  /**
   * CORS allowlist for browser MCP clients (e.g. `https://claude.ai`); the facade
   * applies exact-match CORS + credentials. Unset = no CORS.
   */
  allowedOrigins?: string[];
  /** `true` → throw if no auth method configured; `false` (default) → return `undefined` (open) with a loud warn. */
  required?: boolean;
  /** Injected scope-expansion policy (default identity), applied by each verifier. */
  expandScopes?: ExpandScopes;
}

/**
 * Wire HTTP auth onto `app` and return the bearer middleware for `/mcp`
 * (`undefined` when no method is configured and `required` is falsy).
 */
export function setupHttpAuth(
  app: Express,
  options: AuthOptions,
  logger: Logger = noopLogger,
): RequestHandler | undefined {
  // (a) CORS for browser MCP clients.
  if (options.allowedOrigins && options.allowedOrigins.length > 0) {
    applyCors(app, options.allowedOrigins);
    logger.info('CORS enabled', { origins: options.allowedOrigins });
  }

  const hasApiKeys =
    options.apiKeys !== undefined &&
    (typeof options.apiKeys === 'string' ? options.apiKeys.length > 0 : options.apiKeys.length > 0);
  const hasOidc = options.oidc !== undefined;
  const hasXsuaa = options.xsuaa !== undefined;

  // (e) No method configured → throw or warn+undefined.
  if (!hasApiKeys && !hasOidc && !hasXsuaa) {
    if (options.required) {
      throw new Error(
        'setupHttpAuth: no authentication method configured (apiKeys / oidc / xsuaa) but options.required is true.',
      );
    }
    logger.warn(
      'setupHttpAuth: no authentication method configured — /mcp is OPEN (unauthenticated). ' +
        'Set apiKeys, oidc, or xsuaa, or pass required:true to fail closed.',
    );
    return undefined;
  }

  // (b) Build verifiers → chained verifier.
  const expandScopes = options.expandScopes;
  // Accepted scope names default to the arc-1 set; a consumer with different scope
  // names (e.g. calmcp's `Viewer`) advertises them via `xsuaa.scopesSupported` and
  // we thread those through so they are not filtered out of XSUAA/OIDC tokens.
  const acceptedScopes = options.xsuaa?.scopesSupported;
  const xsuaaVerifier: Verifier | undefined = options.xsuaa
    ? createXsuaaTokenVerifier(options.xsuaa.credentials, { expandScopes, acceptedScopes, logger })
    : undefined;
  const oidcVerifier: Verifier | undefined = options.oidc
    ? createOidcVerifier(options.oidc.issuer, options.oidc.audience, {
        clockToleranceSec: options.oidc.clockToleranceSec,
        algorithms: options.oidc.algorithms,
        scopeClaim: options.oidc.scopeClaim,
        // OIDC-only deployments set oidc.acceptedScopes directly; otherwise fall
        // back to the xsuaa-advertised set (or the verifier's built-in default).
        acceptedScopes: options.oidc.acceptedScopes ?? acceptedScopes,
        fallbackScopes: options.oidc.fallbackScopes,
        expandScopes,
        logger,
      })
    : undefined;
  const chainedVerifier = createChainedTokenVerifier({ apiKeys: options.apiKeys }, xsuaaVerifier, oidcVerifier, {
    expandScopes,
    logger,
  });

  // (c) + (d): XSUAA mode mounts the OAuth router/callback; otherwise just bearer.
  if (options.xsuaa) {
    const xsuaa = options.xsuaa;
    const appUrl = xsuaa.appUrl;
    const issuerUrl = new URL(appUrl);
    const baseUrl = new URL(appUrl);
    const resourceServerUrl = new URL(`${appUrl.replace(/\/$/, '')}/mcp`);
    const resourceMetadataUrl = `${appUrl.replace(/\/$/, '')}/.well-known/oauth-protected-resource/mcp`;

    const { provider, clientStore, stateCodec } = createXsuaaOAuthProvider(xsuaa.credentials, appUrl, {
      clientIdPrefix: xsuaa.clientIdPrefix,
      dcrKdfLabel: xsuaa.dcrKdfLabel,
      stateKdfLabel: xsuaa.stateKdfLabel,
      dcrTtlSeconds: xsuaa.dcrTtlSeconds,
      stateTtlSeconds: xsuaa.stateTtlSeconds,
      dcrSigningSecret: xsuaa.dcrSigningSecret,
      redirectUriPatterns: xsuaa.redirectUriPatterns,
      defaultRedirectUris: xsuaa.defaultRedirectUris,
      callbackUrl: xsuaa.callbackUrl,
      logger,
    });

    // /authorize redirect_uri shim: auto-register a candidate redirect_uri for the
    // pre-registered XSUAA client (Manual-OAuth clients like Copilot Studio). The
    // SDK requires exact redirect_uri matching; `ensureRedirectUri` is pattern-gated
    // (xs-security.json mirror) so only allowlisted URIs are added, then XSUAA stays
    // the authoritative validator. Also merges query params into the body for clients
    // that POST /authorize with params in the query string.
    app.use('/authorize', (req, _res, next) => {
      if (
        req.method === 'POST' &&
        req.query.client_id &&
        !(req.body as { client_id?: unknown } | undefined)?.client_id
      ) {
        req.body = { ...req.query, ...((req.body as Record<string, unknown> | undefined) || {}) };
      }
      const params = (req.method === 'POST' ? req.body : req.query) as
        | { redirect_uri?: unknown; client_id?: unknown }
        | undefined;
      const redirectUri = params?.redirect_uri;
      const clientId = params?.client_id;
      if (typeof clientId === 'string' && typeof redirectUri === 'string') {
        clientStore.ensureRedirectUri(clientId, redirectUri);
      }
      next();
    });

    // /oauth/callback proxy (issue #214 second half).
    app.get('/oauth/callback', createOAuthCallbackHandler(stateCodec, clientStore, { logger }));

    // SDK auth router: OAuth endpoints (authorize/token/register/revoke) + discovery.
    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl,
        baseUrl,
        resourceServerUrl,
        scopesSupported: xsuaa.scopesSupported,
        resourceName: xsuaa.resourceName,
      }),
    );

    logger.info('XSUAA OAuth proxy enabled', { xsappname: xsuaa.credentials.xsappname, appUrl });

    return requireBearerAuth({
      verifier: { verifyAccessToken: chainedVerifier },
      requiredScopes: xsuaa.requiredScopes,
      resourceMetadataUrl,
    });
  }

  // Non-XSUAA (api-key / OIDC): bearer middleware only, no OAuth router.
  logger.info('HTTP auth enabled (no OAuth proxy)', { apiKeys: hasApiKeys, oidc: hasOidc });
  return requireBearerAuth({ verifier: { verifyAccessToken: chainedVerifier } });
}

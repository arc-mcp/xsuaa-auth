/**
 * SDK insulation layer (SPEC §8).
 *
 * The ONLY module that imports MCP SDK auth code. MCP SDK v2 dropped the OAuth
 * authorization-server helpers from `@modelcontextprotocol/server`; the frozen v1
 * copy lives in `@modelcontextprotocol/server-legacy/auth`, which this package
 * depends on directly so it works beside SDK v1 or v2 (or neither).
 *
 * Router, bearer middleware and error classes MUST come from this one copy: the
 * middleware maps errors by `instanceof`, so an error class from another SDK copy
 * turns a 401/400 into a 500. The package re-exports them for that reason.
 */

import {
  type AuthRouterOptions,
  type BearerAuthMiddlewareOptions,
  createOAuthMetadata,
  mcpAuthRouter as legacyMcpAuthRouter,
  requireBearerAuth as legacyRequireBearerAuth,
  metadataHandler,
  type OAuthRegisteredClientsStore,
} from '@modelcontextprotocol/server-legacy/auth';
import { type RequestHandler, Router } from 'express';

export type { AuthInfo, OAuthRegisteredClientsStore } from '@modelcontextprotocol/server-legacy/auth';
export {
  getOAuthProtectedResourceMetadataUrl,
  InsufficientScopeError,
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidTokenError,
  metadataHandler,
  OAuthError,
  ProxyOAuthServerProvider,
  redirectUriMatches,
} from '@modelcontextprotocol/server-legacy/auth';

/**
 * The legacy middleware puts `resourceMetadataUrl` in its own 401/403 only. SDK v2 builds a
 * tool-level scope challenge from `AuthInfo`, so stamp the URL there as v2's middleware does:
 * after validation, and only when the verifier set none.
 */
export function requireBearerAuth(options: BearerAuthMiddlewareOptions): RequestHandler {
  const bearer = legacyRequireBearerAuth(options);
  const { resourceMetadataUrl } = options;
  if (!resourceMetadataUrl) return bearer;
  return (req, res, next) =>
    bearer(req, res, (err?: unknown) => {
      if (!err && req.auth && req.auth.resourceMetadataUrl === undefined) {
        req.auth = { ...req.auth, resourceMetadataUrl };
      }
      next(err);
    });
}

/**
 * The frozen SDK router cannot advertise Client ID Metadata Documents. When the provider
 * resolves URL client_ids, serve the same metadata plus the flag ahead of the router, so the
 * flag and the resolver cannot drift apart: an SDK client uses a URL client_id only when it
 * sees `client_id_metadata_document_supported`.
 */
export function mcpAuthRouter(options: AuthRouterOptions): RequestHandler {
  const router = legacyMcpAuthRouter(options);
  if (
    !('clientIdMetadataDocumentSupported' in options.provider && options.provider.clientIdMetadataDocumentSupported)
  ) {
    return router;
  }
  const metadata = { ...createOAuthMetadata(options), client_id_metadata_document_supported: true };
  const withFlag = Router();
  withFlag.use('/.well-known/oauth-authorization-server', metadataHandler(metadata));
  withFlag.use(router);
  return withFlag;
}

/** server-legacy does not re-export this type; derive it from the store contract. */
export type OAuthClientInformationFull = NonNullable<Awaited<ReturnType<OAuthRegisteredClientsStore['getClient']>>>;

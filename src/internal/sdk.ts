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

import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/server-legacy/auth';

export type { AuthInfo, OAuthRegisteredClientsStore } from '@modelcontextprotocol/server-legacy/auth';
export {
  InsufficientScopeError,
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidTokenError,
  mcpAuthRouter,
  ProxyOAuthServerProvider,
  requireBearerAuth,
} from '@modelcontextprotocol/server-legacy/auth';

/** server-legacy does not re-export this type; derive it from the store contract. */
export type OAuthClientInformationFull = NonNullable<Awaited<ReturnType<OAuthRegisteredClientsStore['getClient']>>>;

/**
 * SDK insulation layer (SPEC §8).
 *
 * This is the ONLY module in the package that imports from
 * `@modelcontextprotocol/sdk/server/auth/*`. The SDK v2 monorepo split relocates
 * these paths (auth → `@modelcontextprotocol/server`, Express → a separate adapter),
 * so confining the imports here makes that migration a one-file change. No other
 * source file may import the SDK directly.
 */
export { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
export { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
export { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
export { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

export type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
export type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
export type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

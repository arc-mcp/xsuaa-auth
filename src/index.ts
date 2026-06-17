/**
 * `@arc-mcp/xsuaa-auth` — core auth entrypoint (`.`).
 *
 * Re-exports the full public core-auth surface frozen in SPEC §6. The
 * principal-propagation surface lives behind the separate `./btp` entrypoint and
 * is intentionally NOT re-exported here.
 */

// ─── OAuth callback handler ──────────────────────────────────────────
export { createOAuthCallbackHandler } from './callback.js';
// ─── Layer-0 config helpers ──────────────────────────────────────────
export { loadXsuaaCredentials, resolveAppUrl } from './credentials.js';
export type { StatelessDcrClientStoreOptions } from './dcr-client-store.js';
// ─── Stateless DCR client store + redirect-uri helpers ───────────────
export { StatelessDcrClientStore } from './dcr-client-store.js';
export type { AuthOptions } from './facade.js';
// ─── Facade ──────────────────────────────────────────────────────────
export { setupHttpAuth } from './facade.js';
// ─── Re-exported SDK types (behind the §8 insulation layer) ──────────
export type { AuthInfo, OAuthClientInformationFull } from './internal/sdk.js';
// ─── Logger contract ─────────────────────────────────────────────────
export type { Logger } from './logger.js';
export { noopLogger } from './logger.js';
export type { CreateXsuaaOAuthProviderOptions } from './oauth-provider.js';
// ─── XSUAA OAuth provider ────────────────────────────────────────────
export { createXsuaaOAuthProvider, XsuaaProxyOAuthProvider } from './oauth-provider.js';
export type { DecodeResult, OAuthStateCodecOptions } from './oauth-state.js';
// ─── OAuth-state codec (#214 callback proxy) ─────────────────────────
export { OAuthStateCodec } from './oauth-state.js';
export {
  matchesRedirectPattern,
  validateRedirectUri,
  XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
  XSUAA_DEFAULT_REDIRECT_URIS,
} from './redirect-uris.js';
// ─── Shared public types ─────────────────────────────────────────────
export type { ApiKeyEntry, ExpandScopes, Verifier } from './types.js';
// ─── Verifiers ───────────────────────────────────────────────────────
export { createApiKeyVerifier, createChainedTokenVerifier, createOidcVerifier } from './verifiers.js';
// ─── XSUAA binding + token verifier + scope helpers ──────────────────
export type { XsuaaCredentials } from './xsuaa.js';
export { createXsuaaTokenVerifier, qualifyXsuaaScopes, RESERVED_OAUTH_SCOPES } from './xsuaa.js';

/**
 * `arc-mcp-xsuaa-auth` — core auth entrypoint (`.`).
 *
 * Re-exports the full public core-auth surface frozen in SPEC §6. The
 * principal-propagation surface lives behind the separate `./btp` entrypoint and
 * is intentionally NOT re-exported here.
 */

// ─── Logger contract ─────────────────────────────────────────────────
export type { Logger } from './logger.js';
export { noopLogger } from './logger.js';

// ─── Shared public types ─────────────────────────────────────────────
export type { Verifier, ExpandScopes, ApiKeyEntry } from './types.js';

// ─── Re-exported SDK types (behind the §8 insulation layer) ──────────
export type { AuthInfo, OAuthClientInformationFull } from './internal/sdk.js';

// ─── XSUAA binding + token verifier + scope helpers ──────────────────
export type { XsuaaCredentials } from './xsuaa.js';
export { createXsuaaTokenVerifier, qualifyXsuaaScopes, RESERVED_OAUTH_SCOPES } from './xsuaa.js';

// ─── Stateless DCR client store + redirect-uri helpers ───────────────
export { StatelessDcrClientStore } from './dcr-client-store.js';
export type { StatelessDcrClientStoreOptions } from './dcr-client-store.js';
export {
  XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
  XSUAA_DEFAULT_REDIRECT_URIS,
  validateRedirectUri,
  matchesRedirectPattern,
} from './redirect-uris.js';

// ─── OAuth-state codec (#214 callback proxy) ─────────────────────────
export { OAuthStateCodec } from './oauth-state.js';
export type { OAuthStateCodecOptions, DecodeResult } from './oauth-state.js';

// ─── XSUAA OAuth provider ────────────────────────────────────────────
export { XsuaaProxyOAuthProvider, createXsuaaOAuthProvider } from './oauth-provider.js';
export type { CreateXsuaaOAuthProviderOptions } from './oauth-provider.js';

// ─── Verifiers ───────────────────────────────────────────────────────
export { createApiKeyVerifier, createOidcVerifier, createChainedTokenVerifier } from './verifiers.js';

// ─── OAuth callback handler ──────────────────────────────────────────
export { createOAuthCallbackHandler } from './callback.js';

// ─── Layer-0 config helpers ──────────────────────────────────────────
export { loadXsuaaCredentials, resolveAppUrl } from './credentials.js';

// ─── Facade ──────────────────────────────────────────────────────────
export { setupHttpAuth } from './facade.js';
export type { AuthOptions } from './facade.js';

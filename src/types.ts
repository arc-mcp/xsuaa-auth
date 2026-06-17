/**
 * Shared public types for the core auth API.
 */
import type { AuthInfo } from './internal/sdk.js';

/** A bearer-token verifier: resolves to `AuthInfo` or throws. */
export type Verifier = (token: string) => Promise<AuthInfo>;

/** Injected scope-expansion policy seam (default identity). */
export type ExpandScopes = (scopes: string[]) => string[];

/** A configured API key with its granted scopes / client identity. */
export interface ApiKeyEntry {
  key: string;
  scopes?: string[];
  clientId?: string;
}

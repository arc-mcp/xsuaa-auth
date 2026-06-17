/**
 * Bearer-token verifiers: API key, OIDC (jose), and the chained verifier.
 *
 * Ported from arc-1's `matchApiKeyFromConfig` / `createOidcVerifier` /
 * `extractOidcScopes` / `createChainedTokenVerifier`. Adaptations:
 *   - api-key input is a `string | ApiKeyEntry[]` (arc-1's `{key, profile}` →
 *     `ApiKeyEntry{key, scopes, clientId}`); matching uses a timing-safe compare,
 *   - OIDC lazy-imports `jose` (`await import('jose')`) and adds an `algorithms`
 *     allowlist (default `['RS256','ES256','PS256']`) passed to `jwtVerify`,
 *   - the chain order is the SPEC-frozen XSUAA → OIDC → api-key,
 *   - the injected `expandScopes` hook (default identity) is applied to each
 *     verifier's output scopes; injected logger defaults to no-op.
 */

import crypto from 'node:crypto';
import type { AuthInfo } from './internal/sdk.js';
import { InvalidTokenError } from './internal/sdk.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import type { ApiKeyEntry, ExpandScopes, Verifier } from './types.js';

const IDENTITY: ExpandScopes = (s) => s;

/** Far-future expiry for static API keys (1 year) — `requireBearerAuth` requires `expiresAt`. */
const ONE_YEAR_SECS = 365 * 24 * 60 * 60;

/** Default JWT signature algorithms accepted by the OIDC verifier. Pinning the
 *  allowlist closes `alg:none` and RS/HS algorithm-confusion attacks. */
const DEFAULT_OIDC_ALGORITHMS = ['RS256', 'ES256', 'PS256'];

/** Scope names arc-1 recognises; the default OIDC/XSUAA accepted-scope set. A
 *  consumer with different scope names (e.g. calmcp's `Viewer`) overrides this
 *  via `acceptedScopes`. Explicit `string[]` annotation keeps it
 *  isolatedDeclarations-clean (SPEC §12). */
export const DEFAULT_ACCEPTED_SCOPES: string[] = ['read', 'write', 'data', 'sql', 'transports', 'git', 'admin'];

/**
 * Non-reversible correlation fingerprint for a bearer token / API key. Logs the
 * first 8 hex chars of `sha256(token)` plus the byte length — enough to correlate
 * the same token across log lines without ever emitting raw or partial token
 * bytes (a partial token leaks the whole secret for short API keys). Never log
 * the token itself.
 */
function tokenFingerprint(token: string): { tokenFp: string; tokenLen: number } {
  return {
    tokenFp: crypto.createHash('sha256').update(token).digest('hex').slice(0, 8),
    tokenLen: token.length,
  };
}

// ─── API key verifier ────────────────────────────────────────────────

/**
 * Compare two strings in constant time. Returns false on any length mismatch
 * without leaking it through early return (the digest equalization keeps the
 * compare time independent of where the strings first differ).
 */
function timingSafeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  // crypto.timingSafeEqual throws on unequal lengths; equalize via a fixed-length
  // HMAC so the comparison is constant-time even for different-length inputs.
  const key = crypto.randomBytes(32);
  const ah = crypto.createHmac('sha256', key).update(ab).digest();
  const bh = crypto.createHmac('sha256', key).update(bb).digest();
  return crypto.timingSafeEqual(ah, bh);
}

/**
 * Normalize the `keys` argument to an `ApiKeyEntry[]`. A bare string is a single
 * key granting no extra scopes (clientId `api-key`).
 */
function normalizeApiKeys(keys: string | ApiKeyEntry[]): ApiKeyEntry[] {
  if (typeof keys === 'string') {
    return keys.length > 0 ? [{ key: keys }] : [];
  }
  return keys;
}

/**
 * Create a verifier that matches a bearer token against configured API keys.
 *
 * On match it returns `AuthInfo` with clientId `api-key` (single string form) or
 * the entry's `clientId` (defaults to `api-key`), the entry's `scopes` (after the
 * injected `expandScopes`), and a far-future `expiresAt`. No match throws
 * {@link InvalidTokenError}.
 */
export function createApiKeyVerifier(
  keys: string | ApiKeyEntry[],
  options: { expandScopes?: ExpandScopes; logger?: Logger } = {},
): Verifier {
  const logger = options.logger ?? noopLogger;
  const expandScopes = options.expandScopes ?? IDENTITY;
  const entries = normalizeApiKeys(keys);

  return async (token: string): Promise<AuthInfo> => {
    for (const entry of entries) {
      if (timingSafeStringEqual(token, entry.key)) {
        const scopes = expandScopes(entry.scopes ?? []);
        const clientId = entry.clientId ?? 'api-key';
        logger.debug('API key matched', { clientId });
        return {
          token,
          clientId,
          scopes,
          expiresAt: Math.floor(Date.now() / 1000) + ONE_YEAR_SECS,
          extra: {},
        };
      }
    }
    throw new InvalidTokenError('API key validation failed: not a recognised key');
  };
}

// ─── OIDC verifier ───────────────────────────────────────────────────

/**
 * Extract scopes from an OIDC JWT payload.
 *
 * Tries `scope` (space-separated string, standard OIDC) then `scp` (Azure AD:
 * space-delimited string for delegated tokens, or array for app tokens).
 * Filters to `acceptedScopes`, applies the injected `expandScopes`, and falls
 * back to `fallbackScopes` when no usable scope claims are present.
 *
 * SECURITY — fail-closed by default: both no-scope-claims and
 * scopes-present-but-none-accepted return `fallbackScopes`, which DEFAULTS TO
 * `[]` (no privileges). A misconfigured IdP that omits scope claims therefore
 * grants nothing rather than silently handing out read access. A consumer that
 * wants the legacy read-only behavior opts in via `fallbackScopes: ['read']`
 * (threaded from the verifier option of the same name) — arc-1 does exactly that
 * to preserve its historical default.
 *
 * @param scopeClaim Optional override of the primary claim name (default `scope`).
 * @param acceptedScopes Scope names to keep (default {@link DEFAULT_ACCEPTED_SCOPES}).
 * @param fallbackScopes Scopes granted when no accepted scope is present (default `[]` = fail closed).
 */
function extractOidcScopes(
  payload: Record<string, unknown>,
  expandScopes: ExpandScopes,
  logger: Logger,
  scopeClaim = 'scope',
  acceptedScopes: string[] = DEFAULT_ACCEPTED_SCOPES,
  fallbackScopes: string[] = [],
): string[] {
  let rawScopes: string[] | undefined;

  const primary = payload[scopeClaim];
  if (typeof primary === 'string') {
    rawScopes = primary.split(' ').filter((s) => s.length > 0);
  } else if (typeof payload.scp === 'string') {
    rawScopes = payload.scp.split(' ').filter((s) => s.length > 0);
  } else if (Array.isArray(payload.scp)) {
    rawScopes = (payload.scp as unknown[]).filter((s): s is string => typeof s === 'string' && s.length > 0);
  }

  // No scope claims at all → fail closed to `fallbackScopes` (default []). The
  // fallback is NOT run through `expandScopes`: it is an explicit, already-final
  // grant chosen by the consumer, not a token-derived scope set.
  if (rawScopes === undefined) {
    logger.warn(
      `OIDC JWT has no scope/scp claims — falling back to the configured fallbackScopes (default none). Configure scope claims in your OIDC provider, or set fallbackScopes, to grant access. Granted: [${fallbackScopes.join(', ')}]`,
    );
    return fallbackScopes;
  }

  const accepted = new Set(acceptedScopes);
  const filtered = rawScopes.filter((s) => accepted.has(s));

  // Scopes present but none accepted → fail closed to `fallbackScopes` (default []).
  if (filtered.length === 0) {
    logger.warn(
      `OIDC JWT has scope claims but none match accepted scopes — falling back to the configured fallbackScopes (default none). Granted: [${fallbackScopes.join(', ')}]`,
      { rawScopes },
    );
    return fallbackScopes;
  }

  return expandScopes(filtered);
}

/**
 * Create an OIDC / Entra ID token verifier using `jose` (lazy-imported on first
 * call, so non-OIDC consumers never need the optional peer).
 *
 * `algorithms` defaults to `['RS256','ES256','PS256']` and is passed to
 * `jwtVerify`, pinning the accepted JWT signature algorithms (closes `alg:none`
 * / algorithm-confusion). The JWKS is discovered from the issuer's
 * `.well-known/openid-configuration` and cached for the verifier's lifetime.
 */
export function createOidcVerifier(
  issuer: string,
  audience: string,
  options: {
    clockToleranceSec?: number;
    scopeClaim?: string;
    algorithms?: string[];
    acceptedScopes?: string[];
    /** Scopes granted when a verified token carries no accepted scope. Defaults to
     *  `[]` (fail closed) so an IdP misconfiguration grants no privileges. Set to
     *  e.g. `['read']` to opt into legacy read-only fallback (arc-1 does this). */
    fallbackScopes?: string[];
    expandScopes?: ExpandScopes;
    logger?: Logger;
  } = {},
): Verifier {
  const logger = options.logger ?? noopLogger;
  const expandScopes = options.expandScopes ?? IDENTITY;
  const algorithms = options.algorithms ?? DEFAULT_OIDC_ALGORITHMS;
  const scopeClaim = options.scopeClaim ?? 'scope';
  const acceptedScopes = options.acceptedScopes ?? DEFAULT_ACCEPTED_SCOPES;
  const fallbackScopes = options.fallbackScopes ?? [];

  // jose is lazy-imported once and the JWKS memoized — `jwtVerify` + the remote
  // JWKS type come from the same module instance.
  let josePromise: Promise<typeof import('jose')> | null = null;
  let jwksPromise: Promise<ReturnType<typeof import('jose').createRemoteJWKSet>> | null = null;

  async function getJose(): Promise<typeof import('jose')> {
    if (!josePromise) josePromise = import('jose');
    return josePromise;
  }

  async function getJwks(): Promise<ReturnType<typeof import('jose').createRemoteJWKSet>> {
    if (jwksPromise) return jwksPromise;
    const pending = (async () => {
      const jose = await getJose();
      const discoveryUrl = new URL('.well-known/openid-configuration', issuer.endsWith('/') ? issuer : `${issuer}/`);
      const resp = await fetch(discoveryUrl.toString());
      // Verify the discovery fetch succeeded — a non-2xx must NOT be parsed as JSON
      // (the body is an error page, not a discovery doc) and must reject so the
      // memoized promise is cleared below and the next request retries.
      if (!resp.ok) {
        throw new Error(`OIDC discovery fetch from ${discoveryUrl.toString()} returned HTTP ${resp.status}`);
      }
      const discovery = (await resp.json()) as { jwks_uri?: string };
      if (!discovery.jwks_uri) {
        throw new Error(`No jwks_uri in OIDC discovery response from ${discoveryUrl.toString()}`);
      }
      logger.info('OIDC JWKS initialized', { issuer, jwksUri: discovery.jwks_uri });
      return jose.createRemoteJWKSet(new URL(discovery.jwks_uri));
    })();
    // Don't cache a rejected discovery/JWKS promise forever — one transient
    // failure would otherwise brick OIDC until process restart. Clear the memo on
    // rejection so the next call retries; keep it on success.
    pending.catch(() => {
      if (jwksPromise === pending) jwksPromise = null;
    });
    jwksPromise = pending;
    return jwksPromise;
  }

  return async (token: string): Promise<AuthInfo> => {
    try {
      const jose = await getJose();
      const jwks = await getJwks();
      const { payload } = await jose.jwtVerify(token, jwks, {
        issuer,
        audience,
        algorithms,
        requiredClaims: ['exp'],
        ...(options.clockToleranceSec != null ? { clockTolerance: options.clockToleranceSec } : {}),
      });

      // Don't log `sub` (PII / user identifier) by default — log the issuer and a
      // boolean presence flag for correlation instead.
      logger.debug('OIDC JWT validated', { iss: payload.iss, hasSub: payload.sub != null });

      const scopes = extractOidcScopes(
        payload as Record<string, unknown>,
        expandScopes,
        logger,
        scopeClaim,
        acceptedScopes,
        fallbackScopes,
      );

      return {
        token,
        clientId: (payload.azp as string) ?? (payload.sub as string) ?? 'oidc-user',
        scopes,
        expiresAt: payload.exp,
        extra: { sub: payload.sub, iss: payload.iss },
      };
    } catch (err) {
      // Wrap jose validation errors as InvalidTokenError so bearerAuth maps to 401.
      if (err instanceof InvalidTokenError) throw err;
      throw new InvalidTokenError((err as Error).message ?? 'Invalid token');
    }
  };
}

// ─── Chained verifier ────────────────────────────────────────────────

/**
 * Chain bearer verifiers in the SPEC-frozen order **XSUAA → OIDC → api-key**.
 *
 * Each provided verifier is tried in turn; the first that resolves wins. If none
 * accept, throws {@link InvalidTokenError}.
 *
 * **`expandScopes` is applied exactly once — by the sub-verifiers, NOT here.** The
 * XSUAA/OIDC/api-key verifiers each expand the scopes they extract; the chain
 * returns their result verbatim. (Re-applying it here would double-apply a
 * non-idempotent expander.) The chain only builds the api-key verifier with the
 * injected hook so the api-key path expands once too.
 *
 * The order is correctness-immaterial (token types are disjoint) but pinned for
 * determinism + test stability.
 */
export function createChainedTokenVerifier(
  config: { apiKeys?: string | ApiKeyEntry[] },
  xsuaaVerifier?: Verifier,
  oidcVerifier?: Verifier,
  options: { expandScopes?: ExpandScopes; logger?: Logger } = {},
): Verifier {
  const logger = options.logger ?? noopLogger;
  const expandScopes = options.expandScopes ?? IDENTITY;

  const hasApiKeys =
    config.apiKeys !== undefined &&
    (typeof config.apiKeys === 'string' ? config.apiKeys.length > 0 : config.apiKeys.length > 0);
  const apiKeyVerifier =
    hasApiKeys && config.apiKeys !== undefined
      ? createApiKeyVerifier(config.apiKeys, { expandScopes, logger })
      : undefined;

  return async (token: string): Promise<AuthInfo> => {
    // Log a non-reversible fingerprint (sha256 prefix + length), never the token.
    const fp = tokenFingerprint(token);
    logger.debug('Chained token verifier: starting', fp);

    // 1. XSUAA — expandScopes already applied inside the verifier.
    if (xsuaaVerifier) {
      try {
        const result = await xsuaaVerifier(token);
        logger.debug('Chained token verifier: XSUAA succeeded', {
          clientId: result.clientId,
          scopeCount: result.scopes.length,
          hasUser: !!(result.extra?.email || result.extra?.userName),
        });
        return result;
      } catch (err) {
        logger.debug('Chained token verifier: XSUAA failed, trying next', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // 2. OIDC — expandScopes already applied inside the verifier.
    if (oidcVerifier) {
      try {
        const result = await oidcVerifier(token);
        logger.debug('Chained token verifier: OIDC succeeded', {
          clientId: result.clientId,
          scopeCount: result.scopes.length,
        });
        return result;
      } catch (err) {
        logger.debug('Chained token verifier: OIDC failed, trying next', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // 3. API key — expandScopes already applied inside the verifier.
    if (apiKeyVerifier) {
      try {
        const result = await apiKeyVerifier(token);
        logger.debug('Chained token verifier: API key matched', { clientId: result.clientId });
        return result;
      } catch (err) {
        logger.debug('Chained token verifier: API key failed', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    logger.debug('Chained token verifier: all methods failed', fp);
    throw new InvalidTokenError('Token validation failed: not a valid XSUAA, OIDC, or API key token');
  };
}

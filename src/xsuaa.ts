/**
 * XSUAA token verification + scope qualification for MCP-native OAuth.
 *
 * Lifted from arc-1's xsuaa.ts. Only the token verifier + scope helpers are
 * ported here; the OAuth provider class, the chained verifier, and
 * `createXsuaaOAuthProvider` land in a later wave (SPEC §6). The crypto/control
 * flow is verbatim — the only changes are the injected `expandScopes` hook
 * (replacing arc-1's `authz/policy` import; default identity), the injected
 * logger (default no-op), and the `@sap/xssec` CJS-interop import (SPEC §12).
 *
 * @sap/xssec for token validation (not jose):
 *  - SAP-specific x5t thumbprint and proof-of-possession validation
 *  - Proper XSUAA audience format handling
 *  - Offline validation with automatic JWKS caching
 *  - checkLocalScope() for scope enforcement
 */

import xssec from '@sap/xssec';
import { type AuthInfo, InvalidTokenError } from './internal/sdk.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import type { ExpandScopes, Verifier } from './types.js';
import { DEFAULT_ACCEPTED_SCOPES } from './verifiers.js';

// `@sap/xssec` is pure CommonJS (no ESM entry) → default-import + destructure
// with esModuleInterop (SPEC §12, documented interop edge).
const { XsuaaService } = xssec;

// ─── Types ───────────────────────────────────────────────────────────

/** XSUAA credentials from VCAP_SERVICES */
export interface XsuaaCredentials {
  url: string;
  clientid: string;
  clientsecret: string;
  xsappname: string;
  uaadomain: string;
  verificationkey?: string;
}

// ─── XSUAA Token Verifier ────────────────────────────────────────────

/**
 * Verify a JWT token using @sap/xssec.
 *
 * Creates a security context from the token using the XSUAA service,
 * then maps it to the MCP SDK's AuthInfo format.
 *
 * `options.expandScopes` is the injected scope-expansion policy seam (default
 * identity); `options.logger` is the injected structural logger (default no-op).
 * `options.acceptedScopes` is the set of local scope names probed via
 * `checkLocalScope` (default {@link DEFAULT_ACCEPTED_SCOPES} — the arc-1 set). A
 * consumer with different scope names (e.g. calmcp's `Viewer`) overrides it so its
 * scopes are not silently dropped.
 */
export function createXsuaaTokenVerifier(
  credentials: XsuaaCredentials,
  options: { expandScopes?: ExpandScopes; acceptedScopes?: string[]; logger?: Logger } = {},
): Verifier {
  const logger = options.logger ?? noopLogger;
  const expandScopes = options.expandScopes ?? ((s: string[]): string[] => s);
  const acceptedScopes = options.acceptedScopes ?? DEFAULT_ACCEPTED_SCOPES;
  const xsuaaService = new XsuaaService({
    clientid: credentials.clientid,
    clientsecret: credentials.clientsecret,
    url: credentials.url,
    xsappname: credentials.xsappname,
    uaadomain: credentials.uaadomain,
  });

  return async (token: string): Promise<AuthInfo> => {
    logger.debug('XSUAA token verification: creating security context');
    // Normalize @sap/xssec validation failures to InvalidTokenError so a rejected
    // token maps to a 401 under requireBearerAuth (matching the OIDC + api-key
    // verifiers) instead of escaping as a 500 when this verifier is used directly.
    let securityContext: Awaited<ReturnType<typeof xsuaaService.createSecurityContext>>;
    try {
      securityContext = await xsuaaService.createSecurityContext(token, { jwt: token });
    } catch (err) {
      logger.debug('XSUAA token validation failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      throw new InvalidTokenError('XSUAA token validation failed');
    }

    // Extract scopes (remove xsappname prefix for local scope names).
    // The token carries scopes like "arc1-mcp!b12345.read"; checkLocalScope strips
    // the prefix, so we probe each accepted short name.
    const grantedScopes: string[] = [];
    for (const scope of acceptedScopes) {
      if (securityContext.checkLocalScope(scope)) {
        grantedScopes.push(scope);
      }
    }
    // Apply implied scope expansion via the injected policy hook (default identity).
    const expandedScopes = expandScopes(grantedScopes);

    const expiresAt = securityContext.token?.payload?.exp;

    const authInfo = {
      token,
      clientId: securityContext.getClientId(),
      scopes: expandedScopes,
      expiresAt: typeof expiresAt === 'number' ? expiresAt : undefined,
      extra: {
        userName: securityContext.getLogonName?.() ?? undefined,
        email: securityContext.getEmail?.() ?? undefined,
      },
    };
    // Don't log email / userName (PII) by default — log counts + boolean presence.
    logger.debug('XSUAA token verified', {
      clientId: authInfo.clientId,
      scopeCount: expandedScopes.length,
      hasUserName: authInfo.extra.userName != null,
      hasEmail: authInfo.extra.email != null,
    });
    return authInfo;
  };
}

// ─── Scope qualification ─────────────────────────────────────────────

/**
 * OIDC/UAA scopes that must NOT be prefixed with the app's xsappname. They are
 * reserved/global in XSUAA, so qualifying them (e.g. `openid` →
 * `arc1-mcp!t498139.openid`) produces an invalid scope that XSUAA rejects.
 */
export const RESERVED_OAUTH_SCOPES = new Set(['openid', 'profile', 'email', 'offline_access']);

/**
 * Qualify short MCP scope names (`read`, `write`, `admin`, …) with the XSUAA
 * xsappname prefix XSUAA requires (it rejects a bare `admin`). Scopes that are
 * already qualified (contain a `.`, e.g. `uaa.user`) or are reserved OIDC scopes
 * ({@link RESERVED_OAUTH_SCOPES}) pass through untouched. Empty entries (Copilot
 * Studio sends `scope=""` → `[""]`) are dropped.
 */
export function qualifyXsuaaScopes(scopes: string[], xsappname: string): string[] {
  return scopes
    .filter((s) => s.length > 0)
    .map((s) => (s.includes('.') || RESERVED_OAUTH_SCOPES.has(s) ? s : `${xsappname}.${s}`));
}

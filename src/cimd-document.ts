/**
 * Validation of a fetched Client ID Metadata Document (CIMD, SEP-991).
 *
 * The transport half — everything up to and including "we have some bytes" — lives in
 * `cimd-fetch.ts`. This module decides whether those bytes describe a client we are
 * willing to act on, and turns them into the SDK's `OAuthClientInformationFull`.
 *
 * The document is entirely attacker-authored: anyone who controls a hostname can serve
 * one. It is therefore treated as untrusted input throughout — a strict field allowlist,
 * a cap on every collection and string, and no value used for anything beyond what it is
 * declared for. In particular `client_name` is display-only and is NEVER evidence of
 * identity: CIMD proves control of a domain and nothing else.
 *
 * Normative requirements enforced here, from
 * `draft-ietf-oauth-client-id-metadata-document-02`:
 *
 *  - **N1** the document's `client_id` MUST equal the Client Identifier URL, compared by
 *    simple string comparison. This is the whole binding between the URL we fetched and
 *    the identity we hand back; without it any host could claim any client_id.
 *  - **N5** redirect URLs MUST be registered, and the one in an authorization request MUST
 *    match a registered one. See {@link cimdRedirectUriMatches} for the one deliberate,
 *    documented deviation.
 *  - **N11** metadata values come from the RFC 7591 registry.
 *  - **N12** symmetric client authentication is forbidden. A CIMD client is public by
 *    construction, which is also exactly what the SDK's token endpoint needs: it demands a
 *    secret whenever `getClient` reports one, so a public client must report none.
 */

import type { OAuthClientInformationFull } from './internal/sdk.js';
import { validateRedirectUri, XSUAA_DEFAULT_REDIRECT_URI_PATTERNS } from './redirect-uris.js';

/** Grant types this server can actually honour. Anything else in a document is dropped. */
const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;
/** Response types this server can actually honour. */
const SUPPORTED_RESPONSE_TYPES = ['code'] as const;
/** Authentication methods that would make the client confidential — forbidden by N12. */
const SYMMETRIC_AUTH_METHODS = ['client_secret_post', 'client_secret_basic', 'client_secret_jwt'] as const;

const DEFAULT_MAX_REDIRECT_URIS = 16;
const DEFAULT_MAX_CLIENT_NAME_LENGTH = 200;

export type CimdDocumentRejection =
  /** Body was not parseable JSON. */
  | 'not_json'
  /** Body parsed but is not a JSON object (an array or scalar). */
  | 'not_object'
  /** No `client_id` property. */
  | 'client_id_missing'
  /** `client_id` is not byte-identical to the URL it was fetched from (N1). */
  | 'client_id_mismatch'
  /** `redirect_uris` absent, not an array, or empty. */
  | 'redirect_uris_missing'
  /** More redirect URIs than the policy cap allows. */
  | 'too_many_redirect_uris'
  /** A redirect URI failed scheme/shape validation. */
  | 'redirect_uri_invalid'
  /** Declares a confidential authentication method (N12). */
  | 'symmetric_auth_method'
  /** Declares grant or response types with no usable overlap. */
  | 'no_supported_grant_types'
  /** `client_name` longer than the policy cap. */
  | 'client_name_too_long';

export interface CimdDocumentPolicy {
  /** Maximum number of redirect URIs accepted. Default 16. */
  maxRedirectUris?: number;
  /** Maximum `client_name` length in characters. Default 200. */
  maxClientNameLength?: number;
  /**
   * Redirect-URI scheme/shape patterns handed to {@link validateRedirectUri}. Defaults to
   * the shipped XSUAA patterns, which is what makes an unknown custom scheme fail closed.
   */
  redirectUriPatterns?: readonly string[];
}

export interface CimdDocumentAccepted {
  ok: true;
  client: OAuthClientInformationFull;
  /**
   * The document's declared `application_type`, retained for observability only. It is
   * deliberately NOT consulted when matching redirect URIs — see
   * {@link cimdRedirectUriMatches}.
   */
  applicationType?: string;
}

export type CimdDocumentResult = CimdDocumentAccepted | { ok: false; reason: CimdDocumentRejection };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const stringArray = (value: unknown): string[] | undefined =>
  Array.isArray(value) && value.every((entry) => typeof entry === 'string') ? (value as string[]) : undefined;

/**
 * Loopback hosts, byte-identical to the MCP SDK's own set — including the bracketed IPv6
 * form, which is what `URL.hostname` yields for `http://[::1]:8080/cb`.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Decide whether a requested redirect URI matches a registered one.
 *
 * ── The deviation, and why it is the safer choice ──
 * The draft (N5) requires exact simple string comparison. This function additionally
 * relaxes the PORT when both URIs target a loopback host, per RFC 8252 §7.3.
 *
 * That is not a convenience. The MCP SDK's `/authorize` handler already applies exactly
 * this relaxation, and it cannot be configured away. If this end were stricter, a native
 * client would pass `/authorize` and then be refused at `/oauth/callback` — the code would
 * already have been minted and would simply never be delivered. Strictness there buys no
 * security (the decision that mattered happened at `/authorize`) and breaks every native
 * client, which cannot know its ephemeral port when it publishes a STATIC hosted document.
 *
 * An earlier design gated the relaxation on `application_type: "native"`. Mirroring the
 * SDK unconditionally replaced that: gating would make this end stricter than `/authorize`
 * for a `web` document that lists a loopback URI, reintroducing the very disagreement the
 * alignment exists to remove. `application_type` is therefore recorded, not obeyed.
 *
 * Relaxation stays confined to loopback-to-loopback; scheme, host, path and query must
 * still match exactly, and `localhost` does not cross-match `127.0.0.1`.
 */
export function cimdRedirectUriMatches(requested: string, registered: string): boolean {
  if (requested === registered) return true;
  let req: URL;
  let reg: URL;
  try {
    req = new URL(requested);
    reg = new URL(registered);
  } catch {
    return false;
  }
  if (!LOOPBACK_HOSTS.has(req.hostname) || !LOOPBACK_HOSTS.has(reg.hostname)) return false;
  return (
    req.protocol === reg.protocol &&
    req.hostname === reg.hostname &&
    req.pathname === reg.pathname &&
    req.search === reg.search
  );
}

/** True when `uri` matches any entry in `registered` under {@link cimdRedirectUriMatches}. */
export function cimdRedirectUriRegistered(uri: string, registered: readonly string[]): boolean {
  return registered.some((entry) => cimdRedirectUriMatches(uri, entry));
}

/**
 * Validate a fetched document against the Client Identifier URL it came from.
 *
 * `clientIdUrl` must be the exact string used as the `client_id` and as the fetch URL —
 * not a normalised or re-serialised form, because N1's comparison is bytewise.
 */
export function validateCimdDocument(
  clientIdUrl: string,
  body: string,
  policy: CimdDocumentPolicy = {},
): CimdDocumentResult {
  const maxRedirectUris = policy.maxRedirectUris ?? DEFAULT_MAX_REDIRECT_URIS;
  const maxClientNameLength = policy.maxClientNameLength ?? DEFAULT_MAX_CLIENT_NAME_LENGTH;
  const patterns = policy.redirectUriPatterns ?? XSUAA_DEFAULT_REDIRECT_URI_PATTERNS;

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, reason: 'not_json' };
  }
  if (!isRecord(parsed)) return { ok: false, reason: 'not_object' };

  // N1 — the binding between the URL we fetched and the identity we return.
  if (typeof parsed.client_id !== 'string') return { ok: false, reason: 'client_id_missing' };
  if (parsed.client_id !== clientIdUrl) return { ok: false, reason: 'client_id_mismatch' };

  const redirectUris = stringArray(parsed.redirect_uris);
  if (!redirectUris || redirectUris.length === 0) return { ok: false, reason: 'redirect_uris_missing' };
  if (redirectUris.length > maxRedirectUris) return { ok: false, reason: 'too_many_redirect_uris' };
  for (const uri of redirectUris) {
    try {
      // Reuse the package's own validator rather than reimplementing it: it carries
      // non-obvious fixes for authority smuggling and it fails closed on unknown schemes.
      validateRedirectUri(uri, patterns);
    } catch {
      return { ok: false, reason: 'redirect_uri_invalid' };
    }
  }

  // N12 — a CIMD client cannot hold a symmetric secret.
  const authMethod = parsed.token_endpoint_auth_method;
  if (typeof authMethod === 'string' && authMethod !== 'none') {
    if ((SYMMETRIC_AUTH_METHODS as readonly string[]).includes(authMethod)) {
      return { ok: false, reason: 'symmetric_auth_method' };
    }
    // Anything else (private_key_jwt, tls_client_auth, …) is unsupported here rather than
    // forbidden by the draft; refuse it the same way, since we cannot honour it.
    return { ok: false, reason: 'symmetric_auth_method' };
  }

  // Intersect rather than trust: a document may advertise grants this server does not
  // implement, and an empty intersection means there is nothing it could actually do.
  const declaredGrants = stringArray(parsed.grant_types);
  const grantTypes = declaredGrants
    ? declaredGrants.filter((g) => (SUPPORTED_GRANT_TYPES as readonly string[]).includes(g))
    : [...SUPPORTED_GRANT_TYPES];
  const declaredResponses = stringArray(parsed.response_types);
  const responseTypes = declaredResponses
    ? declaredResponses.filter((r) => (SUPPORTED_RESPONSE_TYPES as readonly string[]).includes(r))
    : [...SUPPORTED_RESPONSE_TYPES];
  if (grantTypes.length === 0 || responseTypes.length === 0) {
    return { ok: false, reason: 'no_supported_grant_types' };
  }

  let clientName: string | undefined;
  if (typeof parsed.client_name === 'string') {
    if (parsed.client_name.length > maxClientNameLength) return { ok: false, reason: 'client_name_too_long' };
    clientName = parsed.client_name;
  }

  const applicationType = typeof parsed.application_type === 'string' ? parsed.application_type : undefined;

  return {
    ok: true,
    ...(applicationType !== undefined ? { applicationType } : {}),
    client: {
      client_id: clientIdUrl,
      // Public client: no secret is issued and none is reported. The SDK's token endpoint
      // requires a secret whenever one is reported, so reporting none is what lets the
      // PKCE-only exchange succeed.
      client_secret: undefined,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: 'none',
      ...(clientName !== undefined ? { client_name: clientName } : {}),
    },
  };
}

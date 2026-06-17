/**
 * Stateless OAuth Dynamic Client Registration store.
 *
 * MCP clients (Claude Desktop, Cursor, Copilot CLI…) register dynamically
 * via RFC 7591 and cache the returned `client_id` locally. With an
 * in-memory or local-disk store, every CF push / restart wipes the
 * server-side registry — the cached `client_id` then fails with
 * `invalid_client` and the user has to clear their MCP client's OAuth
 * cache to recover.
 *
 * This store eliminates the storage problem entirely. Each `client_id`
 * is a self-validating token: it carries the registration payload
 * (redirect_uris, grant_types, …) plus an HMAC-SHA256 signature derived
 * from a server-held key. `getClient` re-derives the payload by
 * verifying the signature; no persistence is needed. Any process with
 * the same signing key can validate any client_id ever issued.
 *
 * Tradeoffs vs the persisted in-memory store:
 *   + Survives `cf push`, `cf restart`, cell moves, multi-instance scale-out
 *   + No external dependency, no service binding, no native module
 *   - Per-client revocation is impossible (only TTL or full key rotation)
 *   - Rotating the signing key invalidates every outstanding registration
 *
 * Default TTL is 30 days (matches typical refresh-token lifetimes). Setting
 * `ttlSeconds` to `0` or a negative value disables expiration — recommended
 * when MCP clients don't auto-re-register on `invalid_client` (Copilot CLI,
 * Cursor) and a finite TTL just produces periodic outages without security
 * gain. In that mode, forced revocation goes through full key rotation
 * (rotate the signing secret or bump `kdfLabel` from `mcp-dcr/v1` → `v2`).
 *
 * The signing key is derived (via HKDF-style HMAC) from the XSUAA
 * `clientsecret` (by default), so it's already as stable as the service
 * binding — service rebinding rotates both at once, which is the right
 * boundary.
 */

import crypto from 'node:crypto';
import type { OAuthClientInformationFull, OAuthRegisteredClientsStore } from './internal/sdk.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import {
  XSUAA_DEFAULT_REDIRECT_URIS,
  XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
  matchesRedirectPattern,
  validateRedirectUri,
} from './redirect-uris.js';

// ─── Constants ────────────────────────────────────────────────────────

/** Default prefix all DCR-issued client_ids start with. */
const DEFAULT_ID_PREFIX = 'mcp-';

/**
 * Default domain-separation label bound into the HMAC key derivation. Bumping
 * the suffix ("v1" → "v2") invalidates every previously-issued client_id without
 * requiring a service-binding rotation, which is a useful escape hatch.
 */
const DEFAULT_KDF_LABEL = 'mcp-dcr/v1';

/** Schema version of the JSON payload embedded in the signed client_id. */
const PAYLOAD_VERSION = 1;

/**
 * Truncated HMAC-SHA256 length in bytes. 16 bytes = 128 bits, which is well
 * above the practical forgery threshold for opaque IDs (NIST SP 800-107
 * acceptable for non-replayable identifiers).
 */
const SIG_BYTES = 16;

/**
 * Default lifetime of a DCR registration. 30 days matches typical OAuth
 * refresh-token lifetimes and provides a conservative compromise window.
 * Set `ttlSeconds` to `0` (or any non-positive value) to disable expiration
 * — recommended for environments where MCP clients don't auto-re-register
 * on `invalid_client` (Copilot CLI, Cursor) and a finite TTL produces
 * periodic outages. Forced revocation in that case goes through full key
 * rotation (rotate the signing secret or bump `kdfLabel`).
 */
const DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60;

// Defaults applied when a registration omits these fields.
const DEFAULT_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;
const DEFAULT_RESPONSE_TYPES = ['code'] as const;
const DEFAULT_TOKEN_AUTH_METHOD = 'client_secret_post';

// ─── Payload Schema ───────────────────────────────────────────────────

/**
 * Compact JSON shape stored inside the signed `client_id`.
 *
 * Keys are intentionally short to keep the resulting URL-safe `client_id`
 * under a few hundred bytes — the id is sent in `/authorize` query strings
 * and `client_id` form fields, both of which can be capped by intermediaries.
 */
interface SignedPayload {
  v: number;
  iat: number; // issued-at, seconds since epoch
  ru: string[]; // redirect_uris
  gt?: string[]; // grant_types
  rt?: string[]; // response_types
  am?: string; // token_endpoint_auth_method
  cn?: string; // client_name
}

// ─── Public types ─────────────────────────────────────────────────────

export interface StatelessDcrClientStoreOptions {
  /** Prefix all DCR-issued client_ids start with. Default `'mcp-'`. */
  clientIdPrefix?: string;

  /**
   * Domain-separation label bound into the HMAC key derivation. Default
   * `'mcp-dcr/v1'`. Bumping it ("v1" → "v2") invalidates every previously-issued
   * client_id without a service-binding rotation — a useful revocation escape
   * hatch.
   */
  kdfLabel?: string;

  /**
   * How long an issued client_id remains valid, in seconds. After this
   * window `getClient()` returns undefined and clients are forced to
   * re-register via `/register`. Default: 30 days. Set to `0` (or any
   * non-positive value) to disable expiration — registrations then stay
   * valid until the signing key rotates.
   */
  ttlSeconds?: number;

  /**
   * Redirect-URI allowlist (xs-security.json glob mirror) for the
   * pre-registered default client. Default
   * {@link XSUAA_DEFAULT_REDIRECT_URI_PATTERNS}. MUST stay in sync with the
   * XSUAA service's `oauth2-configuration.redirect-uris`.
   */
  redirectUriPatterns?: readonly string[];

  /**
   * Built-in redirect_uris baked into the pre-registered default client.
   * Default {@link XSUAA_DEFAULT_REDIRECT_URIS}.
   */
  defaultRedirectUris?: readonly string[];

  /** Clock injection point for tests. Default: `Date.now`. */
  now?: () => number;

  /** Injected structural logger. Default: silent no-op. */
  logger?: Logger;
}

// ─── Store ────────────────────────────────────────────────────────────

export class StatelessDcrClientStore implements OAuthRegisteredClientsStore {
  private readonly xsuaaClient: OAuthClientInformationFull;
  private readonly hmacKey: Buffer;
  private readonly ttlSeconds: number;
  private readonly now: () => number;
  private readonly idPrefix: string;
  private readonly redirectUriPatterns: readonly string[];
  private readonly logger: Logger;

  constructor(
    xsuaaClientId: string,
    xsuaaClientSecret: string,
    signingSecret: string,
    options: StatelessDcrClientStoreOptions = {},
  ) {
    if (!signingSecret) {
      throw new Error('StatelessDcrClientStore requires a non-empty signingSecret');
    }
    this.logger = options.logger ?? noopLogger;
    this.idPrefix = options.clientIdPrefix ?? DEFAULT_ID_PREFIX;
    this.redirectUriPatterns = options.redirectUriPatterns ?? XSUAA_DEFAULT_REDIRECT_URI_PATTERNS;
    const kdfLabel = options.kdfLabel ?? DEFAULT_KDF_LABEL;
    const defaultRedirectUris = options.defaultRedirectUris ?? XSUAA_DEFAULT_REDIRECT_URIS;
    // Defense-in-depth: warn (don't throw) on weak signing secrets. NIST
    // SP 800-131A r2 sets 112 bits / 14 bytes as the HMAC floor; 128 bits /
    // 16 bytes is the conservative consensus across production OAuth servers
    // (Keycloak documents 14 chars, Okta requires 32 for client_secret_jwt,
    // Hydra accepts 6 silently). The legacy default (XSUAA `clientsecret`,
    // typically 40+ chars) clears the bar; the realistic trigger here is a
    // test/dev secret. Use byte length, not char length, so multi-byte UTF-8
    // is measured correctly.
    const secretBytes = Buffer.byteLength(signingSecret, 'utf8');
    if (secretBytes < 16) {
      this.logger.warn(
        'StatelessDcrClientStore signing secret is shorter than 16 bytes (128 bits) — below the recommended minimum. Use `openssl rand -base64 48` for a secure value.',
        { bytes: secretBytes },
      );
    }
    // Derive a dedicated HMAC key so the raw service-binding secret is never
    // used directly to sign client_ids. The kdfLabel doubles as a domain
    // separator (see comment on the option).
    this.hmacKey = crypto.createHmac('sha256', signingSecret).update(kdfLabel).digest();
    this.xsuaaClient = buildXsuaaDefaultClient(xsuaaClientId, xsuaaClientSecret, defaultRedirectUris);
    this.ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    this.now = options.now ?? (() => Date.now());
  }

  // ── OAuthRegisteredClientsStore implementation ──

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    if (clientId === this.xsuaaClient.client_id) {
      return this.xsuaaClient;
    }

    if (!clientId.startsWith(this.idPrefix)) {
      this.emitLookupFailed(clientId, 'unknown_prefix');
      return undefined;
    }

    const decoded = this.decodeAndVerify(clientId);
    if (decoded.kind === 'error') {
      this.emitLookupFailed(clientId, decoded.reason);
      return undefined;
    }

    if (this.ttlSeconds > 0) {
      const ageSec = Math.floor(this.now() / 1000) - decoded.payload.iat;
      if (ageSec > this.ttlSeconds) {
        this.emitLookupFailed(clientId, 'expired');
        this.logger.debug('OAuth client expired (TTL)', { clientId, ageSec, ttlSeconds: this.ttlSeconds });
        return undefined;
      }
    }

    return this.payloadToClientInfo(clientId, decoded.payload);
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
  ): Promise<OAuthClientInformationFull> {
    if (client.redirect_uris) {
      for (const uri of client.redirect_uris) {
        validateRedirectUri(uri, this.redirectUriPatterns);
      }
    }

    const issuedAt = Math.floor(this.now() / 1000);
    const payload: SignedPayload = {
      v: PAYLOAD_VERSION,
      iat: issuedAt,
      ru: client.redirect_uris ?? [],
    };
    if (client.grant_types) payload.gt = client.grant_types;
    if (client.response_types) payload.rt = client.response_types;
    if (client.token_endpoint_auth_method) payload.am = client.token_endpoint_auth_method;
    if (client.client_name) payload.cn = client.client_name;

    const clientId = this.encode(payload);
    // RFC 7591 §2 / RFC 8252: a client registering with
    // `token_endpoint_auth_method: 'none'` is a PUBLIC client (PKCE, no secret).
    // The SDK's token-endpoint `authenticateClient` requires a secret whenever
    // `getClient` reports one, so a public client MUST be issued none — otherwise
    // its PKCE-only token exchange is rejected with "Client secret is required"
    // (breaks Cursor / Eclipse / VS Code, which register as public + PKCE).
    const isPublicClient = payload.am === 'none';
    const clientSecret = isPublicClient ? undefined : this.deriveSecret(clientId);

    this.logger.debug('OAuth client registered (stateless)', {
      clientId,
      clientName: client.client_name,
      idBytes: clientId.length,
    });
    this.logger.emitAudit?.({
      timestamp: new Date().toISOString(),
      level: 'info',
      event: 'oauth_client_registered',
      registeredClientId: clientId,
      clientName: client.client_name,
      redirectUriCount: payload.ru.length,
      idBytes: clientId.length,
    });

    // RFC 7591 §3.2.1: `client_secret_expires_at` is REQUIRED when a
    // `client_secret` is issued. Value is the absolute expiry time in
    // seconds since epoch, OR exactly 0 if the secret never expires —
    // exactly the semantic ttlSeconds=0 introduces.
    const clientSecretExpiresAt = isPublicClient ? undefined : this.ttlSeconds > 0 ? issuedAt + this.ttlSeconds : 0;

    return {
      ...client,
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: issuedAt,
      client_secret_expires_at: clientSecretExpiresAt,
    };
  }

  // ── SDK redirect_uri hook ──

  /**
   * Called by the MCP SDK before redirect_uri validation on `/authorize`.
   *
   * For the pre-registered XSUAA client we mutate the in-memory list so the
   * SDK's exact-match check passes. The mutation is replayed on every
   * `/authorize`, so it doesn't need to persist. SECURITY: we register a
   * candidate URI ONLY if it matches `redirectUriPatterns` (the vendored
   * mirror of xs-security.json). The issue-#214 callback proxy removed XSUAA
   * from the client-redirect path, so an un-gated add here would let an attacker
   * register an arbitrary redirect_uri and have the SDK accept it — the entry
   * point for authorization-code interception (security audit 2026-06). A
   * non-matching URI is dropped (audited); the SDK's exact-match check then
   * rejects the `/authorize` request before any state is minted.
   *
   * For DCR (`mcp-…`) clients we are stateless by design: there's nothing
   * to mutate. The previous in-memory store implemented a percent-encoding
   * loose-match (BAS/Theia registers `?x=1` then authorizes with `%3Fx=1`).
   * Reproducing that statelessly would require either bundling every
   * encoding variant in the signed payload or keeping a per-process scratch
   * map, both of which undermine the "no state" goal. We accept the
   * regression: affected clients re-register on encoding-variant mismatch,
   * which is exactly what they did under the old store after every restart.
   */
  ensureRedirectUri(clientId: string, uri: string): void {
    if (clientId !== this.xsuaaClient.client_id) return;
    if (this.xsuaaClient.redirect_uris.includes(uri)) return;

    if (!matchesRedirectPattern(uri, this.redirectUriPatterns)) {
      this.logger.warn('Dynamic redirect_uri rejected for XSUAA default client (not in allowlist)', { clientId, uri });
      this.logger.emitAudit?.({
        timestamp: new Date().toISOString(),
        level: 'warn',
        event: 'oauth_redirect_uri_rejected',
        registeredClientId: clientId,
        redirectUri: uri,
      });
      return;
    }

    this.xsuaaClient.redirect_uris.push(uri);
    this.logger.debug('Dynamic redirect_uri registered for XSUAA client', { clientId, uri });
    this.logger.emitAudit?.({
      timestamp: new Date().toISOString(),
      level: 'info',
      event: 'oauth_redirect_uri_registered',
      registeredClientId: clientId,
      redirectUri: uri,
    });
  }

  /**
   * Validate that `uri` is an allowed redirect target for `clientId` at the
   * `/oauth/callback` proxy — the control that stops authorization-code
   * interception (security audit 2026-06, follow-up to PR #352).
   *
   *  - Default (pre-registered XSUAA) client → must match the redirect-uri
   *    allowlist (`matchesRedirectPattern`). Deliberately consults the
   *    static allowlist, NOT the mutable in-memory list, so the verdict is
   *    stateless and identical on every instance — a code is never forwarded to
   *    an unlisted URI even if `/authorize` ran on a different instance.
   *  - DCR (`mcp-…`) client → must be one of the redirect_uris baked immutably
   *    into the signed client_id (re-derived by `getClient`). Returns
   *    `unknown_client` when the id is unrecognised / expired / forged.
   */
  async checkRedirectUri(clientId: string, uri: string): Promise<'ok' | 'unknown_client' | 'unregistered'> {
    if (clientId === this.xsuaaClient.client_id) {
      return matchesRedirectPattern(uri, this.redirectUriPatterns) ? 'ok' : 'unregistered';
    }
    const info = await this.getClient(clientId);
    if (!info) return 'unknown_client';
    return info.redirect_uris.includes(uri) ? 'ok' : 'unregistered';
  }

  // ── Internals: encode / decode / sign / verify ──

  private payloadToClientInfo(clientId: string, payload: SignedPayload): OAuthClientInformationFull {
    // Public clients (token_endpoint_auth_method 'none') carry no secret — see
    // registerClient. getClient must report none too, or the SDK's token-endpoint
    // clientAuth ("if client.client_secret → secret required") rejects the
    // public client's PKCE-only exchange.
    const isPublicClient = payload.am === 'none';
    return {
      client_id: clientId,
      client_secret: isPublicClient ? undefined : this.deriveSecret(clientId),
      client_id_issued_at: payload.iat,
      redirect_uris: payload.ru,
      grant_types: payload.gt ?? [...DEFAULT_GRANT_TYPES],
      response_types: payload.rt ?? [...DEFAULT_RESPONSE_TYPES],
      token_endpoint_auth_method: payload.am ?? DEFAULT_TOKEN_AUTH_METHOD,
      client_name: payload.cn,
    };
  }

  private encode(payload: SignedPayload): string {
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = this.sign(payloadB64);
    return `${this.idPrefix}${payloadB64}.${sig}`;
  }

  /**
   * Decode and verify a `client_id`. Returns either the parsed payload or a
   * structured failure reason — the caller emits the failure as an audit
   * event with the right reason code (so probing attempts are observable).
   */
  private decodeAndVerify(
    clientId: string,
  ):
    | { kind: 'ok'; payload: SignedPayload }
    | { kind: 'error'; reason: 'malformed' | 'bad_signature' | 'invalid_payload' } {
    const stripped = clientId.slice(this.idPrefix.length);
    const dot = stripped.lastIndexOf('.');
    if (dot < 0) return { kind: 'error', reason: 'malformed' };

    const payloadB64 = stripped.slice(0, dot);
    const sigB64 = stripped.slice(dot + 1);

    if (!this.verifySignature(payloadB64, sigB64)) {
      return { kind: 'error', reason: 'bad_signature' };
    }

    const payload = parsePayload(payloadB64);
    if (!payload) return { kind: 'error', reason: 'invalid_payload' };

    return { kind: 'ok', payload };
  }

  private verifySignature(payloadB64: string, sigB64: string): boolean {
    const expected = Buffer.from(this.sign(payloadB64), 'base64url');
    const actual = Buffer.from(sigB64, 'base64url');
    if (actual.length !== expected.length || actual.length !== SIG_BYTES) return false;
    return crypto.timingSafeEqual(actual, expected);
  }

  private sign(payloadB64: string): string {
    const fullDigest = crypto.createHmac('sha256', this.hmacKey).update(payloadB64).digest();
    // Truncate to SIG_BYTES — see the comment on the constant for rationale.
    return fullDigest.subarray(0, SIG_BYTES).toString('base64url');
  }

  /**
   * The client_secret is derived deterministically from the client_id, so
   * any instance with the same signing key can validate it. This is the
   * core reason DCR survives container restarts and scales out horizontally
   * with no shared state.
   */
  private deriveSecret(clientId: string): string {
    return crypto.createHmac('sha256', this.hmacKey).update(`secret:${clientId}`).digest('base64url');
  }

  private emitLookupFailed(
    clientId: string,
    reason: 'unknown_prefix' | 'malformed' | 'bad_signature' | 'invalid_payload' | 'expired',
  ): void {
    this.logger.debug('OAuth client lookup failed', { clientId, reason });
    this.logger.emitAudit?.({
      timestamp: new Date().toISOString(),
      // 'expired' is normal-ish (TTL eviction); the rest are probing/forgery signals.
      level: reason === 'expired' ? 'info' : 'warn',
      event: 'oauth_client_lookup_failed',
      registeredClientId: clientId,
      reason,
    });
  }
}

// ─── Default XSUAA client ─────────────────────────────────────────────

/**
 * Pre-registered XSUAA client config. MCP clients that hit the XSUAA
 * `clientid` directly (Manual mode in Copilot Studio, etc.) resolve through
 * this entry instead of going through DCR.
 */
function buildXsuaaDefaultClient(
  clientId: string,
  clientSecret: string,
  defaultRedirectUris: readonly string[],
): OAuthClientInformationFull {
  return {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [...defaultRedirectUris],
    grant_types: [...DEFAULT_GRANT_TYPES],
    response_types: [...DEFAULT_RESPONSE_TYPES],
    token_endpoint_auth_method: DEFAULT_TOKEN_AUTH_METHOD,
    client_name: 'MCP XSUAA Default Client',
  };
}

// ─── Module-level helpers ─────────────────────────────────────────────

/**
 * Parse a base64url-encoded payload back into a typed `SignedPayload`. Returns
 * `undefined` on any failure (decode error, JSON parse error, schema mismatch).
 */
function parsePayload(payloadB64: string): SignedPayload | undefined {
  try {
    const json = Buffer.from(payloadB64, 'base64url').toString('utf8');
    const parsed = JSON.parse(json) as SignedPayload;
    if (parsed.v !== PAYLOAD_VERSION) return undefined;
    if (typeof parsed.iat !== 'number' || !Array.isArray(parsed.ru)) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

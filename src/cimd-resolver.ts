/**
 * Resolution of an HTTPS-URL `client_id` into a client record: cache, single-flight,
 * hardened fetch, document validation.
 *
 * This is the piece that turns SEP-991's "the client_id IS a URL" into something the MCP
 * SDK's `OAuthRegisteredClientsStore` can answer with. It sits between `cimd-fetch.ts`
 * (transport, SSRF controls) and `cimd-document.ts` (what the bytes are allowed to say),
 * and adds the two properties neither of them can provide alone: bounded repetition and
 * a stable snapshot.
 *
 * ── Why a single snapshot matters ──
 * A document can change after it validates — the draft calls this out explicitly. An
 * authorization is checked twice against it: once at `/authorize` and again when the code
 * is released at `/oauth/callback`. Both checks read the SAME cache entry, so a document
 * edited mid-flight cannot turn a granted authorization into a puzzling refusal, and the
 * exposure window is bounded by the TTL rather than by the document author's whim.
 *
 * ── Fail closed, and terminally ──
 * Every failure returns a reason and nothing else. A `client_id` that has been classified
 * as CIMD is never retried down another path: a fallback is precisely how a blocked fetch
 * becomes an unblocked one.
 */

import { CimdCache, type CimdCacheOptions, ttlFromCacheHeaders } from './cimd-cache.js';
import { type CimdDocumentPolicy, type CimdDocumentRejection, validateCimdDocument } from './cimd-document.js';
import {
  type CimdFetchFailureReason,
  type CimdFetchOptions,
  fetchClientIdMetadataDocument,
  validateClientIdUrl,
} from './cimd-fetch.js';
import type { OAuthClientInformationFull } from './internal/sdk.js';
import { type Logger, noopLogger } from './logger.js';

/** Everything that can stop a URL client_id from resolving. Audit-only, never user-facing. */
export type CimdResolutionFailure = CimdFetchFailureReason | CimdDocumentRejection;

export interface CimdResolution {
  client: OAuthClientInformationFull;
  applicationType?: string;
}

export type CimdResolveResult =
  | { ok: true; resolution: CimdResolution; cacheHit: boolean }
  | { ok: false; reason: CimdResolutionFailure; cacheHit: boolean };

export interface CimdResolverOptions {
  /** Host allowlist. Empty or omitted means open — see the package README. */
  allowedHosts?: readonly string[];
  /** Forward proxy to tunnel through. See `cimd-fetch.ts`. */
  proxyUrl?: string;
  /** Transport tuning passed through to the fetcher. */
  fetch?: Pick<CimdFetchOptions, 'connectTimeoutMs' | 'globalTimeoutMs' | 'maxBytes'>;
  /** Document-shape caps. */
  document?: CimdDocumentPolicy;
  /** Cache tuning. */
  cache?: CimdCacheOptions;
  /** Injected structural logger. Default: silent no-op. */
  logger?: Logger;
}

type CachedOutcome = { ok: true; resolution: CimdResolution } | { ok: false; reason: CimdResolutionFailure };

/**
 * Network-level failures worth retrying sooner than a document that is simply wrong. A
 * malformed document will still be malformed in thirty seconds; a timeout may not be.
 */
const TRANSIENT_REASONS: ReadonlySet<string> = new Set<CimdResolutionFailure>([
  'dns_failure',
  'timeout',
  'network_error',
  'tls_failure',
  'bad_status',
  'proxy_unreachable',
]);

export class CimdResolver {
  private readonly cache: CimdCache<CachedOutcome>;
  private readonly inFlight = new Map<string, Promise<CimdResolveResult>>();
  private readonly options: CimdResolverOptions;
  private readonly logger: Logger;

  constructor(options: CimdResolverOptions = {}) {
    this.options = options;
    this.logger = options.logger ?? noopLogger;
    this.cache = new CimdCache<CachedOutcome>(options.cache ?? {});
  }

  /** True when `clientId` should be treated as a CIMD identity rather than a DCR one. */
  static isUrlClientId(clientId: string): boolean {
    // Decide on the PARSED value, never a raw `startsWith('https://')`: this codebase has
    // already learned (see `matchesRedirectPattern`) that raw-string decisions about URLs
    // diverge from how the URL later parses.
    try {
      return new URL(clientId).protocol === 'https:';
    } catch {
      return false;
    }
  }

  async resolve(clientId: string): Promise<CimdResolveResult> {
    const cached = this.cache.get(clientId);
    if (cached) {
      this.logger.debug('CIMD cache hit', { clientId, ok: cached.ok });
      return { ...cached, cacheHit: true };
    }

    // Coalesce concurrent resolutions of the same id. Without this a burst of identical
    // `/authorize` calls multiplies one-to-one into outbound requests.
    const existing = this.inFlight.get(clientId);
    if (existing) return await existing;

    const flight = this.resolveUncached(clientId).finally(() => {
      this.inFlight.delete(clientId);
    });
    this.inFlight.set(clientId, flight);
    return await flight;
  }

  private async resolveUncached(clientId: string): Promise<CimdResolveResult> {
    // Everything below this point performed (or attempted) real work, so nothing here is
    // a cache hit — including the callers coalesced into this same flight.
    // Shape and allowlist first: a refusal here costs no DNS and no socket.
    const shape = validateClientIdUrl(clientId, this.options.allowedHosts);
    if (!shape.ok) return this.remember(clientId, { ok: false, reason: shape.reason });

    const fetched = await fetchClientIdMetadataDocument(clientId, {
      ...(this.options.allowedHosts ? { allowedHosts: this.options.allowedHosts } : {}),
      ...(this.options.proxyUrl !== undefined ? { proxyUrl: this.options.proxyUrl } : {}),
      ...this.options.fetch,
    });
    if (!fetched.ok) return this.remember(clientId, { ok: false, reason: fetched.reason });

    const validated = validateCimdDocument(clientId, fetched.body, this.options.document ?? {});
    if (!validated.ok) return this.remember(clientId, { ok: false, reason: validated.reason });

    const ttl = ttlFromCacheHeaders(
      { cacheControl: fetched.cacheControl, expires: fetched.expires },
      Date.now(),
      this.cache.options,
    );
    const outcome: CachedOutcome = {
      ok: true,
      resolution: {
        client: validated.client,
        ...(validated.applicationType !== undefined ? { applicationType: validated.applicationType } : {}),
      },
    };
    this.cache.set(clientId, outcome, ttl);
    this.logger.debug('CIMD document resolved', {
      clientId,
      redirectUriCount: validated.client.redirect_uris.length,
      ttlSeconds: ttl,
    });
    return { ...outcome, cacheHit: false };
  }

  private remember(clientId: string, failure: { ok: false; reason: CimdResolutionFailure }): CimdResolveResult {
    const ttl = TRANSIENT_REASONS.has(failure.reason)
      ? this.cache.options.transientNegativeTtlSeconds
      : this.cache.options.negativeTtlSeconds;
    this.cache.set(clientId, failure, ttl);
    this.logger.debug('CIMD resolution failed', { clientId, reason: failure.reason, ttlSeconds: ttl });
    return { ...failure, cacheHit: false };
  }
}

/**
 * Bounded, per-instance cache for resolved Client ID Metadata Documents.
 *
 * ── Why per-instance and in memory ──
 * The consumer of this package is stateless by design, and its rate limiters are already
 * per-instance and in memory. A shared store would reintroduce exactly the durable
 * registration state that CIMD exists to remove. Divergence between instances is bounded
 * by the TTL ceiling and is harmless: the document is public, idempotent, and cheap to
 * re-fetch.
 *
 * ── Why failures are cached too ──
 * `/authorize` is unauthenticated, so a hostile or simply broken `client_id` could
 * otherwise be replayed into unbounded outbound traffic. Negative entries turn that into
 * one fetch per TTL. Permanent failures (the document is wrong) are held longer than
 * transient ones (the network blipped), so a brief outage does not lock a legitimate
 * client out for as long as a bogus document is suppressed.
 *
 * ── Why the key is the raw string ──
 * Keys are the exact `client_id` text, never a normalised URL. The draft compares
 * identities by simple string comparison, so `https://x/c` and `https://x:443/c` are
 * different clients; normalising here would quietly merge them.
 */

/** How long a cached failure is honoured, by cause. */
export type CimdFailureKind = 'permanent' | 'transient';

export interface CimdCacheOptions {
  /** Maximum entries before least-recently-used eviction. Default 256. */
  maxEntries?: number;
  /** TTL applied when the response carries no usable cache headers. Default 900 s. */
  defaultTtlSeconds?: number;
  /** Lower clamp on any TTL derived from cache headers. Default 300 s. */
  minTtlSeconds?: number;
  /** Upper clamp on any TTL derived from cache headers. Default 3600 s. */
  maxTtlSeconds?: number;
  /** TTL for a document that failed validation. Default 300 s. */
  negativeTtlSeconds?: number;
  /** TTL for a network-level failure. Default 30 s. */
  transientNegativeTtlSeconds?: number;
  /** Clock injection point for tests. Default `Date.now`. */
  now?: () => number;
}

interface CacheEntry<T> {
  value: T;
  expiresAtMs: number;
}

const DEFAULTS = {
  maxEntries: 256,
  defaultTtlSeconds: 900,
  minTtlSeconds: 300,
  maxTtlSeconds: 3600,
  negativeTtlSeconds: 300,
  transientNegativeTtlSeconds: 30,
} as const;

/**
 * Derive a cache lifetime from RFC 9111 response headers, clamped to the configured
 * bounds. The draft explicitly permits an authorization server to impose its own bounds.
 *
 * The floor matters: without it a hostile document could serve `max-age=0` and make every
 * single `/authorize` call an outbound fetch, which is the amplification primitive the
 * cache exists to remove. `no-store`/`no-cache` are treated the same way — honoured as
 * "as briefly as we allow", not as "never cache".
 *
 * The ceiling matters for the opposite reason: it bounds how long a legitimate client's
 * rotated redirect URIs can go unnoticed.
 */
export function ttlFromCacheHeaders(
  headers: { cacheControl?: string | undefined; expires?: string | undefined },
  nowMs: number,
  options: Pick<CimdCacheOptions, 'defaultTtlSeconds' | 'minTtlSeconds' | 'maxTtlSeconds'> = {},
): number {
  const def = options.defaultTtlSeconds ?? DEFAULTS.defaultTtlSeconds;
  const min = options.minTtlSeconds ?? DEFAULTS.minTtlSeconds;
  const max = options.maxTtlSeconds ?? DEFAULTS.maxTtlSeconds;
  const clamp = (seconds: number): number => Math.min(max, Math.max(min, seconds));

  const cc = headers.cacheControl?.toLowerCase();
  if (cc) {
    if (/(^|[\s,])(no-store|no-cache)([\s,;]|$)/.test(cc)) return clamp(0);
    const maxAge = /(^|[\s,])max-age\s*=\s*"?(\d+)"?/.exec(cc)?.[2];
    if (maxAge !== undefined) return clamp(Number(maxAge));
  }
  if (headers.expires) {
    const at = Date.parse(headers.expires);
    if (!Number.isNaN(at)) return clamp(Math.floor((at - nowMs) / 1000));
  }
  return clamp(def);
}

/**
 * A small TTL + LRU map. Deliberately not a dependency: the behaviour needed here is a few
 * dozen lines, and the security-relevant part is the bound, not the eviction policy.
 */
export class CimdCache<T> {
  private readonly entries = new Map<string, CacheEntry<T>>();
  private readonly maxEntries: number;
  private readonly now: () => number;
  readonly options: Required<Omit<CimdCacheOptions, 'now'>>;

  constructor(options: CimdCacheOptions = {}) {
    this.now = options.now ?? (() => Date.now());
    this.maxEntries = options.maxEntries ?? DEFAULTS.maxEntries;
    this.options = {
      maxEntries: this.maxEntries,
      defaultTtlSeconds: options.defaultTtlSeconds ?? DEFAULTS.defaultTtlSeconds,
      minTtlSeconds: options.minTtlSeconds ?? DEFAULTS.minTtlSeconds,
      maxTtlSeconds: options.maxTtlSeconds ?? DEFAULTS.maxTtlSeconds,
      negativeTtlSeconds: options.negativeTtlSeconds ?? DEFAULTS.negativeTtlSeconds,
      transientNegativeTtlSeconds: options.transientNegativeTtlSeconds ?? DEFAULTS.transientNegativeTtlSeconds,
    };
  }

  /** Current entry count, expired-but-not-yet-evicted entries included. For tests/metrics. */
  get size(): number {
    return this.entries.size;
  }

  get(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Re-insert so Map iteration order tracks recency: the oldest key is evicted first.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, value: T, ttlSeconds: number): void {
    if (ttlSeconds <= 0) return;
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAtMs: this.now() + ttlSeconds * 1000 });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}

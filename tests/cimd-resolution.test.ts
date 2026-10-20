/**
 * CIMD resolution (T2): document validation, caching, and the `getClient` /
 * `checkRedirectUri` integration.
 *
 * The transport is mocked here — `cimd-fetch.test.ts` owns the SSRF controls, and
 * re-proving them through this layer would only couple the two suites. `validateClientIdUrl`
 * is kept REAL via `importOriginal`, because URL-shape refusal is part of the resolution
 * contract and must stay wired.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CimdCache, ttlFromCacheHeaders } from '../src/cimd-cache.js';
import { cimdRedirectUriMatches, validateCimdDocument } from '../src/cimd-document.js';
import { CimdResolver } from '../src/cimd-resolver.js';
import { StatelessDcrClientStore } from '../src/index.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

const mockFetch = vi.hoisted(() => vi.fn());
vi.mock('../src/cimd-fetch.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/cimd-fetch.js')>();
  return { ...actual, fetchClientIdMetadataDocument: mockFetch };
});

const URL_ID = 'https://client.example.com/mcp/metadata.json';

/** A minimal document that passes every check. */
function goodDoc(overrides: Record<string, unknown> = {}, clientId = URL_ID): string {
  return JSON.stringify({
    client_id: clientId,
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    ...overrides,
  });
}

function serves(body: string, headers: { cacheControl?: string; expires?: string } = {}): void {
  mockFetch.mockResolvedValue({ ok: true, body, resolvedAddress: '93.184.216.34', ...headers });
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('validateCimdDocument', () => {
  it('accepts a well-formed document and reports it as a public client', () => {
    const result = validateCimdDocument(URL_ID, goodDoc({ client_name: 'Example', application_type: 'web' }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.client_id).toBe(URL_ID);
    // A CIMD client is public by construction (N12), and the SDK's token endpoint demands
    // a secret whenever getClient reports one — so it must report none.
    expect(result.client.client_secret).toBeUndefined();
    expect(result.client.token_endpoint_auth_method).toBe('none');
    expect(result.client.grant_types).toEqual(['authorization_code', 'refresh_token']);
    expect(result.client.response_types).toEqual(['code']);
    expect(result.client.client_name).toBe('Example');
    expect(result.applicationType).toBe('web');
  });

  it('enforces N1: the document client_id must equal the URL, bytewise', () => {
    const mismatch = validateCimdDocument(URL_ID, goodDoc({}, 'https://other.example.com/m.json'));
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) expect(mismatch.reason).toBe('client_id_mismatch');

    // Simple string comparison means a port-normalised spelling is a DIFFERENT identity.
    const ported = validateCimdDocument(URL_ID, goodDoc({}, 'https://client.example.com:443/mcp/metadata.json'));
    expect(ported.ok).toBe(false);
    if (!ported.ok) expect(ported.reason).toBe('client_id_mismatch');
  });

  it('rejects a missing client_id, non-JSON, and non-object bodies', () => {
    for (const [body, reason] of [
      ['not json at all', 'not_json'],
      ['[]', 'not_object'],
      ['"a string"', 'not_object'],
      ['42', 'not_object'],
      [JSON.stringify({ redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] }), 'client_id_missing'],
    ] as const) {
      const r = validateCimdDocument(URL_ID, body);
      expect(r.ok, body).toBe(false);
      if (!r.ok) expect(r.reason, body).toBe(reason);
    }
  });

  it('requires a non-empty, capped, individually valid redirect_uris list', () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ redirect_uris: undefined }, 'redirect_uris_missing'],
      [{ redirect_uris: [] }, 'redirect_uris_missing'],
      [{ redirect_uris: 'https://claude.ai/api/mcp/auth_callback' }, 'redirect_uris_missing'],
      [{ redirect_uris: [1, 2] }, 'redirect_uris_missing'],
      [{ redirect_uris: ['javascript:alert(1)'] }, 'redirect_uri_invalid'],
      [{ redirect_uris: ['http://evil.example.com/cb'] }, 'redirect_uri_invalid'], // http, non-loopback
      [{ redirect_uris: ['totally-unknown-scheme://cb'] }, 'redirect_uri_invalid'],
      [{ redirect_uris: Array.from({ length: 17 }, (_, i) => `https://claude.ai/cb${i}`) }, 'too_many_redirect_uris'],
    ];
    for (const [overrides, reason] of cases) {
      const r = validateCimdDocument(URL_ID, goodDoc(overrides));
      expect(r.ok, reason).toBe(false);
      if (!r.ok) expect(r.reason, JSON.stringify(overrides).slice(0, 60)).toBe(reason);
    }
  });

  it('refuses any confidential authentication method (N12)', () => {
    for (const method of ['client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt']) {
      const r = validateCimdDocument(URL_ID, goodDoc({ token_endpoint_auth_method: method }));
      expect(r.ok, method).toBe(false);
      if (!r.ok) expect(r.reason, method).toBe('symmetric_auth_method');
    }
    expect(validateCimdDocument(URL_ID, goodDoc({ token_endpoint_auth_method: 'none' })).ok).toBe(true);
  });

  it('intersects grant and response types, and refuses an empty intersection', () => {
    const narrowed = validateCimdDocument(
      URL_ID,
      goodDoc({ grant_types: ['authorization_code', 'client_credentials'] }),
    );
    expect(narrowed.ok).toBe(true);
    if (narrowed.ok) expect(narrowed.client.grant_types).toEqual(['authorization_code']);

    for (const overrides of [{ grant_types: ['client_credentials'] }, { response_types: ['token'] }]) {
      const r = validateCimdDocument(URL_ID, goodDoc(overrides));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('no_supported_grant_types');
    }
  });

  it('caps client_name and ignores unknown fields', () => {
    const long = validateCimdDocument(URL_ID, goodDoc({ client_name: 'x'.repeat(201) }));
    expect(long.ok).toBe(false);
    if (!long.ok) expect(long.reason).toBe('client_name_too_long');

    const extra = validateCimdDocument(
      URL_ID,
      goodDoc({ logo_uri: 'https://evil/x.png', jwks_uri: 'http://10.0.0.1/j' }),
    );
    expect(extra.ok).toBe(true);
    // Nothing from the document is carried through except what was validated — in
    // particular no URL that this server might later be tempted to dereference.
    if (extra.ok) expect(Object.keys(extra.client)).not.toContain('logo_uri');
  });
});

describe('cimdRedirectUriMatches — mirrors the SDK so both ends agree', () => {
  it('matches identical URIs', () => {
    expect(cimdRedirectUriMatches('https://claude.ai/cb', 'https://claude.ai/cb')).toBe(true);
    expect(cimdRedirectUriMatches('https://claude.ai/cb', 'https://claude.ai/other')).toBe(false);
  });

  it('relaxes only the port, and only loopback-to-loopback', () => {
    // A hosted static document cannot know a native client's ephemeral port.
    expect(cimdRedirectUriMatches('http://127.0.0.1:61234/cb', 'http://127.0.0.1:5000/cb')).toBe(true);
    expect(cimdRedirectUriMatches('http://localhost:61234/cb', 'http://localhost:5000/cb')).toBe(true);
    expect(cimdRedirectUriMatches('http://[::1]:61234/cb', 'http://[::1]:5000/cb')).toBe(true);
    // Non-loopback gets no relaxation at all.
    expect(cimdRedirectUriMatches('https://claude.ai:8443/cb', 'https://claude.ai/cb')).toBe(false);
  });

  it('does not cross-match localhost and 127.0.0.1, or differing path/query/scheme', () => {
    expect(cimdRedirectUriMatches('http://127.0.0.1:5000/cb', 'http://localhost:5000/cb')).toBe(false);
    expect(cimdRedirectUriMatches('http://127.0.0.1:1/cb', 'http://127.0.0.1:2/other')).toBe(false);
    expect(cimdRedirectUriMatches('http://127.0.0.1:1/cb?a=1', 'http://127.0.0.1:2/cb?a=2')).toBe(false);
    expect(cimdRedirectUriMatches('https://127.0.0.1:1/cb', 'http://127.0.0.1:2/cb')).toBe(false);
  });
});

describe('ttlFromCacheHeaders — RFC 9111 within our own bounds', () => {
  const bounds = { defaultTtlSeconds: 900, minTtlSeconds: 300, maxTtlSeconds: 3600 };
  const now = Date.UTC(2026, 7, 18, 12, 0, 0);

  it('honours max-age inside the bounds', () => {
    expect(ttlFromCacheHeaders({ cacheControl: 'max-age=600' }, now, bounds)).toBe(600);
    expect(ttlFromCacheHeaders({ cacheControl: 'public, max-age=1200, immutable' }, now, bounds)).toBe(1200);
  });

  it('clamps a hostile max-age=0 up to the floor', () => {
    // Without the floor, a document could make every single /authorize an outbound fetch.
    expect(ttlFromCacheHeaders({ cacheControl: 'max-age=0' }, now, bounds)).toBe(300);
    expect(ttlFromCacheHeaders({ cacheControl: 'no-store' }, now, bounds)).toBe(300);
    expect(ttlFromCacheHeaders({ cacheControl: 'no-cache, max-age=99999' }, now, bounds)).toBe(300);
  });

  it('clamps an over-long max-age down to the ceiling', () => {
    expect(ttlFromCacheHeaders({ cacheControl: 'max-age=999999' }, now, bounds)).toBe(3600);
  });

  it('falls back to Expires, then to the default', () => {
    expect(ttlFromCacheHeaders({ expires: new Date(now + 600_000).toUTCString() }, now, bounds)).toBe(600);
    expect(ttlFromCacheHeaders({ expires: 'garbage' }, now, bounds)).toBe(900);
    expect(ttlFromCacheHeaders({}, now, bounds)).toBe(900);
  });
});

describe('CimdCache', () => {
  it('expires entries and evicts least-recently-used ones', () => {
    let clock = 1_000_000;
    const cache = new CimdCache<string>({ maxEntries: 2, now: () => clock });

    cache.set('a', 'A', 10);
    cache.set('b', 'B', 10);
    expect(cache.get('a')).toBe('A'); // refreshes recency of 'a'
    cache.set('c', 'C', 10);
    expect(cache.size).toBe(2);
    expect(cache.get('b')).toBeUndefined(); // 'b' was least recently used
    expect(cache.get('a')).toBe('A');

    clock += 11_000;
    expect(cache.get('a')).toBeUndefined();
  });
});

describe('CimdResolver', () => {
  it('classifies client_ids on the parsed URL, not a raw prefix', () => {
    expect(CimdResolver.isUrlClientId('https://x.example.com/m.json')).toBe(true);
    expect(CimdResolver.isUrlClientId('HTTPS://x.example.com/m.json')).toBe(true); // scheme is case-insensitive
    expect(CimdResolver.isUrlClientId('http://x.example.com/m.json')).toBe(false);
    expect(CimdResolver.isUrlClientId('mcp-abc.def')).toBe(false);
    expect(CimdResolver.isUrlClientId('sb-arc1!t599384')).toBe(false);
    expect(CimdResolver.isUrlClientId('')).toBe(false);
  });

  it('caches a resolved document and does not refetch within the TTL', async () => {
    serves(goodDoc(), { cacheControl: 'max-age=600' });
    const resolver = new CimdResolver();
    const first = await resolver.resolve(URL_ID);
    const second = await resolver.resolve(URL_ID);
    expect(first.ok && second.ok).toBe(true);
    expect(first.cacheHit).toBe(false);
    expect(second.cacheHit).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('coalesces concurrent resolutions into one fetch', async () => {
    let release: (v: unknown) => void = () => {};
    mockFetch.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ ok: true, body: goodDoc(), resolvedAddress: '1.1.1.1' });
        }),
    );
    const resolver = new CimdResolver();
    const all = Promise.all([resolver.resolve(URL_ID), resolver.resolve(URL_ID), resolver.resolve(URL_ID)]);
    release(undefined);
    const results = await all;
    expect(results.every((r) => r.ok)).toBe(true);
    // A burst of identical /authorize calls must not multiply into outbound requests.
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('caches a validation failure longer than a transient one', async () => {
    const resolver = new CimdResolver();
    serves(goodDoc({}, 'https://wrong.example.com/m.json'));
    const bad = await resolver.resolve(URL_ID);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toBe('client_id_mismatch');
    // Re-asking is served from the negative entry, not from a second fetch.
    await resolver.resolve(URL_ID);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('refuses a bad URL shape without fetching', async () => {
    const resolver = new CimdResolver();
    const result = await resolver.resolve('https://client.example.com');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('shape');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('propagates a transport refusal verbatim', async () => {
    mockFetch.mockResolvedValue({ ok: false, reason: 'blocked_address' });
    const resolver = new CimdResolver();
    const result = await resolver.resolve(URL_ID);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('blocked_address');
  });
});

describe('StatelessDcrClientStore — CIMD integration', () => {
  const XSUAA_ID = 'sb-arc1!t599384';
  const makeStore = (cimd?: Record<string, unknown>, logger = makeCapturingLogger()) => ({
    store: new StatelessDcrClientStore(XSUAA_ID, 'xsuaa-secret', 'signing-secret-long-enough', {
      logger,
      ...(cimd ? { cimd } : {}),
    }),
    logger,
  });

  it('resolves a URL client_id through getClient when enabled', async () => {
    serves(goodDoc());
    const { store, logger } = makeStore({});
    const client = await store.getClient(URL_ID);
    expect(client?.client_id).toBe(URL_ID);
    expect(client?.client_secret).toBeUndefined();
    expect(logger.audit.some((e) => e.event === 'oauth_cimd_resolved')).toBe(true);
  });

  it('refuses a URL client_id when CIMD is disabled, and says so', async () => {
    const { store, logger } = makeStore();
    expect(await store.getClient(URL_ID)).toBeUndefined();
    expect(mockFetch).not.toHaveBeenCalled();
    const event = logger.audit.find((e) => e.event === 'oauth_cimd_rejected');
    expect(event?.reason).toBe('cimd_disabled');
  });

  it('never falls back to the DCR path when CIMD resolution fails', async () => {
    mockFetch.mockResolvedValue({ ok: false, reason: 'blocked_address' });
    const { store, logger } = makeStore({});
    expect(await store.getClient(URL_ID)).toBeUndefined();
    // A fallback is how a refused fetch becomes an accepted one, so the DCR branch must
    // not even be consulted: no `unknown_prefix` lookup failure is recorded.
    expect(logger.audit.some((e) => e.event === 'oauth_client_lookup_failed')).toBe(false);
    const event = logger.audit.find((e) => e.event === 'oauth_cimd_rejected');
    expect(event?.reason).toBe('blocked_address');
    expect(event?.level).toBe('warn');
  });

  it('leaves DCR and the default client untouched when CIMD is on', async () => {
    serves(goodDoc());
    const { store } = makeStore({});
    const registered = await store.registerClient({
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      token_endpoint_auth_method: 'none',
    } as never);
    expect(registered.client_id.startsWith('mcp-')).toBe(true);
    expect((await store.getClient(registered.client_id))?.client_id).toBe(registered.client_id);
    expect((await store.getClient(XSUAA_ID))?.client_id).toBe(XSUAA_ID);
  });

  it('checks a CIMD redirect_uri against the document, through the same cache entry', async () => {
    serves(goodDoc({ redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] }));
    const { store } = makeStore({});
    expect(await store.checkRedirectUri(URL_ID, 'https://claude.ai/api/mcp/auth_callback')).toBe('ok');
    expect(await store.checkRedirectUri(URL_ID, 'https://evil.example.com/cb')).toBe('unregistered');
    // /authorize and /oauth/callback must read one snapshot, so a document edited
    // mid-flight cannot turn a granted authorization into a puzzling refusal.
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('applies loopback port relaxation to a CIMD client, matching /authorize', async () => {
    serves(goodDoc({ redirect_uris: ['http://127.0.0.1:5000/callback'] }));
    const { store } = makeStore({});
    expect(await store.checkRedirectUri(URL_ID, 'http://127.0.0.1:61234/callback')).toBe('ok');
    expect(await store.checkRedirectUri(URL_ID, 'http://127.0.0.1:61234/other')).toBe('unregistered');
  });

  it('reports unknown_client for a CIMD id that cannot be resolved', async () => {
    mockFetch.mockResolvedValue({ ok: false, reason: 'timeout' });
    const { store } = makeStore({});
    expect(await store.checkRedirectUri(URL_ID, 'https://claude.ai/api/mcp/auth_callback')).toBe('unknown_client');
  });

  it('ensureRedirectUri is a no-op for CIMD clients — the document is the client’s to state', async () => {
    serves(goodDoc());
    const { store, logger } = makeStore({});
    store.ensureRedirectUri(URL_ID, 'https://attacker.example.com/cb');
    expect(logger.audit.some((e) => e.event === 'oauth_redirect_uri_registered')).toBe(false);
    // And the widening did not take: the document still governs.
    expect(await store.checkRedirectUri(URL_ID, 'https://attacker.example.com/cb')).toBe('unregistered');
  });
});

/**
 * Tests for the bearer-token verifiers (SPEC §6).
 *
 *  - createApiKeyVerifier: single-string + ApiKeyEntry[] forms, wrong-key rejection,
 *    scopes/clientId attached, injected expandScopes applied.
 *  - createOidcVerifier: a REAL RS256 token is minted with `jose` and verified
 *    against a local JWKS served through a stubbed global `fetch` (discovery +
 *    jwks_uri), so the alg-pinning is genuinely exercised — `alg:none` and a
 *    disallowed alg are rejected; issuer/audience mismatch rejected.
 *  - createChainedTokenVerifier: the SPEC-frozen XSUAA → OIDC → api-key order, and
 *    InvalidTokenError when every verifier rejects.
 *
 * The chained-verifier behavioral cases are ported from arc-1
 * `tests/unit/server/xsuaa.test.ts` (its `createChainedTokenVerifier` block), with
 * the api-key shape adapted from arc-1's `{key, profile}` to the package's
 * `ApiKeyEntry{key, scopes, clientId}`.
 */

import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type AuthInfo, createApiKeyVerifier, createChainedTokenVerifier, createOidcVerifier } from '../src/index.js';
import { InvalidTokenError } from '../src/internal/sdk.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ─── createApiKeyVerifier ────────────────────────────────────────────

describe('createApiKeyVerifier', () => {
  it('accepts a single-string key and returns clientId "api-key" with no scopes', async () => {
    const verify = createApiKeyVerifier('s3cret');
    const info = await verify('s3cret');
    expect(info.clientId).toBe('api-key');
    expect(info.scopes).toEqual([]);
    expect(info.token).toBe('s3cret');
    expect(info.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('rejects a wrong key (single-string form) with InvalidTokenError', async () => {
    const verify = createApiKeyVerifier('s3cret');
    await expect(verify('nope')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects everything when the single-string key is empty (no entries)', async () => {
    const verify = createApiKeyVerifier('');
    await expect(verify('')).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(verify('anything')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('attaches the entry scopes + clientId for an ApiKeyEntry[] match', async () => {
    const verify = createApiKeyVerifier([
      { key: 'viewer-key', scopes: ['read'], clientId: 'api-key:viewer' },
      { key: 'admin-key', scopes: ['read', 'write', 'admin'], clientId: 'api-key:admin' },
    ]);
    const viewer = await verify('viewer-key');
    expect(viewer.clientId).toBe('api-key:viewer');
    expect(viewer.scopes).toEqual(['read']);

    const admin = await verify('admin-key');
    expect(admin.clientId).toBe('api-key:admin');
    expect(admin.scopes).toEqual(['read', 'write', 'admin']);
  });

  it('defaults clientId to "api-key" and scopes to [] when an entry omits them', async () => {
    const verify = createApiKeyVerifier([{ key: 'bare' }]);
    const info = await verify('bare');
    expect(info.clientId).toBe('api-key');
    expect(info.scopes).toEqual([]);
  });

  it('rejects a key not in the ApiKeyEntry[]', async () => {
    const verify = createApiKeyVerifier([{ key: 'known', scopes: ['read'] }]);
    await expect(verify('unknown')).rejects.toThrow(/not a recognised key/);
  });

  it('applies the injected expandScopes hook to the matched entry scopes', async () => {
    const expandScopes = vi.fn((s: string[]) => [...new Set([...s, 'read'])]);
    const verify = createApiKeyVerifier([{ key: 'k', scopes: ['write'] }], { expandScopes });
    const info = await verify('k');
    expect(expandScopes).toHaveBeenCalledWith(['write']);
    expect(info.scopes.sort()).toEqual(['read', 'write']);
  });
});

// ─── createOidcVerifier (real jose, local JWKS via stubbed fetch) ────

describe('createOidcVerifier', () => {
  const ISSUER = 'https://issuer.example.com';
  const AUDIENCE = 'mcp-audience';
  let privateKey: CryptoKey;
  let publicJwk: JWK;

  /** Install a global `fetch` that serves the OIDC discovery doc + the JWKS. */
  function stubDiscoveryFetch(jwk: JWK = publicJwk): void {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const u = String(url);
        if (u.includes('.well-known/openid-configuration')) {
          return new Response(JSON.stringify({ jwks_uri: `${ISSUER}/jwks` }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (u.includes('/jwks')) {
          return new Response(JSON.stringify({ keys: [jwk] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        throw new Error(`unexpected fetch: ${u}`);
      }),
    );
  }

  async function mintToken(
    claims: Record<string, unknown>,
    overrides: { issuer?: string; audience?: string; alg?: string; expiresIn?: string } = {},
  ): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: overrides.alg ?? 'RS256', kid: 'test-kid' })
      .setIssuer(overrides.issuer ?? ISSUER)
      .setAudience(overrides.audience ?? AUDIENCE)
      .setExpirationTime(overrides.expiresIn ?? '1h')
      .sign(privateKey);
  }

  beforeEach(async () => {
    const kp = await generateKeyPair('RS256', { extractable: true });
    privateKey = kp.privateKey;
    publicJwk = await exportJWK(kp.publicKey);
    publicJwk.kid = 'test-kid';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';
  });

  it('verifies a valid RS256 token and extracts the `scope` claim', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'read write', azp: 'my-app', sub: 'user-1' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    const info = await verify(token);
    expect(info.clientId).toBe('my-app'); // azp preferred
    expect(info.scopes.sort()).toEqual(['read', 'write']);
    expect(info.extra).toMatchObject({ sub: 'user-1', iss: ISSUER });
  });

  it('fails closed to NO scopes by default when the token has no scope/scp claims', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ sub: 'user-2' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    const info = await verify(token);
    // Default fallbackScopes is [] — an IdP that omits scope claims grants nothing.
    expect(info.scopes).toEqual([]);
  });

  it('grants the opt-in fallbackScopes (legacy read-only) when the token has no scope/scp claims', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ sub: 'user-2b' });
    // arc-1 opts into the historical read-only fallback via fallbackScopes:['read'].
    const verify = createOidcVerifier(ISSUER, AUDIENCE, { fallbackScopes: ['read'] });
    const info = await verify(token);
    expect(info.scopes).toEqual(['read']);
  });

  it('fails closed to NO scopes when scopes are present but none are accepted (default)', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'totally-unknown other-unknown', sub: 'user-2c' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    const info = await verify(token);
    expect(info.scopes).toEqual([]);
  });

  it('grants the opt-in fallbackScopes when scopes are present but none are accepted', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'totally-unknown', sub: 'user-2d' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE, { fallbackScopes: ['read'] });
    const info = await verify(token);
    expect(info.scopes).toEqual(['read']);
  });

  it('reads Azure-AD `scp` array claims', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scp: ['read', 'admin'], sub: 'user-3' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    const info = await verify(token);
    expect(info.scopes).toContain('read');
    expect(info.scopes).toContain('admin');
  });

  it('rejects an alg:none token (unsigned) — alg pinning', async () => {
    stubDiscoveryFetch();
    // Hand-craft an unsigned JWT (header alg:none, empty signature).
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(
      JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 3600, scope: 'admin' }),
    ).toString('base64url');
    const noneToken = `${header}.${body}.`;
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    await expect(verify(noneToken)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects a token signed with an algorithm outside the allowlist', async () => {
    stubDiscoveryFetch();
    // Restrict the allowlist to ES256, then present an RS256 token → rejected.
    const token = await mintToken({ scope: 'read', sub: 'u' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE, { algorithms: ['ES256'] });
    await expect(verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects an audience mismatch', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'read', sub: 'u' }, { audience: 'some-other-audience' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    await expect(verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects an issuer mismatch', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'read', sub: 'u' }, { issuer: 'https://evil.example.com' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    await expect(verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('applies the injected expandScopes to known OIDC scopes', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'write', sub: 'u' });
    const expandScopes = vi.fn((s: string[]) => [...new Set([...s, 'read'])]);
    const verify = createOidcVerifier(ISSUER, AUDIENCE, { expandScopes });
    const info = await verify(token);
    expect(expandScopes).toHaveBeenCalledWith(['write']);
    expect(info.scopes.sort()).toEqual(['read', 'write']);
  });

  // ── M2: configurable acceptedScopes (don't hardcode arc-1's scope names) ──
  it('keeps a non-arc-1 scope (e.g. "Viewer") when acceptedScopes is set to it', async () => {
    stubDiscoveryFetch();
    const token = await mintToken({ scope: 'Viewer', sub: 'calmcp-user' });
    // With the default accepted set, "Viewer" is unknown → fail-closed (empty) fallback.
    const defaultVerify = createOidcVerifier(ISSUER, AUDIENCE);
    expect((await defaultVerify(token)).scopes).toEqual([]);
    // With acceptedScopes:['Viewer'], the consumer's scope flows through.
    const viewerVerify = createOidcVerifier(ISSUER, AUDIENCE, { acceptedScopes: ['Viewer'] });
    expect((await viewerVerify(token)).scopes).toEqual(['Viewer']);
  });

  // ── S2: don't cache OIDC discovery/JWKS failures forever ──
  it('retries discovery after a transient failure (failed promise is not memoized)', async () => {
    let attempt = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const u = String(url);
        if (u.includes('.well-known/openid-configuration')) {
          attempt += 1;
          if (attempt === 1) throw new Error('transient DNS failure'); // first discovery fails
          return new Response(JSON.stringify({ jwks_uri: `${ISSUER}/jwks` }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (u.includes('/jwks')) {
          return new Response(JSON.stringify({ keys: [publicJwk] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        throw new Error(`unexpected fetch: ${u}`);
      }),
    );

    const token = await mintToken({ scope: 'read', sub: 'u' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);

    // First attempt rejects (discovery threw).
    await expect(verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
    // Second attempt succeeds — the memoized rejected promise was cleared so the
    // retry re-runs discovery (would stay broken until restart without the fix).
    const info = await verify(token);
    expect(info.scopes).toEqual(['read']);
    expect(attempt).toBe(2);
  });

  it('rejects (and retries) when the discovery fetch returns a non-2xx status', async () => {
    let discoveryHits = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const u = String(url);
        if (u.includes('.well-known/openid-configuration')) {
          discoveryHits += 1;
          if (discoveryHits === 1) {
            return new Response('gateway down', { status: 503 }); // non-ok → must reject, not parse
          }
          return new Response(JSON.stringify({ jwks_uri: `${ISSUER}/jwks` }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (u.includes('/jwks')) {
          return new Response(JSON.stringify({ keys: [publicJwk] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        throw new Error(`unexpected fetch: ${u}`);
      }),
    );

    const token = await mintToken({ scope: 'read', sub: 'u' });
    const verify = createOidcVerifier(ISSUER, AUDIENCE);
    await expect(verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
    // The 503 was not memoized → a later request retries and succeeds.
    await expect(verify(token)).resolves.toMatchObject({ scopes: ['read'] });
  });
});

// ─── createChainedTokenVerifier (XSUAA → OIDC → api-key) ─────────────

describe('createChainedTokenVerifier', () => {
  it('returns API key auth when token matches (only apiKeys configured)', async () => {
    const verifier = createChainedTokenVerifier({
      apiKeys: [{ key: 'my-key', scopes: ['read', 'write', 'admin'], clientId: 'api-key:admin' }],
    });
    const result = await verifier('my-key');
    expect(result.clientId).toBe('api-key:admin');
    expect(result.scopes).toContain('admin');
    expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('throws when API key does not match and no other verifiers', async () => {
    const verifier = createChainedTokenVerifier({ apiKeys: [{ key: 'my-key', scopes: ['read'] }] });
    await expect(verifier('wrong-key')).rejects.toThrow('Token validation failed');
  });

  it('tries the XSUAA verifier first', async () => {
    const xsuaaVerifier = vi.fn().mockResolvedValue({
      token: 'xsuaa-token',
      clientId: 'xsuaa-client',
      scopes: ['read'],
      extra: {},
    } satisfies AuthInfo);

    const verifier = createChainedTokenVerifier({ apiKeys: [{ key: 'my-key', scopes: ['read'] }] }, xsuaaVerifier);
    const result = await verifier('xsuaa-token');
    expect(result.clientId).toBe('xsuaa-client');
    expect(xsuaaVerifier).toHaveBeenCalledWith('xsuaa-token');
  });

  it('falls through to OIDC when XSUAA fails', async () => {
    const xsuaaVerifier = vi.fn().mockRejectedValue(new Error('Invalid token'));
    const oidcVerifier = vi.fn().mockResolvedValue({
      token: 'oidc-token',
      clientId: 'oidc-client',
      scopes: ['read', 'write', 'admin'],
      extra: {},
    } satisfies AuthInfo);

    const verifier = createChainedTokenVerifier({}, xsuaaVerifier, oidcVerifier);
    const result = await verifier('oidc-token');
    expect(result.clientId).toBe('oidc-client');
    expect(xsuaaVerifier).toHaveBeenCalled();
    expect(oidcVerifier).toHaveBeenCalled();
  });

  it('falls through to API key when both XSUAA and OIDC fail', async () => {
    const xsuaaVerifier = vi.fn().mockRejectedValue(new Error('XSUAA fail'));
    const oidcVerifier = vi.fn().mockRejectedValue(new Error('OIDC fail'));

    const verifier = createChainedTokenVerifier(
      { apiKeys: [{ key: 'my-key', scopes: ['admin'], clientId: 'api-key:admin' }] },
      xsuaaVerifier,
      oidcVerifier,
    );
    const result = await verifier('my-key');
    expect(result.clientId).toBe('api-key:admin');
  });

  it('throws InvalidTokenError when all verifiers fail and no API key', async () => {
    const xsuaaVerifier = vi.fn().mockRejectedValue(new Error('XSUAA fail'));
    const oidcVerifier = vi.fn().mockRejectedValue(new Error('OIDC fail'));

    const verifier = createChainedTokenVerifier({}, xsuaaVerifier, oidcVerifier);
    await expect(verifier('invalid-token')).rejects.toThrow('Token validation failed');
    await expect(verifier('invalid-token')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('works (throws) with no verifiers configured at all', async () => {
    const verifier = createChainedTokenVerifier({});
    await expect(verifier('any-token')).rejects.toThrow('Token validation failed');
    await expect(verifier('any-token')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('honors the single-string apiKeys form in the chain', async () => {
    const verifier = createChainedTokenVerifier({ apiKeys: 'solo-key' });
    const result = await verifier('solo-key');
    expect(result.clientId).toBe('api-key');
    await expect(verifier('nope')).rejects.toThrow('Token validation failed');
  });

  it('returns the XSUAA sub-verifier scopes verbatim (chain does NOT re-expand — S1)', async () => {
    // Contract after S1: the chain applies expandScopes EXACTLY once, inside the
    // sub-verifiers. A real XSUAA verifier built with `expandScopes` would already
    // carry the expansion; the chain must NOT expand again. Here the sub-verifier
    // mock returns its scopes pre-expanded and the chain returns them unchanged.
    const xsuaaVerifier = vi.fn().mockResolvedValue({
      token: 't',
      clientId: 'xsuaa-client',
      scopes: ['read', 'write'], // sub-verifier already expanded write→read+write
      extra: {},
    } satisfies AuthInfo);
    // A non-idempotent expander is injected to prove the chain does NOT call it.
    const expandScopes = vi.fn((s: string[]) => [...s, 'CHAIN-REAPPLIED']);
    const verifier = createChainedTokenVerifier({}, xsuaaVerifier, undefined, { expandScopes });
    const result = await verifier('t');
    expect(result.scopes.sort()).toEqual(['read', 'write']);
    expect(result.scopes).not.toContain('CHAIN-REAPPLIED');
  });

  // ── S1: expandScopes is applied EXACTLY once (sub-verifier only, not the chain) ──
  it('applies a NON-idempotent expandScopes exactly once via the api-key path', async () => {
    // This expander is deliberately non-idempotent: each call appends a fresh
    // marker. If the chain re-applied it on top of the sub-verifier, the marker
    // would appear twice.
    let calls = 0;
    const expandScopes = vi.fn((s: string[]) => {
      calls += 1;
      return [...s, `marker-${calls}`];
    });
    const verifier = createChainedTokenVerifier({ apiKeys: [{ key: 'k', scopes: ['read'] }] }, undefined, undefined, {
      expandScopes,
    });
    const result = await verifier('k');
    expect(expandScopes).toHaveBeenCalledTimes(1);
    expect(result.scopes).toEqual(['read', 'marker-1']); // exactly one marker
  });

  it('does NOT re-apply expandScopes on top of an XSUAA sub-verifier that already expanded', async () => {
    // The sub-verifier returns scopes that already carry the expansion marker. The
    // chain must return them verbatim — re-applying a non-idempotent expander would
    // double the marker.
    const expandScopes = vi.fn((s: string[]) => [...s, 'EXPANDED']);
    const xsuaaVerifier = vi.fn(async (token: string) => ({
      token,
      clientId: 'xsuaa-client',
      scopes: expandScopes(['write']), // sub-verifier applied it once
      extra: {},
    }));
    const verifier = createChainedTokenVerifier({}, xsuaaVerifier, undefined, { expandScopes });
    const result = await verifier('t');
    // 'EXPANDED' appears exactly once (sub-verifier), not twice (no chain re-apply).
    expect(result.scopes).toEqual(['write', 'EXPANDED']);
    expect(result.scopes.filter((s) => s === 'EXPANDED')).toHaveLength(1);
    expect(expandScopes).toHaveBeenCalledTimes(1);
  });

  // ── M1 / S3: never log token material; log a non-reversible fingerprint only ──
  it('does not log raw or partial token bytes (fingerprint + length only)', async () => {
    const logger = makeCapturingLogger();
    const SECRET = 'super-secret-api-key-value-1234567890';
    const verifier = createChainedTokenVerifier(
      { apiKeys: [{ key: 'other', scopes: ['read'] }] },
      undefined,
      undefined,
      {
        logger,
      },
    );
    // Token does not match → exercises both the "starting" and "all methods failed" logs.
    await expect(verifier(SECRET)).rejects.toBeInstanceOf(InvalidTokenError);

    const allEntries = [...logger.debugs, ...logger.infos, ...logger.warns, ...logger.errors];
    // No log message or data value may contain the secret or any >=8-char slice of it.
    const secretSlice = SECRET.slice(0, 12);
    for (const entry of allEntries) {
      const serialized = `${entry.message} ${JSON.stringify(entry.data ?? {})}`;
      expect(serialized).not.toContain(SECRET);
      expect(serialized).not.toContain(secretSlice);
    }
    // The starting log carries a fingerprint + length, never the token.
    const start = logger.debugs.find((e) => /starting/.test(e.message));
    expect(start?.data).toMatchObject({ tokenLen: SECRET.length });
    const tokenFp = start?.data?.tokenFp;
    expect(typeof tokenFp).toBe('string');
    expect(tokenFp).toHaveLength(8);
    expect(start?.data).not.toHaveProperty('tokenPreview');
  });

  it('does not log user PII (email/userName) from an XSUAA success', async () => {
    const logger = makeCapturingLogger();
    const xsuaaVerifier = vi.fn(async (token: string) => ({
      token,
      clientId: 'xsuaa-client',
      scopes: ['read'],
      extra: { email: 'alice@example.com', userName: 'ALICE' },
    }));
    const verifier = createChainedTokenVerifier({}, xsuaaVerifier, undefined, { logger });
    await verifier('jwt-token');

    const allEntries = [...logger.debugs, ...logger.infos, ...logger.warns, ...logger.errors];
    for (const entry of allEntries) {
      const serialized = `${entry.message} ${JSON.stringify(entry.data ?? {})}`;
      expect(serialized).not.toContain('alice@example.com');
      expect(serialized).not.toContain('ALICE');
    }
    // The success log reports presence as a boolean, not the value.
    const ok = logger.debugs.find((e) => /XSUAA succeeded/.test(e.message));
    expect(ok?.data).toMatchObject({ hasUser: true });
  });
});

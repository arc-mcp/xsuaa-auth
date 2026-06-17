/**
 * Tests for the stateless OAuth DCR client store.
 *
 * Ported from arc-1 `tests/unit/server/stateless-client-store.test.ts`. Adaptations
 * for the package:
 *   - default client_id prefix is `mcp-` (not `arc1-`),
 *   - the logger is INJECTED — audit-event assertions read the capturing logger's
 *     `audit` array instead of installing a sink on a module-level logger,
 *   - the `clientIdPrefix` / `kdfLabel` options are exercised explicitly,
 *   - the xs-security.json drift-guard is dropped (the package vendors the patterns
 *     as exported defaults; there is no xs-security.json in the package — SPEC §6).
 */

import { describe, expect, it } from 'vitest';
import { StatelessDcrClientStore } from '../src/index.js';
import { type CapturingLogger, makeCapturingLogger } from './helpers/test-logger.js';

const SIGNING = 'test-signing-secret';
const XSUAA_ID = 'sb-arc1!t599384';
const XSUAA_SECRET = 'xsuaa-default-secret';

function makeStore(
  opts: {
    now?: () => number;
    ttlSeconds?: number;
    logger?: CapturingLogger;
    clientIdPrefix?: string;
    kdfLabel?: string;
  } = {},
) {
  return new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, SIGNING, opts);
}

describe('StatelessDcrClientStore', () => {
  it('requires a non-empty signing secret', () => {
    expect(() => new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, '')).toThrow(/non-empty/);
  });

  it('returns the pre-registered XSUAA default client unchanged', async () => {
    const store = makeStore();
    const client = await store.getClient(XSUAA_ID);
    expect(client?.client_id).toBe(XSUAA_ID);
    expect(client?.client_secret).toBe(XSUAA_SECRET);
    expect(client?.redirect_uris).toContain('https://claude.ai/api/mcp/auth_callback');
  });

  it('warns (via the injected logger) when signingSecret is shorter than 16 bytes', () => {
    const logger = makeCapturingLogger();
    new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, 'short', { logger }); // 5 bytes
    const warn = logger.warns.find((w) => /shorter than 16 bytes/.test(w.message));
    expect(warn).toBeDefined();
    expect(warn?.data).toMatchObject({ bytes: 5 });
  });

  it('does not warn when signingSecret is exactly 16 bytes or longer', () => {
    const logger = makeCapturingLogger();
    new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, 'a'.repeat(16), { logger });
    expect(logger.has('warn', /shorter than 16 bytes/)).toBe(false);
  });

  it('measures byte length, not char length, for multi-byte UTF-8 secrets', () => {
    // 'ü' is 2 bytes in UTF-8. 'üüüü' (4 chars) = 8 bytes → warn.
    const l1 = makeCapturingLogger();
    new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, 'üüüü', { logger: l1 });
    expect(l1.warns.find((w) => /shorter than 16 bytes/.test(w.message))?.data).toMatchObject({ bytes: 8 });

    // 'üüüüüüüü' (8 chars × 2 bytes) = 16 bytes → no warn.
    const l2 = makeCapturingLogger();
    new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, 'üüüüüüüü', { logger: l2 });
    expect(l2.has('warn', /shorter than 16 bytes/)).toBe(false);
  });

  it('round-trips a registered client through register → getClient', async () => {
    const store = makeStore();
    const registered = await store.registerClient({
      redirect_uris: ['https://example.com/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
      client_name: 'test-client',
    });

    expect(registered.client_id.startsWith('mcp-')).toBe(true);
    expect(registered.client_secret).toBeTruthy();
    expect(registered.client_id_issued_at).toBeTypeOf('number');

    const fetched = await store.getClient(registered.client_id);
    expect(fetched).toBeDefined();
    expect(fetched?.client_id).toBe(registered.client_id);
    expect(fetched?.client_secret).toBe(registered.client_secret);
    expect(fetched?.redirect_uris).toEqual(['https://example.com/callback']);
    expect(fetched?.client_name).toBe('test-client');
  });

  it('survives a process-style restart: a fresh store with the same secret resolves prior IDs', async () => {
    const first = makeStore();
    const registered = await first.registerClient({
      redirect_uris: ['https://example.com/cb'],
      client_name: 'persistent-by-design',
    });

    const second = makeStore(); // simulate a CF push: brand new instance, same signing secret
    const fetched = await second.getClient(registered.client_id);
    expect(fetched?.client_id).toBe(registered.client_id);
    expect(fetched?.client_secret).toBe(registered.client_secret);
  });

  it('rejects a client_id with a tampered payload', async () => {
    const store = makeStore();
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    const body = registered.client_id.slice('mcp-'.length);
    const dotIdx = body.lastIndexOf('.');
    const tamperedPayload = `${body[0] === 'A' ? 'B' : 'A'}${body.slice(1, dotIdx)}${body.slice(dotIdx)}`;
    const tampered = `mcp-${tamperedPayload}`;

    expect(await store.getClient(tampered)).toBeUndefined();
  });

  it('rejects a client_id signed with a different secret', async () => {
    const issuer = makeStore();
    const registered = await issuer.registerClient({ redirect_uris: ['https://example.com/cb'] });

    const otherStore = new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, 'a-different-secret');
    expect(await otherStore.getClient(registered.client_id)).toBeUndefined();
  });

  it('rejects a client_id signed with a different kdfLabel even when the secret matches', async () => {
    const issuer = makeStore({ kdfLabel: 'mcp-dcr/v1' });
    const registered = await issuer.registerClient({ redirect_uris: ['https://example.com/cb'] });
    const rotated = new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, SIGNING, { kdfLabel: 'mcp-dcr/v2' });
    expect(await rotated.getClient(registered.client_id)).toBeUndefined();
  });

  it('returns undefined for malformed or unprefixed client IDs', async () => {
    const store = makeStore();
    expect(await store.getClient('not-prefixed')).toBeUndefined();
    expect(await store.getClient('mcp-')).toBeUndefined();
    expect(await store.getClient('mcp-no-dot-here')).toBeUndefined();
    expect(await store.getClient('mcp-payload.invalid-sig')).toBeUndefined();
  });

  it('expires clients past TTL', async () => {
    let nowMs = 1_700_000_000_000;
    const store = makeStore({ now: () => nowMs, ttlSeconds: 60 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    expect(await store.getClient(registered.client_id)).toBeDefined();
    nowMs += 61_000;
    expect(await store.getClient(registered.client_id)).toBeUndefined();
  });

  it('produces deterministic client_secret for a given client_id', async () => {
    const store = makeStore();
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    const a = await store.getClient(registered.client_id);
    const b = await store.getClient(registered.client_id);
    expect(a?.client_secret).toBe(registered.client_secret);
    expect(b?.client_secret).toBe(registered.client_secret);
  });

  it('encodes and rejects redirect URIs per the allowlist policy', async () => {
    const store = makeStore();
    await expect(store.registerClient({ redirect_uris: ['javascript:alert(1)'] })).rejects.toThrow(/javascript:/);
    await expect(store.registerClient({ redirect_uris: ['http://evil.example.com/cb'] })).rejects.toThrow(
      /http:\/\/ is only allowed/,
    );

    await expect(store.registerClient({ redirect_uris: ['http://localhost:1234/cb'] })).resolves.toBeDefined();
    await expect(store.registerClient({ redirect_uris: ['cursor://cb'] })).resolves.toBeDefined();
  });

  it('keeps client_id length under a reasonable URL budget', async () => {
    const store = makeStore();
    const registered = await store.registerClient({
      redirect_uris: [
        'https://claude.ai/api/mcp/auth_callback',
        'cursor://anysphere.cursor-retrieval/oauth/callback',
        'http://localhost:6274/oauth/callback',
      ],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
      client_name: 'Claude Desktop',
    });
    expect(registered.client_id.length).toBeLessThan(800);
  });

  it('honors a custom clientIdPrefix', async () => {
    const store = makeStore({ clientIdPrefix: 'calmcp-' });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    expect(registered.client_id.startsWith('calmcp-')).toBe(true);
    // And it round-trips under the same prefix.
    expect((await store.getClient(registered.client_id))?.client_id).toBe(registered.client_id);
    // A default-prefix store cannot resolve a custom-prefix id.
    expect(await makeStore().getClient(registered.client_id)).toBeUndefined();
  });

  it('mutates redirect_uris on the XSUAA default client via ensureRedirectUri (allowlisted URI)', async () => {
    const store = makeStore();
    store.ensureRedirectUri(XSUAA_ID, 'https://abc.hana.ondemand.com/login/callback');
    const c = await store.getClient(XSUAA_ID);
    expect(c?.redirect_uris).toContain('https://abc.hana.ondemand.com/login/callback');
  });

  it('does NOT register a non-allowlisted redirect_uri on the XSUAA default client', async () => {
    const store = makeStore();
    store.ensureRedirectUri(XSUAA_ID, 'https://attacker.example/cb');
    const c = await store.getClient(XSUAA_ID);
    expect(c?.redirect_uris).not.toContain('https://attacker.example/cb');
  });

  it('is a no-op for ensureRedirectUri on DCR clients (stateless)', async () => {
    const store = makeStore();
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    store.ensureRedirectUri(registered.client_id, 'https://other.example.com/cb');
    const fetched = await store.getClient(registered.client_id);
    expect(fetched?.redirect_uris).toEqual(['https://example.com/cb']);
  });
});

describe('StatelessDcrClientStore.checkRedirectUri (fail-closed)', () => {
  it("default client → 'ok' for an allowlisted URI, 'unregistered' otherwise (stateless, ignores in-memory list)", async () => {
    const store = makeStore();
    expect(await store.checkRedirectUri(XSUAA_ID, 'https://claude.ai/api/mcp/auth_callback')).toBe('ok');
    expect(await store.checkRedirectUri(XSUAA_ID, 'https://global.consent.azure-apim.net/redirect/x')).toBe('ok');
    expect(await store.checkRedirectUri(XSUAA_ID, 'https://attacker.example/cb')).toBe('unregistered');
  });

  it("DCR client → 'ok' only for a redirect_uri baked into its signed client_id", async () => {
    const store = makeStore();
    const reg = await store.registerClient({ redirect_uris: ['https://app.example.com/cb'] });
    expect(await store.checkRedirectUri(reg.client_id, 'https://app.example.com/cb')).toBe('ok');
    expect(await store.checkRedirectUri(reg.client_id, 'https://attacker.example/cb')).toBe('unregistered');
  });

  it("returns 'unknown_client' for an unrecognised/forged client_id", async () => {
    const store = makeStore();
    expect(await store.checkRedirectUri('mcp-bogus.AAAAAAAAAAAAAAAAAAAAAA', 'https://app.example.com/cb')).toBe(
      'unknown_client',
    );
  });
});

describe('StatelessDcrClientStore default TTL', () => {
  it('defaults to 30 days when ttlSeconds is not provided', async () => {
    let nowMs = 1_700_000_000_000;
    const store = makeStore({ now: () => nowMs });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    nowMs += (30 * 24 * 60 * 60 - 1) * 1000; // just under 30 days — still valid
    expect(await store.getClient(registered.client_id)).toBeDefined();

    nowMs += 2_000; // 1 second past 30 days — expired
    expect(await store.getClient(registered.client_id)).toBeUndefined();
  });

  it('explicit ttlSeconds=0 disables expiration entirely', async () => {
    let nowMs = 1_700_000_000_000;
    const store = makeStore({ now: () => nowMs, ttlSeconds: 0 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    nowMs += 10 * 365 * 24 * 60 * 60 * 1000; // 10 years later — still valid (no TTL)
    expect(await store.getClient(registered.client_id)).toBeDefined();
  });

  it('negative ttlSeconds also disables expiration', async () => {
    let nowMs = 1_700_000_000_000;
    const store = makeStore({ now: () => nowMs, ttlSeconds: -1 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    nowMs += 365 * 24 * 60 * 60 * 1000;
    expect(await store.getClient(registered.client_id)).toBeDefined();
  });
});

describe('StatelessDcrClientStore client_secret_expires_at (RFC 7591 §3.2.1)', () => {
  it('emits client_secret_expires_at = iat + ttlSeconds when TTL is positive', async () => {
    const store = makeStore({ now: () => 1_700_000_000_000, ttlSeconds: 3600 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    expect(registered.client_secret_expires_at).toBe(1_700_000_000 + 3600);
  });

  it('emits client_secret_expires_at = 0 when ttlSeconds=0 ("will not expire")', async () => {
    const store = makeStore({ now: () => 1_700_000_000_000, ttlSeconds: 0 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    expect(registered.client_secret_expires_at).toBe(0);
  });

  it('emits client_secret_expires_at = 0 when ttlSeconds is negative', async () => {
    const store = makeStore({ now: () => 1_700_000_000_000, ttlSeconds: -1 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    expect(registered.client_secret_expires_at).toBe(0);
  });

  it('emits client_secret_expires_at with the default 30-day TTL when ttlSeconds is unset', async () => {
    const store = makeStore({ now: () => 1_700_000_000_000 });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });
    expect(registered.client_secret_expires_at).toBe(1_700_000_000 + 30 * 24 * 60 * 60);
  });
});

describe('StatelessDcrClientStore audit events (via injected logger.emitAudit)', () => {
  it('emits oauth_client_registered on /register with id length and uri count', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });

    const registered = await store.registerClient({
      redirect_uris: ['https://example.com/cb', 'cursor://x/cb'],
      client_name: 'audit-test',
    });

    const evt = logger.audit.find(
      (e) => e.event === 'oauth_client_registered' && e.registeredClientId === registered.client_id,
    );
    expect(evt).toBeDefined();
    expect(evt?.redirectUriCount).toBe(2);
    expect(evt?.clientName).toBe('audit-test');
    expect(evt?.idBytes).toBe(registered.client_id.length);
    expect(evt?.level).toBe('info');
  });

  it('emits oauth_client_lookup_failed reason="bad_signature" for tampered IDs', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    const tampered = `mcp-${registered.client_id.slice('mcp-'.length).replace(/^./, 'X')}`;
    expect(await store.getClient(tampered)).toBeUndefined();

    const fail = logger.audit.find(
      (e) => e.event === 'oauth_client_lookup_failed' && e.registeredClientId === tampered,
    );
    expect(fail?.reason).toBe('bad_signature');
    expect(fail?.level).toBe('warn');
  });

  it('emits oauth_client_lookup_failed reason="malformed" for missing-signature IDs', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    expect(await store.getClient('mcp-no-dot-here')).toBeUndefined();
    const fail = logger.audit.find(
      (e) => e.event === 'oauth_client_lookup_failed' && e.registeredClientId === 'mcp-no-dot-here',
    );
    expect(fail?.reason).toBe('malformed');
  });

  it('emits oauth_client_lookup_failed reason="unknown_prefix" for non-mcp IDs', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    expect(await store.getClient('foreign-id')).toBeUndefined();
    const fail = logger.audit.find(
      (e) => e.event === 'oauth_client_lookup_failed' && e.registeredClientId === 'foreign-id',
    );
    expect(fail?.reason).toBe('unknown_prefix');
  });

  it('emits oauth_client_lookup_failed reason="expired" at level "info" past TTL', async () => {
    const logger = makeCapturingLogger();
    let nowMs = 1_700_000_000_000;
    const store = makeStore({ now: () => nowMs, ttlSeconds: 60, logger });
    const registered = await store.registerClient({ redirect_uris: ['https://example.com/cb'] });

    nowMs += 61_000;
    expect(await store.getClient(registered.client_id)).toBeUndefined();

    const fail = logger.audit.find(
      (e) => e.event === 'oauth_client_lookup_failed' && e.registeredClientId === registered.client_id,
    );
    expect(fail?.reason).toBe('expired');
    expect(fail?.level).toBe('info'); // TTL eviction is normal-ish, not adversarial
  });

  it('emits oauth_redirect_uri_registered when XSUAA default redirect_uris is widened', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    store.ensureRedirectUri(XSUAA_ID, 'https://global.consent.azure-apim.net/redirect/contoso');

    const evt = logger.audit.find((e) => e.event === 'oauth_redirect_uri_registered');
    expect(evt).toBeDefined();
    expect(evt?.redirectUri).toBe('https://global.consent.azure-apim.net/redirect/contoso');
    expect(evt?.registeredClientId).toBe(XSUAA_ID);
  });

  it('emits oauth_redirect_uri_rejected (warn) when a non-allowlisted URI is refused', async () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    store.ensureRedirectUri(XSUAA_ID, 'https://attacker.example/cb');

    const evt = logger.audit.find((e) => e.event === 'oauth_redirect_uri_rejected');
    expect(evt).toBeDefined();
    expect(evt?.redirectUri).toBe('https://attacker.example/cb');
    expect(evt?.registeredClientId).toBe(XSUAA_ID);
    expect(evt?.level).toBe('warn');
    expect(logger.audit.find((e) => e.event === 'oauth_redirect_uri_registered')).toBeUndefined();
  });

  it('does not emit oauth_redirect_uri_registered when ensureRedirectUri is a no-op (DCR client)', async () => {
    const store0 = makeStore();
    const registered = await store0.registerClient({ redirect_uris: ['https://example.com/cb'] });

    const logger = makeCapturingLogger();
    const store = new StatelessDcrClientStore(XSUAA_ID, XSUAA_SECRET, SIGNING, { logger });
    store.ensureRedirectUri(registered.client_id, 'https://other.example.com/cb');
    expect(logger.audit.find((e) => e.event === 'oauth_redirect_uri_registered')).toBeUndefined();
  });

  it('does not emit oauth_redirect_uri_registered when the URI is already in the list', () => {
    const logger = makeCapturingLogger();
    const store = makeStore({ logger });
    store.ensureRedirectUri(XSUAA_ID, 'https://claude.ai/api/mcp/auth_callback');
    expect(logger.audit.find((e) => e.event === 'oauth_redirect_uri_registered')).toBeUndefined();
  });
});

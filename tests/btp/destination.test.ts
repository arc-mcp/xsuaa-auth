/**
 * `./btp` — per-user destination lookup (principal propagation).
 *
 * Ported from arc-1 `tests/unit/adt/btp-pp.test.ts`. Adaptations for the package:
 *   - imported from `@arc-mcp/xsuaa-auth/btp` (here via `../../src/btp.js`),
 *   - adds the package's JWT-shape guard test (a non-JWT — e.g. an api-key — throws),
 *   - `@sap-cloud-sdk/connectivity`'s `getDestination` is mocked; the jwt-bearer
 *     "Option 2" fallback path mocks the global `fetch`.
 *
 * A valid SDK happy-path needs the userJwt to be a 3-segment string (the guard);
 * the segments need not be cryptographically valid — the SDK is mocked.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetDestination = vi.fn();
vi.mock('@sap-cloud-sdk/connectivity', () => ({
  getDestination: mockGetDestination,
}));

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Import AFTER mocking.
const { lookupDestinationWithUserToken, resolveBTPDestination } = await import('../../src/btp.js');

import type { BTPConfig } from '../../src/btp.js';

/** A syntactically-valid (3-segment) but unsigned JWT for the SDK happy paths. */
const USER_JWT = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(
  JSON.stringify({ sub: 'u', email: 'u@example.com', scope: ['read'] }),
).toString('base64url')}.`;

const TEST_BTP_CONFIG: BTPConfig = {
  xsuaaUrl: 'https://test.auth.example.com',
  xsuaaClientId: 'xsuaa-client',
  xsuaaSecret: 'xsuaa-secret',
  destinationUrl: 'https://destination.example.com',
  destinationClientId: 'dest-client',
  destinationSecret: 'dest-secret',
  destinationTokenUrl: 'https://test.auth.example.com/oauth/token',
  connectivityProxyHost: 'proxy.internal',
  connectivityProxyPort: '20003',
  connectivityClientId: 'conn-client',
  connectivitySecret: 'conn-secret',
  connectivityTokenUrl: 'https://test.auth.example.com/oauth/token',
};

describe('lookupDestinationWithUserToken', () => {
  beforeEach(() => {
    mockGetDestination.mockReset();
    mockFetch.mockReset();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Package addition: JWT-shape guard (anti-footgun) ──
  it('throws on a non-JWT user token (e.g. an api-key string), without calling the SDK', async () => {
    await expect(lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_TRIAL', 'an-api-key-not-a-jwt')).rejects.toThrow(
      /requires a JWT bearer token/,
    );
    expect(mockGetDestination).not.toHaveBeenCalled();
  });

  it('throws on a 2-segment token (still not a JWT)', async () => {
    await expect(lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_TRIAL', 'aaa.bbb')).rejects.toThrow(
      /requires a JWT bearer token/,
    );
  });

  // ── Shape 1: PrincipalPropagation → SAP-Connectivity-Authentication ──
  it('resolves via SDK and returns PrincipalPropagation auth tokens', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_TRIAL',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'PrincipalPropagationToken',
          value: 'saml-assertion-encoded',
          error: null,
          http_header: { key: 'SAP-Connectivity-Authentication', value: 'Bearer saml-assertion-encoded' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_TRIAL', USER_JWT);

    // The PP (user-JWT) lookup MUST pin per-user cache isolation so one user's
    // propagated identity can never be served from another user's cache entry.
    expect(mockGetDestination).toHaveBeenCalledWith({
      destinationName: 'SAP_TRIAL',
      jwt: USER_JWT,
      useCache: true,
      isolationStrategy: 'tenant-user',
    });
    expect(result.destination.Name).toBe('SAP_TRIAL');
    expect(result.destination.Authentication).toBe('PrincipalPropagation');
    expect(result.authTokens.sapConnectivityAuth).toBe('Bearer saml-assertion-encoded');
  });

  // ── Security: per-user cache isolation on the PP lookup ──
  it('pins isolationStrategy "tenant-user" on the per-user (PP) getDestination call', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_TRIAL',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'PrincipalPropagationToken',
          value: 'saml',
          error: null,
          http_header: { key: 'SAP-Connectivity-Authentication', value: 'Bearer saml' },
        },
      ],
    });

    await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_TRIAL', USER_JWT);

    // Assert the cache-isolation option specifically (not just the whole arg shape),
    // so a regression that drops it — silently widening the cache key to tenant-only
    // and risking a cross-user identity leak — fails this test.
    const callArg = mockGetDestination.mock.calls[0][0] as { useCache?: boolean; isolationStrategy?: string };
    expect(callArg.isolationStrategy).toBe('tenant-user');
    expect(callArg.useCache).toBe(true);
  });

  // ── Shape 2: OAuth2SAMLBearerAssertion → Bearer token (top-level value) ──
  it('returns the Bearer token for OAuth2SAMLBearerAssertion destinations', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'S4_CLOUD',
      url: 'https://s4.cloud.sap',
      authentication: 'OAuth2SAMLBearerAssertion',
      proxyType: 'Internet',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'Bearer',
          value: 'oauth-access-token-for-user',
          error: null,
          http_header: { key: 'Authorization', value: 'Bearer oauth-access-token-for-user' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'S4_CLOUD', USER_JWT);
    expect(result.authTokens.bearerToken).toBe('oauth-access-token-for-user');
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
  });

  it('returns Bearer token for OAuth2UserTokenExchange (SDK lowercases type to "bearer", #301)', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'ABAP_FREE_PP',
      url: 'https://abc.abap.us10.hana.ondemand.com',
      authentication: 'OAuth2UserTokenExchange',
      proxyType: 'Internet',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'bearer',
          value: 'abap-user-context-token',
          error: null,
          http_header: { key: 'Authorization', value: 'Bearer abap-user-context-token' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'ABAP_FREE_PP', USER_JWT);
    expect(result.authTokens.bearerToken).toBe('abap-user-context-token');
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
  });

  it('falls back to the Authorization http_header when a bearer entry has no top-level value', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'ABAP_FREE_PP',
      url: 'https://abc.abap.us10.hana.ondemand.com',
      authentication: 'OAuth2UserTokenExchange',
      proxyType: 'Internet',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'bearer',
          value: '',
          error: null,
          http_header: { key: 'Authorization', value: 'Bearer header-only-token' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'ABAP_FREE_PP', USER_JWT);
    expect(result.authTokens.bearerToken).toBe('header-only-token');
  });

  it('throws on an auth-token error from the Destination Service', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_TRIAL',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'PrincipalPropagationToken',
          value: '',
          error: 'User token validation failed: token expired',
          http_header: { key: 'SAP-Connectivity-Authentication', value: '' },
        },
      ],
    });

    await expect(lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_TRIAL', USER_JWT)).rejects.toThrow(
      'auth token error',
    );
  });

  it('throws when the SDK returns null (destination not found)', async () => {
    mockGetDestination.mockResolvedValueOnce(null);
    await expect(lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'NONEXISTENT', USER_JWT)).rejects.toThrow(
      "no destination for 'NONEXISTENT'",
    );
  });

  // ── Shape 3: no authTokens (BasicAuthentication) → empty tokens ──
  it('handles destinations with no authTokens array', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_BASIC',
      url: 'http://sap:50000',
      authentication: 'BasicAuthentication',
      proxyType: 'OnPremise',
      username: 'DEVELOPER',
      password: 'pass123',
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_BASIC', USER_JWT);
    expect(result.destination.Authentication).toBe('BasicAuthentication');
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
    expect(result.authTokens.bearerToken).toBeUndefined();
  });

  it('maps cloudConnectorLocationId from the SDK destination', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_PP_LOC2',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      cloudConnectorLocationId: 'LOC2',
      authTokens: [
        {
          type: 'PrincipalPropagationToken',
          value: 'saml-assertion',
          error: null,
          http_header: { key: 'SAP-Connectivity-Authentication', value: 'Bearer saml-assertion' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_PP_LOC2', USER_JWT);
    expect(result.destination.CloudConnectorLocationId).toBe('LOC2');
  });

  // ── Option-2 jwt-bearer fallback ──
  it('falls back to jwt-bearer exchange (Option 2) when the SDK returns no auth tokens for a PP destination', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_PP',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: null,
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'exchanged-token', expires_in: 3600 }),
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_PP', USER_JWT);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [fetchUrl, fetchOpts] = mockFetch.mock.calls[0] as [string, { body: string }];
    expect(fetchUrl).toBe(TEST_BTP_CONFIG.connectivityTokenUrl);
    expect(fetchOpts.body).toContain('grant_type=urn');
    expect(fetchOpts.body).toContain(`assertion=${encodeURIComponent(USER_JWT)}`);

    // Option 2: the ORIGINAL user JWT is used as SAP-Connectivity-Authentication.
    expect(result.authTokens.sapConnectivityAuth).toBe(`Bearer ${USER_JWT}`);
  });

  it('does NOT set sapConnectivityAuth when the jwt-bearer exchange itself fails (logs, returns empty)', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_PP',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: null,
    });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 401, text: async () => 'unauthorized' });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_PP', USER_JWT);
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
  });

  it('does NOT set sapConnectivityAuth when the jwt-bearer exchange throws a network error', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'SAP_PP',
      url: 'http://sap:50000',
      authentication: 'PrincipalPropagation',
      proxyType: 'OnPremise',
      username: '',
      password: '',
      authTokens: null,
    });
    mockFetch.mockRejectedValueOnce(new Error('network down'));

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'SAP_PP', USER_JWT);
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
  });
});

// ─── resolveBTPDestination (startup top-level resolver) ──────────────

describe('resolveBTPDestination', () => {
  beforeEach(() => {
    mockGetDestination.mockReset();
    mockFetch.mockReset();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  function jsonOk(body: unknown): {
    ok: true;
    status: number;
    json: () => Promise<unknown>;
    text: () => Promise<string>;
  } {
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
  }

  it('throws when VCAP_SERVICES is absent (not on BTP CF)', async () => {
    vi.stubEnv('VCAP_SERVICES', undefined);
    await expect(resolveBTPDestination('SAP_TRIAL')).rejects.toThrow(/VCAP_SERVICES is not available/);
  });

  it('resolves an OnPremise BasicAuth destination + builds a connectivity proxy', async () => {
    vi.stubEnv(
      'VCAP_SERVICES',
      JSON.stringify({
        xsuaa: [{ name: 'x', credentials: { url: 'https://xsuaa.example.com', clientid: 'xc', clientsecret: 'xs' } }],
        destination: [
          {
            name: 'd',
            credentials: {
              uri: 'https://dest.example.com',
              url: 'https://dest-auth.example.com',
              clientid: 'dc',
              clientsecret: 'ds',
            },
          },
        ],
        connectivity: [
          {
            name: 'c',
            credentials: {
              onpremise_proxy_host: 'proxy.internal',
              onpremise_proxy_http_port: '20003',
              clientid: 'cc',
              clientsecret: 'cs',
              token_service_url: 'https://conn-auth.example.com',
            },
          },
        ],
      }),
    );

    // 1: destination-service token, 2: destination config.
    mockFetch.mockResolvedValueOnce(jsonOk({ access_token: 'dest-token', expires_in: 3600 })).mockResolvedValueOnce(
      jsonOk({
        destinationConfiguration: {
          Name: 'SAP_A4H',
          URL: 'https://sap.example.com',
          Authentication: 'BasicAuthentication',
          ProxyType: 'OnPremise',
          User: 'sap-user',
          Password: 'sap-pass',
          'sap-client': '100',
          CloudConnectorLocationId: 'EU10',
        },
      }),
    );

    const resolved = await resolveBTPDestination('SAP_A4H');
    expect(resolved.url).toBe('https://sap.example.com');
    expect(resolved.username).toBe('sap-user');
    expect(resolved.password).toBe('sap-pass');
    expect(resolved.client).toBe('100');
    expect(resolved.proxy).not.toBeNull();
    expect(resolved.proxy?.host).toBe('proxy.internal');
    expect(resolved.proxy?.locationId).toBe('EU10');
  });

  it('returns a null proxy for an Internet (non-OnPremise) destination, defaulting client to 100', async () => {
    vi.stubEnv(
      'VCAP_SERVICES',
      JSON.stringify({
        destination: [
          {
            name: 'd',
            credentials: {
              uri: 'https://dest.example.com',
              url: 'https://dest-auth.example.com',
              clientid: 'dc',
              clientsecret: 'ds',
            },
          },
        ],
      }),
    );
    mockFetch.mockResolvedValueOnce(jsonOk({ access_token: 'dest-token', expires_in: 3600 })).mockResolvedValueOnce(
      jsonOk({
        destinationConfiguration: {
          Name: 'S4_CLOUD',
          URL: 'https://s4.cloud.sap',
          Authentication: 'OAuth2SAMLBearerAssertion',
          ProxyType: 'Internet',
          User: '',
          Password: '',
        },
      }),
    );

    const resolved = await resolveBTPDestination('S4_CLOUD');
    expect(resolved.proxy).toBeNull();
    expect(resolved.client).toBe('100'); // default when sap-client absent
  });
});

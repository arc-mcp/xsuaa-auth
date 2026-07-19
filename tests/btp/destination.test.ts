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
const {
  DestinationServiceRequestError,
  listDestinationsAtLevel,
  lookupDestination,
  lookupDestinationWithUserToken,
  lookupDestinationWithUserTokenUncached,
  resolveBTPDestination,
} = await import('../../src/btp.js');

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

function serializedError(error: unknown): string {
  if (!(error instanceof Error)) return JSON.stringify(error);
  return [
    error.message,
    error.stack,
    JSON.stringify(error, Object.getOwnPropertyNames(error)),
    String((error as Error & { cause?: unknown }).cause),
  ].join('\n');
}

describe('listDestinationsAtLevel', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it.each([
    ['subaccount', 'subaccountDestinations'],
    ['instance', 'instanceDestinations'],
  ] as const)('fetches the explicit %s collection with a fresh service token', async (level, collection) => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'service-token', expires_in: 3600 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [
          {
            Name: 'ARC1_A4H_100_PP',
            Type: 'HTTP',
            URL: 'http://a4h.internal:50000',
            Authentication: 'PrincipalPropagation',
            ProxyType: 'OnPremise',
            User: 'SENTINEL_COLLECTION_USER',
            Password: 'sensitive',
            'sap-sysid': 'A4H',
            'sap-client': '100',
            'arc1.enabled': 'true',
            authTokens: [{ value: 'must-not-be-copied' }],
            certificates: [{ content: 'must-not-be-copied' }],
          },
        ],
      });

    const result = await listDestinationsAtLevel(TEST_BTP_CONFIG, level);

    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      `${TEST_BTP_CONFIG.destinationUrl}/destination-configuration/v1/${collection}`,
      { headers: { Authorization: 'Bearer service-token' } },
    );
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      Name: 'ARC1_A4H_100_PP',
      Type: 'HTTP',
      'sap-client': '100',
      User: 'SENTINEL_COLLECTION_USER',
      Password: 'sensitive',
    });
    expect(result[0].originalProperties).toMatchObject({
      'sap-sysid': 'A4H',
      'arc1.enabled': 'true',
    });
    expect(result[0].originalProperties).not.toHaveProperty('User');
    expect(result[0].originalProperties).not.toHaveProperty('Password');
    expect(result[0].originalProperties).not.toHaveProperty('authTokens');
    expect(result[0].originalProperties).not.toHaveProperty('certificates');
    expect(JSON.stringify(result[0].originalProperties)).not.toContain('SENTINEL_COLLECTION_USER');
  });

  it('returns a typed body-free error for a failed collection request', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'service-token', expires_in: 3600 }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        body: null,
      });

    const error = await listDestinationsAtLevel(TEST_BTP_CONFIG, 'subaccount').catch((caught) => caught);
    expect(error).toBeInstanceOf(DestinationServiceRequestError);
    expect(error).toMatchObject({ operation: 'list', status: 403 });
    expect(error.message).not.toContain('secret response body');
  });

  it('does not retain a failed token endpoint response body in the error graph', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => 'client_secret=must-never-escape',
    });

    const error = await listDestinationsAtLevel(TEST_BTP_CONFIG, 'subaccount').catch((caught) => caught);
    expect(error).toBeInstanceOf(DestinationServiceRequestError);
    expect(error).toMatchObject({ operation: 'token' });
    expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain('must-never-escape');
    expect(error.cause).toBeUndefined();
  });
});

describe('lookupDestination', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('returns Basic credentials only on a successful Find response', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'service-token', expires_in: 3600 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          destinationConfiguration: {
            Name: 'ARC1_A4H_100_BASIC',
            URL: 'https://a4h.internal:50001',
            Authentication: 'BasicAuthentication',
            ProxyType: 'OnPremise',
            User: 'SENTINEL_BASIC_USER',
            Password: 'SENTINEL_BASIC_PASSWORD',
            clientSecret: 'SENTINEL_CLIENT_SECRET',
            tokenServiceUser: 'SENTINEL_TOKEN_USER',
            tokenServicePassword: 'SENTINEL_TOKEN_PASSWORD',
            KeyStorePassword: 'SENTINEL_KEYSTORE_PASSWORD',
            SystemUser: 'SENTINEL_SYSTEM_USER',
            authTokens: [{ value: 'SENTINEL_AUTH_TOKEN' }],
            certificates: [{ content: 'SENTINEL_CERTIFICATE' }],
            headers: {
              Authorization: 'SENTINEL_AUTHORIZATION_HEADER',
              'x-safe-header': 'safe-value',
            },
            'sap-sysid': 'A4H',
            'sap-client': '100',
            Description: 'A4H shared reader',
            Preemptive: 'true',
            'arc1.enabled': 'true',
          },
        }),
      });

    const destination = await lookupDestination(TEST_BTP_CONFIG, 'ARC1_A4H_100_BASIC');

    expect(destination).toMatchObject({
      Name: 'ARC1_A4H_100_BASIC',
      User: 'SENTINEL_BASIC_USER',
      Password: 'SENTINEL_BASIC_PASSWORD',
    });
    expect(destination.originalProperties).toMatchObject({
      'sap-sysid': 'A4H',
      'sap-client': '100',
      Description: 'A4H shared reader',
      Preemptive: 'true',
      'arc1.enabled': 'true',
      headers: { 'x-safe-header': 'safe-value' },
    });
    expect(JSON.stringify(destination.originalProperties)).not.toContain('SENTINEL');
    for (const key of [
      'User',
      'Password',
      'clientSecret',
      'tokenServiceUser',
      'tokenServicePassword',
      'KeyStorePassword',
      'SystemUser',
      'authTokens',
      'certificates',
    ]) {
      expect(destination.originalProperties).not.toHaveProperty(key);
    }
  });

  it.each([
    {
      name: 'network failure',
      response: () => Promise.reject(new Error('SENTINEL_FIND_NETWORK_SECRET')),
      status: undefined,
    },
    {
      name: 'non-2xx response',
      response: () =>
        Promise.resolve(
          new Response('SENTINEL_FIND_RESPONSE_SECRET', {
            status: 403,
            headers: { 'x-test-secret': 'SENTINEL_FIND_HEADER_SECRET' },
          }),
        ),
      status: 403,
    },
    {
      name: 'invalid JSON response',
      response: () => Promise.resolve(new Response('SENTINEL_FIND_INVALID_JSON', { status: 200 })),
      status: 200,
    },
    {
      name: 'invalid response shape',
      response: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              destinationConfiguration: {
                Name: 'ARC1_A4H_100_BASIC',
                User: 'SENTINEL_SHAPE_USER',
                Password: 'SENTINEL_SHAPE_PASSWORD',
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        ),
      status: 200,
    },
  ])('returns a typed body-free error for a Find $name', async ({ response, status }) => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'service-token', expires_in: 3600 }),
      })
      .mockImplementationOnce(response);

    const error = await lookupDestination(TEST_BTP_CONFIG, 'ARC1_A4H_100_BASIC').catch((caught) => caught);

    expect(error).toBeInstanceOf(DestinationServiceRequestError);
    expect(error).toMatchObject({ operation: 'find', status });
    expect(serializedError(error)).not.toContain('SENTINEL');
  });

  it.each([
    {
      name: 'network failure',
      response: () => Promise.reject(new Error('SENTINEL_TOKEN_NETWORK_SECRET')),
    },
    {
      name: 'non-2xx response',
      response: () =>
        Promise.resolve(
          new Response('SENTINEL_TOKEN_RESPONSE_SECRET', {
            status: 401,
            headers: { 'x-test-secret': 'SENTINEL_TOKEN_HEADER_SECRET' },
          }),
        ),
    },
    {
      name: 'invalid JSON response',
      response: () => Promise.resolve(new Response('SENTINEL_TOKEN_INVALID_JSON', { status: 200 })),
    },
    {
      name: 'invalid response shape',
      response: () =>
        Promise.resolve(
          new Response(JSON.stringify({ access_token: '', detail: 'SENTINEL_TOKEN_SHAPE_SECRET' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
    },
  ])('returns a typed body-free error for a token $name', async ({ response }) => {
    mockFetch.mockImplementationOnce(response);

    const error = await lookupDestination(TEST_BTP_CONFIG, 'ARC1_A4H_100_BASIC').catch((caught) => caught);

    expect(error).toBeInstanceOf(DestinationServiceRequestError);
    expect(error).toMatchObject({ operation: 'token' });
    expect(serializedError(error)).not.toContain('SENTINEL');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

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
      originalProperties: {
        destinationConfiguration: {
          Name: 'SAP_TRIAL',
          Type: 'HTTP',
          User: 'SENTINEL_PP_ORIGINAL_USER',
          Password: 'SENTINEL_PP_ORIGINAL_PASSWORD',
          'sap-sysid': 'A4H',
          'sap-client': '100',
          'arc1.enabled': 'true',
        },
        authTokens: [{ value: 'do-not-copy' }],
      },
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
    expect(result.destination.originalProperties).toMatchObject({
      'sap-sysid': 'A4H',
      'arc1.enabled': 'true',
    });
    expect(JSON.stringify(result.destination.originalProperties)).not.toContain('SENTINEL');
    expect(result.destination.originalProperties).not.toHaveProperty('User');
    expect(result.destination.originalProperties).not.toHaveProperty('Password');
    expect(result.destination.originalProperties).not.toHaveProperty('authTokens');
    expect(result.authTokens.sapConnectivityAuth).toBe('Bearer saml-assertion-encoded');
  });

  it('provides an explicit uncached PP lookup for immediate retries and drift detection', async () => {
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

    await lookupDestinationWithUserTokenUncached(TEST_BTP_CONFIG, 'SAP_TRIAL', USER_JWT);

    expect(mockGetDestination).toHaveBeenCalledWith({
      destinationName: 'SAP_TRIAL',
      jwt: USER_JWT,
      useCache: false,
      isolationStrategy: 'tenant-user',
    });
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

  // ── Shape 2b: SAMLAssertion → ready-to-use Authorization header value ──
  it('returns the SAMLAssertion Authorization header value for SAMLAssertion destinations (S/4HC, BAS flow)', async () => {
    mockGetDestination.mockResolvedValueOnce({
      name: 'S4HC_PP',
      url: 'https://my.s4hana.cloud.sap',
      authentication: 'SAMLAssertion',
      proxyType: 'Internet',
      username: '',
      password: '',
      authTokens: [
        {
          type: 'SAML2.0',
          value: '',
          error: null,
          http_header: { key: 'Authorization', value: 'SAML2.0 ass=base64assertion' },
        },
      ],
    });

    const result = await lookupDestinationWithUserToken(TEST_BTP_CONFIG, 'S4HC_PP', USER_JWT);
    expect(result.destination.Authentication).toBe('SAMLAssertion');
    expect(result.authTokens.samlAssertionAuthorization).toBe('SAML2.0 ass=base64assertion');
    // Mutually exclusive with the other per-user credential shapes.
    expect(result.authTokens.bearerToken).toBeUndefined();
    expect(result.authTokens.sapConnectivityAuth).toBeUndefined();
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

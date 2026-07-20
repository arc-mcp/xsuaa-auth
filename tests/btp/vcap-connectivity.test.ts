/**
 * `./btp` — parseVCAPServices, lookupDestination (startup), createConnectivityProxy.
 *
 * Ported from arc-1 `tests/unit/adt/btp.test.ts`. Adaptations for the package:
 *   - `parseVCAPServices(env?)` takes an explicit env (no process.env mutation),
 *   - functions are imported from `@arc-mcp/xsuaa-auth/btp` (here via `../../src/btp.js`),
 *   - the global `fetch` is stubbed for the token + destination-service calls.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type BTPConfig,
  BTPRequestTimeoutError,
  createConnectivityProxy,
  DEFAULT_BTP_REQUEST_TIMEOUT_MS,
  DestinationServiceRequestError,
  lookupDestination,
  MAX_BTP_REQUEST_TIMEOUT_MS,
  parseVCAPServices,
} from '../../src/btp.js';

const BASE_BTP_CONFIG: BTPConfig = {
  xsuaaUrl: 'https://xsuaa.example.com',
  xsuaaClientId: 'xsuaa-client',
  xsuaaSecret: 'xsuaa-secret',
  destinationUrl: 'https://destination.example.com',
  destinationClientId: 'destination-client',
  destinationSecret: 'destination-secret',
  destinationTokenUrl: 'https://destination-auth.example.com/oauth/token',
  connectivityProxyHost: 'proxy.internal',
  connectivityProxyPort: '20003',
  connectivityClientId: 'connectivity-client',
  connectivitySecret: 'connectivity-secret',
  connectivityTokenUrl: 'https://connectivity-auth.example.com/oauth/token',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function rejectWhenAborted(signal: AbortSignal | null | undefined): Promise<never> {
  if (!signal) return Promise.reject(new Error('Expected an abort signal'));
  return new Promise((_, reject) => {
    const rejectWithReason = () => reject(signal.reason ?? new Error('Request aborted'));
    if (signal.aborted) rejectWithReason();
    else signal.addEventListener('abort', rejectWithReason, { once: true });
  });
}

describe('parseVCAPServices', () => {
  it('returns null when VCAP_SERVICES is not set (explicit empty env)', () => {
    expect(parseVCAPServices({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it('parses xsuaa, destination, and connectivity bindings with token URL fallbacks', () => {
    const env = {
      VCAP_SERVICES: JSON.stringify({
        xsuaa: [
          {
            name: 'xsuaa',
            credentials: { url: 'https://xsuaa.example.com', clientid: 'xsuaa-client', clientsecret: 'xsuaa-secret' },
          },
        ],
        destination: [
          {
            name: 'destination',
            credentials: {
              uri: 'https://destination.example.com',
              url: 'https://destination-auth.example.com',
              clientid: 'destination-client',
              clientsecret: 'destination-secret',
            },
          },
        ],
        connectivity: [
          {
            name: 'connectivity',
            credentials: {
              onpremise_proxy_host: 'proxy.internal',
              onpremise_proxy_http_port: '20003',
              clientid: 'connectivity-client',
              clientsecret: 'connectivity-secret',
              token_service_url: 'https://connectivity-auth.example.com',
            },
          },
        ],
      }),
    } as NodeJS.ProcessEnv;

    const config = parseVCAPServices(env);

    expect(config).not.toBeNull();
    expect(config?.xsuaaUrl).toBe('https://xsuaa.example.com');
    expect(config?.destinationUrl).toBe('https://destination.example.com');
    // token_service_url fallback path: destination uses url + /oauth/token.
    expect(config?.destinationTokenUrl).toBe('https://destination-auth.example.com/oauth/token');
    expect(config?.connectivityProxyHost).toBe('proxy.internal');
    // connectivity ensures the /oauth/token suffix.
    expect(config?.connectivityTokenUrl).toBe('https://connectivity-auth.example.com/oauth/token');
  });

  it('defaults to process.env when no env arg is passed (null off-BTP)', () => {
    // vi.stubEnv(name, undefined) removes the var without the `delete` operator;
    // vi.unstubAllEnvs() restores the original value.
    vi.stubEnv('VCAP_SERVICES', undefined);
    try {
      expect(parseVCAPServices()).toBeNull();
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('lookupDestination (startup direct-fetch path)', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('looks up a destination using a client-credentials token', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ access_token: 'destination-token', expires_in: 3600 }))
      .mockResolvedValueOnce(
        jsonResponse({
          destinationConfiguration: {
            Name: 'SAP_A4H',
            URL: 'https://sap.example.com',
            Authentication: 'BasicAuthentication',
            ProxyType: 'OnPremise',
            User: 'sap-user',
            Password: 'sap-password',
            'sap-client': '100',
            CloudConnectorLocationId: 'EU10',
          },
        }),
      );

    const destination = await lookupDestination(BASE_BTP_CONFIG, 'SAP_A4H');

    expect(destination.Name).toBe('SAP_A4H');
    expect(destination.ProxyType).toBe('OnPremise');
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://destination-auth.example.com/oauth/token',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://destination.example.com/destination-configuration/v1/destinations/SAP_A4H',
      expect.objectContaining({
        headers: { Authorization: 'Bearer destination-token' },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('throws when the Destination Service returns a non-2xx', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ access_token: 'destination-token', expires_in: 3600 }))
      .mockResolvedValueOnce(new Response('not found', { status: 404 }));
    const error = await lookupDestination(BASE_BTP_CONFIG, 'MISSING').catch((caught) => caught);
    expect(error).toBeInstanceOf(DestinationServiceRequestError);
    expect(error).toMatchObject({ operation: 'find', status: 404 });
  });
});

describe('createConnectivityProxy', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('returns null when no proxy host is configured', () => {
    const proxy = createConnectivityProxy({ ...BASE_BTP_CONFIG, connectivityProxyHost: '' });
    expect(proxy).toBeNull();
  });

  it('builds the descriptor (host/port/protocol/locationId)', () => {
    const proxy = createConnectivityProxy(BASE_BTP_CONFIG, 'EU10');
    expect(proxy).not.toBeNull();
    expect(proxy?.host).toBe('proxy.internal');
    expect(proxy?.port).toBe(20003);
    expect(proxy?.protocol).toBe('http');
    expect(proxy?.locationId).toBe('EU10');
  });

  it('caches the connectivity proxy token until the expiry buffer', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ access_token: 'connectivity-token', expires_in: 3600 }));
    const proxy = createConnectivityProxy(BASE_BTP_CONFIG, 'EU10');

    await expect(proxy?.getProxyToken()).resolves.toBe('connectivity-token');
    await expect(proxy?.getProxyToken()).resolves.toBe('connectivity-token');

    // Only ONE token fetch — the second call is served from cache.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://connectivity-auth.example.com/oauth/token',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }),
    );
  });

  it('defaults the proxy port to 20003 when not provided', () => {
    const proxy = createConnectivityProxy({ ...BASE_BTP_CONFIG, connectivityProxyPort: '' });
    expect(proxy?.port).toBe(20003);
  });

  it('uses the default timeout and does not cache a timed-out connectivity token request', async () => {
    vi.useFakeTimers();
    let firstSignal: AbortSignal | undefined;
    fetchMock
      .mockImplementationOnce((_url, init?: RequestInit) => {
        firstSignal = init?.signal ?? undefined;
        return rejectWhenAborted(init?.signal);
      })
      .mockResolvedValueOnce(jsonResponse({ access_token: 'retry-token', expires_in: 3600 }));
    const proxy = createConnectivityProxy(BASE_BTP_CONFIG);
    if (!proxy) throw new Error('Expected connectivity proxy');

    const firstAttempt = proxy.getProxyToken();
    const rejection = expect(firstAttempt).rejects.toMatchObject({
      timeoutMs: DEFAULT_BTP_REQUEST_TIMEOUT_MS,
    });
    await vi.advanceTimersByTimeAsync(DEFAULT_BTP_REQUEST_TIMEOUT_MS - 1);
    expect(firstSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await rejection;
    expect(firstSignal?.aborted).toBe(true);
    expect(await proxy.getProxyToken()).toBe('retry-token');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('caps an oversized connectivity request timeout', async () => {
    vi.useFakeTimers();
    let requestSignal: AbortSignal | undefined;
    fetchMock.mockImplementationOnce((_url, init?: RequestInit) => {
      requestSignal = init?.signal ?? undefined;
      return rejectWhenAborted(init?.signal);
    });
    const proxy = createConnectivityProxy({ ...BASE_BTP_CONFIG, requestTimeoutMs: Number.MAX_SAFE_INTEGER });
    if (!proxy) throw new Error('Expected connectivity proxy');

    const request = proxy.getProxyToken();
    const rejection = expect(request).rejects.toBeInstanceOf(BTPRequestTimeoutError);
    await vi.advanceTimersByTimeAsync(MAX_BTP_REQUEST_TIMEOUT_MS - 1);
    expect(requestSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await rejection;
    expect(requestSignal?.reason).toMatchObject({ timeoutMs: MAX_BTP_REQUEST_TIMEOUT_MS });
  });
});

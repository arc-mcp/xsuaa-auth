/**
 * BTP Destination Service lookups (startup + per-user principal propagation).
 *
 * Startup path (`lookupDestination`, `resolveBTPDestination`) uses direct fetch
 * to the Destination Service API — works with BasicAuth destinations without a
 * user JWT. Per-user principal-propagation path (`lookupDestinationWithUserToken`)
 * uses SAP Cloud SDK's `getDestination()` for automatic token management and
 * per-user caching, with a jwt-bearer "Option 2" fallback.
 *
 * The package returns credentials + a proxy descriptor; it never applies them.
 * What to do when no PP token is produced is consumer policy.
 */

import {
  type DestinationAuthToken,
  getDestination,
  type Destination as SdkDestination,
} from '@sap-cloud-sdk/connectivity';
import { type Logger, noopLogger } from '../logger.js';
import { type BTPProxyConfig, createConnectivityProxy } from './connectivity.js';
import { type BTPConfig, fetchClientCredentialsToken, parseVCAPServices } from './vcap.js';

// ─── Types ───────────────────────────────────────────────────────────

/** Resolved destination from BTP Destination Service */
export interface Destination {
  Name: string;
  URL: string;
  Authentication: string;
  ProxyType: string;
  User: string;
  Password: string;
  /** Destination type as configured in BTP (normally HTTP). */
  Type?: string;
  'sap-client'?: string;
  /** Cloud Connector Location ID — used to route to the correct SCC instance */
  CloudConnectorLocationId?: string;
  /**
   * Original destination configuration properties, including custom properties.
   * Authentication-token and certificate response payloads are deliberately excluded.
   * This object can still contain destination credentials and must be treated as sensitive.
   */
  originalProperties?: Readonly<Record<string, unknown>>;
}

/** Destination configuration level in the bound Destination service. */
export type DestinationLevel = 'subaccount' | 'instance';

/** Safe, typed error for collection requests. Response bodies are never included. */
export class DestinationServiceRequestError extends Error {
  constructor(
    message: string,
    readonly operation: 'token' | 'list',
    readonly status?: number,
  ) {
    super(message);
    this.name = 'DestinationServiceRequestError';
  }
}

/**
 * Per-user authentication tokens returned by Destination Service
 * when called with X-User-Token header.
 *
 * For PrincipalPropagation destinations, the Destination Service
 * generates a SAML assertion containing the user identity and returns
 * it as the SAP-Connectivity-Authentication header value.
 */
export interface PerUserAuthTokens {
  /** SAP-Connectivity-Authentication header value (SAML assertion for Cloud Connector) */
  sapConnectivityAuth?: string;
  /** Any Bearer token returned by the Destination Service */
  bearerToken?: string;
  /** PP "Option 1" (jwt-bearer → Proxy-Authorization). RESERVED / not yet produced
   *  by `lookupDestinationWithUserToken`: on a successful per-user lookup this
   *  package sets `sapConnectivityAuth` (Bearer <verified user JWT>), never this
   *  field. A consumer implementing the jwt-bearer exchange assigns it itself. */
  ppProxyAuth?: string;
  /** SAMLAssertion flow (e.g. S/4HANA Public Cloud developer extensibility, the same flow BAS
   *  uses): the ready-to-use `Authorization` header value (e.g. "SAML2.0 …") returned by the
   *  Destination Service. The consumer sends it verbatim as `Authorization`, alongside
   *  `x-sap-security-session: create` (mirrors the SAP Cloud SDK's SAMLAssertion handling). */
  samlAssertionAuthorization?: string;
}

// ─── Destination Service ─────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringProperty(properties: Record<string, unknown>, key: string): string {
  const value = properties[key];
  return typeof value === 'string' ? value : '';
}

function originalConfiguration(value: unknown): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) return Object.freeze({});
  const nested = value.destinationConfiguration;
  const source = isRecord(nested) ? nested : value;
  const { authTokens: _authTokens, certificates: _certificates, ...configuration } = source;
  return Object.freeze(configuration);
}

function destinationFromConfiguration(value: unknown): Destination {
  const properties = originalConfiguration(value);
  return {
    Name: stringProperty(properties, 'Name'),
    URL: stringProperty(properties, 'URL'),
    Authentication: stringProperty(properties, 'Authentication'),
    ProxyType: stringProperty(properties, 'ProxyType'),
    User: stringProperty(properties, 'User'),
    Password: stringProperty(properties, 'Password'),
    Type: stringProperty(properties, 'Type') || undefined,
    'sap-client': stringProperty(properties, 'sap-client') || undefined,
    CloudConnectorLocationId: stringProperty(properties, 'CloudConnectorLocationId') || undefined,
    originalProperties: properties,
  };
}

async function destinationServiceAccessToken(btpConfig: BTPConfig): Promise<string> {
  const tokenUrl = btpConfig.destinationTokenUrl || `${btpConfig.xsuaaUrl}/oauth/token`;
  try {
    const { accessToken } = await fetchClientCredentialsToken(
      tokenUrl,
      btpConfig.destinationClientId,
      btpConfig.destinationSecret,
    );
    return accessToken;
  } catch {
    throw new DestinationServiceRequestError('Destination Service token acquisition failed', 'token');
  }
}

/**
 * Fetch every destination configured at one explicit level of the bound service.
 *
 * The call uses a fresh service token and a direct collection request; it does not use the
 * SAP Cloud SDK destination cache. Consumers should immediately project the returned objects
 * because originalProperties can contain sensitive destination credentials.
 */
export async function listDestinationsAtLevel(
  btpConfig: BTPConfig,
  level: DestinationLevel,
  logger: Logger = noopLogger,
): Promise<Destination[]> {
  const accessToken = await destinationServiceAccessToken(btpConfig);
  const collection = level === 'subaccount' ? 'subaccountDestinations' : 'instanceDestinations';
  const url = `${btpConfig.destinationUrl.replace(/\/$/, '')}/destination-configuration/v1/${collection}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  } catch {
    throw new DestinationServiceRequestError(`Destination Service ${level} list request failed`, 'list');
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new DestinationServiceRequestError(
      `Destination Service ${level} list request returned HTTP ${response.status}`,
      'list',
      response.status,
    );
  }

  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw new DestinationServiceRequestError(
      `Destination Service ${level} list returned an invalid response`,
      'list',
      response.status,
    );
  }
  const entries = Array.isArray(raw)
    ? raw
    : isRecord(raw) && Array.isArray(raw.destinations)
      ? raw.destinations
      : undefined;
  if (!entries) {
    throw new DestinationServiceRequestError(
      `Destination Service ${level} list returned an invalid response`,
      'list',
      response.status,
    );
  }

  const destinations = entries.map(destinationFromConfiguration);
  logger.info('BTP destination collection resolved', { level, count: destinations.length });
  return destinations;
}

/**
 * Look up a destination from the BTP Destination Service.
 * Returns SAP URL, credentials, and proxy type.
 */
export async function lookupDestination(
  btpConfig: BTPConfig,
  destinationName: string,
  logger: Logger = noopLogger,
): Promise<Destination> {
  // Get token for Destination Service API
  const tokenUrl = btpConfig.destinationTokenUrl || `${btpConfig.xsuaaUrl}/oauth/token`;
  const { accessToken } = await fetchClientCredentialsToken(
    tokenUrl,
    btpConfig.destinationClientId,
    btpConfig.destinationSecret,
  );

  // Call Destination Service
  const destUrl = `${btpConfig.destinationUrl.replace(/\/$/, '')}/destination-configuration/v1/destinations/${encodeURIComponent(destinationName)}`;
  const resp = await fetch(destUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Destination Service returned HTTP ${resp.status}: ${text.slice(0, 200)}`);
  }

  const data = (await resp.json()) as unknown;
  const destination = destinationFromConfiguration(data);

  // Don't log the resolved SAP URL/host (internal topology) — name + auth metadata
  // are enough to debug a destination lookup. Same for the per-user paths below.
  logger.info('BTP destination resolved', {
    name: destination.Name,
    auth: destination.Authentication,
    proxyType: destination.ProxyType,
    hasLocationId: destination.CloudConnectorLocationId != null,
  });

  return destination;
}

// ─── Per-User Destination (Principal Propagation) ────────────────────

/**
 * Look up a destination with the user's JWT token for principal propagation.
 *
 * Uses SAP Cloud SDK's `getDestination()` to resolve the destination with per-user
 * JWT. The SDK handles service token acquisition, X-User-Token header injection,
 * and per-user destination caching.
 *
 * This is the key API for per-user SAP authentication:
 * 1. Caller passes the user's JWT (from XSUAA/OIDC)
 * 2. SDK calls the Destination Service with X-User-Token header
 * 3. For PrincipalPropagation destinations: returns SAP-Connectivity-Authentication header
 * 4. For OAuth2SAMLBearerAssertion destinations: returns a Bearer token
 *
 * Includes a jwt-bearer fallback (Option 2) when the Destination Service returns
 * no auth tokens — uses direct fetch to the Connectivity Service token URL.
 *
 * @param btpConfig - BTP service credentials (needed for jwt-bearer fallback only)
 */
export async function lookupDestinationWithUserToken(
  btpConfig: BTPConfig,
  destinationName: string,
  userJwt: string,
  logger: Logger = noopLogger,
): Promise<{ destination: Destination; authTokens: PerUserAuthTokens }> {
  return lookupDestinationWithUserTokenInternal(btpConfig, destinationName, userJwt, true, logger);
}

/**
 * Resolve a per-user destination without reading from or writing to the SAP Cloud SDK cache.
 * Use this when every request must observe destination/PP changes immediately and failed PP
 * resolutions must never influence a later retry.
 */
export async function lookupDestinationWithUserTokenUncached(
  btpConfig: BTPConfig,
  destinationName: string,
  userJwt: string,
  logger: Logger = noopLogger,
): Promise<{ destination: Destination; authTokens: PerUserAuthTokens }> {
  return lookupDestinationWithUserTokenInternal(btpConfig, destinationName, userJwt, false, logger);
}

async function lookupDestinationWithUserTokenInternal(
  btpConfig: BTPConfig,
  destinationName: string,
  userJwt: string,
  useCache: boolean,
  logger: Logger,
): Promise<{ destination: Destination; authTokens: PerUserAuthTokens }> {
  // JWT-shape guard (anti-footgun): PP needs a per-user user token, not an API key.
  // arc-1 guards this at its call site; the package guards it for every consumer.
  if (userJwt.split('.').length !== 3) {
    throw new Error('lookupDestinationWithUserToken requires a JWT bearer token (got a non-JWT, e.g. an API key)');
  }

  // Log JWT-claim PRESENCE for PP debugging (decode payload without verification).
  // Never log the raw claims — `sub`/`email`/`user_uuid`/`origin` are user PII and
  // `iss`/`aud`/`azp`/`zid` leak BTP tenant topology. Emit booleans/counts/the
  // grant type only.
  try {
    const parts = userJwt.split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      const scopeCount = Array.isArray(payload.scope)
        ? payload.scope.length
        : typeof payload.scope === 'string'
          ? payload.scope.split(' ').filter(Boolean).length
          : 0;
      logger.debug('PP user JWT claims (redacted)', {
        destination: destinationName,
        grantType: payload.grant_type,
        hasSub: payload.sub != null,
        hasEmail: payload.email != null,
        hasUserUuid: payload.user_uuid != null,
        hasZid: payload.zid != null,
        hasIss: payload.iss != null,
        audCount: Array.isArray(payload.aud) ? payload.aud.length : payload.aud != null ? 1 : 0,
        hasAzp: payload.azp != null,
        scopeCount,
        hasOrigin: payload.origin != null,
        exp: payload.exp,
      });
    }
  } catch {
    logger.debug('PP user JWT: failed to decode claims');
  }

  // Use SAP Cloud SDK to resolve the destination with per-user JWT.
  // The SDK handles: service token acquisition, X-User-Token header,
  // and per-user destination caching.
  //
  // SECURITY (cross-user cache isolation): a PrincipalPropagation destination
  // resolves to a per-user SAML assertion / bearer token, so a cache entry MUST
  // NOT be shared across users. We pin `isolationStrategy: 'tenant-user'`
  // explicitly: the SDK's default is already 'tenant-user', but pinning it makes
  // the per-user guarantee load-bearing in code (a future SDK default change or a
  // technical-destination copy-paste cannot silently widen the cache key to
  // tenant-only and leak one user's propagated identity to another). The value is
  // the SDK's `IsolationStrategy` string-literal union ('tenant' | 'tenant-user').
  const sdkDest: SdkDestination | null = await getDestination({
    destinationName,
    jwt: userJwt,
    useCache,
    isolationStrategy: 'tenant-user',
  });

  if (!sdkDest) {
    throw new Error(`Destination Service (per-user) returned no destination for '${destinationName}'`);
  }

  // Map SDK Destination → package Destination type
  const originalProperties = originalConfiguration(sdkDest.originalProperties);
  const dest: Destination = {
    Name: sdkDest.name ?? destinationName,
    URL: sdkDest.url ?? '',
    Authentication: sdkDest.authentication ?? '',
    ProxyType: sdkDest.proxyType ?? '',
    User: sdkDest.username ?? '',
    Password: sdkDest.password ?? '',
    Type: sdkDest.type ?? (stringProperty(originalProperties, 'Type') || undefined),
    'sap-client': sdkDest.sapClient ?? (stringProperty(originalProperties, 'sap-client') || undefined),
    CloudConnectorLocationId:
      sdkDest.cloudConnectorLocationId ?? (stringProperty(originalProperties, 'CloudConnectorLocationId') || undefined),
    originalProperties,
  };

  const tokens: PerUserAuthTokens = {};
  const sdkAuthTokens: DestinationAuthToken[] | null | undefined = sdkDest.authTokens;

  // Log raw auth response for PP debugging.
  // Field names avoid "token" substring to prevent logger redaction.
  const rawEntries = sdkAuthTokens?.map((t) => ({
    entryType: t.type,
    httpHeaderKey: t.http_header?.key,
    hasValue: !!t.value,
    hasHttpHeaderValue: !!t.http_header?.value,
    entryError: t.error,
  }));
  logger.debug('Destination Service PP response', {
    destination: destinationName,
    authentication: dest.Authentication,
    proxyType: dest.ProxyType,
    ppEntryCount: sdkAuthTokens?.length ?? 0,
    ppEntries: rawEntries ?? 'NONE',
  });

  // Extract auth tokens from the SDK response
  if (sdkAuthTokens) {
    for (const token of sdkAuthTokens) {
      if (token.error) {
        logger.error('Destination Service auth token error', {
          destination: destinationName,
          tokenType: token.type,
          error: token.error,
        });
        throw new Error(`Destination Service auth token error for '${destinationName}': ${token.error}`);
      }

      // SAP-Connectivity-Authentication header (used by Cloud Connector for PP)
      if (token.http_header?.key === 'SAP-Connectivity-Authentication') {
        tokens.sapConnectivityAuth = token.http_header.value;
        logger.debug('PP: SAP-Connectivity-Authentication header extracted', {
          destination: destinationName,
          headerValueLength: token.http_header.value.length,
        });
      }

      // Bearer token (OAuth2UserTokenExchange / OAuth2SAMLBearerAssertion). The SAP Cloud SDK
      // lowercases the type ("bearer") for OAuth2UserTokenExchange and exposes the token via
      // `value` and/or an `Authorization` http_header. Match case-insensitively and fall back to
      // the header value (stripping the "Bearer " prefix). Verified live against a BTP ABAP
      // Environment (#301): a capital-B-only check silently dropped the token (hasBearer:false).
      if (token.type?.toLowerCase() === 'bearer') {
        tokens.bearerToken = token.value || token.http_header?.value?.replace(/^Bearer\s+/i, '');
      }
    }
  } else {
    logger.warn('Destination Service returned no authTokens — trying jwt-bearer exchange fallback', {
      destination: destinationName,
      authentication: dest.Authentication,
    });
  }

  // SAMLAssertion flow (e.g. S/4HANA Public Cloud developer extensibility — same flow BAS uses).
  // The Destination Service returns the assertion as a ready-to-use Authorization header value; the
  // SAP Cloud SDK uses the first non-error token's `http_header.value` for this type (see
  // @sap-cloud-sdk/connectivity authorization-header.ts → headerFromTokens). We surface it so the
  // consumer can send it verbatim as Authorization + `x-sap-security-session: create`.
  if (dest.Authentication === 'SAMLAssertion' && !tokens.sapConnectivityAuth && !tokens.bearerToken) {
    const usable = sdkAuthTokens?.find((token) => !token.error && token.http_header?.value);
    if (usable?.http_header?.value) {
      tokens.samlAssertionAuthorization = usable.http_header.value;
      logger.debug('PP: SAMLAssertion Authorization header extracted', {
        destination: destinationName,
        headerValueLength: usable.http_header.value.length,
      });
    }
  }

  // ─── PP jwt-bearer fallback (Option 2) ─────────────────────────────
  //
  // Background: The BTP Destination Service SHOULD return authTokens containing
  // the SAP-Connectivity-Authentication header for PrincipalPropagation destinations.
  // In practice, it often returns NO authTokens (empty response). This is a known
  // issue — the Destination Service simply omits the field.
  //
  // Workaround: We perform a jwt-bearer token exchange with the Connectivity
  // Service's XSUAA to verify the user JWT is valid. If the exchange succeeds,
  // we send the ORIGINAL user JWT as SAP-Connectivity-Authentication (Option 2
  // per SAP docs page 211). The Cloud Connector extracts the user identity from
  // this header and generates the X.509 certificate.
  //
  // Why Option 2 and not Option 1?
  // - Option 1 sends the EXCHANGED token as Proxy-Authorization
  // - The CC couldn't extract the principal from the exchanged token
  //   (CC trace: "no principal available, injecting empty certificate")
  // - Option 2 sends the ORIGINAL user JWT as SAP-Connectivity-Authentication
  //   + regular connectivity proxy token as Proxy-Authorization
  // - The CC successfully extracts the user email from the original JWT
  //
  // Reference: SAP BTP Connectivity docs page 209-213
  // https://help.sap.com/docs/connectivity/sap-btp-connectivity-cf/configure-principal-propagation-via-user-exchange-token
  if (!tokens.sapConnectivityAuth && dest.Authentication === 'PrincipalPropagation' && btpConfig.connectivityClientId) {
    logger.info('PP jwt-bearer exchange: attempting direct exchange with Connectivity Service', {
      destination: destinationName,
    });

    try {
      // Exchange user JWT via jwt-bearer grant type with Connectivity Service credentials.
      // This validates the user JWT and proves we have a legitimate user token.
      // The exchange itself isn't used for auth — we use the original JWT instead.
      const exchangeResp = await fetch(btpConfig.connectivityTokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          client_id: btpConfig.connectivityClientId,
          client_secret: btpConfig.connectivitySecret,
          assertion: userJwt,
          token_format: 'jwt',
          response_type: 'token',
        }).toString(),
      });

      if (exchangeResp.ok) {
        await exchangeResp.json(); // consume response body

        // Option 2: Send the ORIGINAL user JWT as SAP-Connectivity-Authentication.
        // The CC reads this header, extracts the user identity (email), and generates
        // a short-lived X.509 certificate with CN=${email}. The regular connectivity
        // proxy token (from btpProxy.getProxyToken()) is sent as Proxy-Authorization.
        tokens.sapConnectivityAuth = `Bearer ${userJwt}`;

        logger.info('PP: using Option 2 (SAP-Connectivity-Authentication with original JWT)', {
          destination: destinationName,
        });
      } else {
        const errText = await exchangeResp.text();
        logger.error('PP jwt-bearer exchange: failed', {
          destination: destinationName,
          status: exchangeResp.status,
          error: errText.slice(0, 300),
        });
      }
    } catch (err) {
      logger.error('PP jwt-bearer exchange: error', {
        destination: destinationName,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  logger.info('BTP destination resolved (per-user)', {
    name: dest.Name,
    auth: dest.Authentication,
    hasConnectivityAuth: !!tokens.sapConnectivityAuth,
    hasBearer: !!tokens.bearerToken,
    hasSamlAssertion: !!tokens.samlAssertionAuthorization,
  });

  return { destination: dest, authTokens: tokens };
}

// ─── Top-Level Resolver ──────────────────────────────────────────────

/**
 * Resolve BTP destination and connectivity proxy.
 * Called on startup when SAP_BTP_DESTINATION env var is set.
 *
 * Returns the resolved SAP connection config to override defaults.
 */
export async function resolveBTPDestination(
  destinationName: string,
  logger: Logger = noopLogger,
): Promise<{
  url: string;
  username: string;
  password: string;
  client: string;
  proxy: BTPProxyConfig | null;
}> {
  const btpConfig = parseVCAPServices(process.env, logger);
  if (!btpConfig) {
    throw new Error('SAP_BTP_DESTINATION is set but VCAP_SERVICES is not available. Are you running on BTP CF?');
  }

  // Use direct fetch for startup — works with BasicAuth destinations without JWT.
  // The SDK's getDestination() fails for PrincipalPropagation destinations at startup
  // because there's no user JWT available yet.
  const dest = await lookupDestination(btpConfig, destinationName, logger);
  const proxy =
    dest.ProxyType === 'OnPremise' ? createConnectivityProxy(btpConfig, dest.CloudConnectorLocationId, logger) : null;

  return {
    url: dest.URL,
    username: dest.User,
    password: dest.Password,
    client: dest['sap-client'] || '100',
    proxy,
  };
}

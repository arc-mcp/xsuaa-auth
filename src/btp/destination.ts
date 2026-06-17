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
  type Destination as SdkDestination,
  getDestination,
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
  'sap-client'?: string;
  /** Cloud Connector Location ID — used to route to the correct SCC instance */
  CloudConnectorLocationId?: string;
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
  /** PP Option 1: jwt-bearer exchanged token for Proxy-Authorization (recommended approach) */
  ppProxyAuth?: string;
}

// ─── Destination Service ─────────────────────────────────────────────

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

  const data = (await resp.json()) as { destinationConfiguration: Destination };

  // Don't log the resolved SAP URL/host (internal topology) — name + auth metadata
  // are enough to debug a destination lookup. Same for the per-user paths below.
  logger.info('BTP destination resolved', {
    name: data.destinationConfiguration.Name,
    auth: data.destinationConfiguration.Authentication,
    proxyType: data.destinationConfiguration.ProxyType,
    hasLocationId: data.destinationConfiguration.CloudConnectorLocationId != null,
  });

  return data.destinationConfiguration;
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
  // and per-user destination caching (keyed by destinationName + jwt).
  const sdkDest: SdkDestination | null = await getDestination({
    destinationName,
    jwt: userJwt,
    useCache: true,
  });

  if (!sdkDest) {
    throw new Error(`Destination Service (per-user) returned no destination for '${destinationName}'`);
  }

  // Map SDK Destination → package Destination type
  const dest: Destination = {
    Name: sdkDest.name ?? destinationName,
    URL: sdkDest.url ?? '',
    Authentication: sdkDest.authentication ?? '',
    ProxyType: sdkDest.proxyType ?? '',
    User: sdkDest.username ?? '',
    Password: sdkDest.password ?? '',
    'sap-client': sdkDest.sapClient ?? undefined,
    CloudConnectorLocationId: sdkDest.cloudConnectorLocationId ?? undefined,
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

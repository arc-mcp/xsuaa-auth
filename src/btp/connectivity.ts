/**
 * Cloud Connector connectivity-proxy descriptor.
 *
 * `createConnectivityProxy` returns a {@link BTPProxyConfig} whose `getProxyToken`
 * caches the connectivity JWT and auto-refreshes it 60 seconds before expiry.
 * The package returns this descriptor only; the consumer's SAP HTTP client
 * applies it (host/port + Proxy-Authorization + SAP-Connectivity-SCC-Location_ID).
 */

import { type Logger, noopLogger } from '../logger.js';
import { type BTPConfig, fetchClientCredentialsToken } from './vcap.js';

// ─── Types ───────────────────────────────────────────────────────────

/** Proxy configuration descriptor for the consumer's HTTP client / proxy agent */
export interface BTPProxyConfig {
  host: string;
  port: number;
  protocol: string;
  /** Returns a fresh connectivity proxy JWT token (cached, auto-refreshed) */
  getProxyToken: () => Promise<string>;
  /** Cloud Connector Location ID — sent as SAP-Connectivity-SCC-Location_ID header */
  locationId?: string;
}

// ─── Connectivity Proxy ──────────────────────────────────────────────

/**
 * Create a proxy configuration for routing through the Cloud Connector.
 *
 * Returns a BTPProxyConfig with a token getter that caches the connectivity
 * JWT and auto-refreshes it 60 seconds before expiry.
 */
export function createConnectivityProxy(
  btpConfig: BTPConfig,
  locationId?: string,
  logger: Logger = noopLogger,
): BTPProxyConfig | null {
  if (!btpConfig.connectivityProxyHost) return null;

  let cachedToken = '';
  let expiresAt = 0;

  return {
    host: btpConfig.connectivityProxyHost,
    port: Number.parseInt(btpConfig.connectivityProxyPort || '20003', 10),
    protocol: 'http',
    locationId,
    getProxyToken: async () => {
      // Return cached token if still valid (60s buffer)
      if (cachedToken && Date.now() < expiresAt) {
        return cachedToken;
      }

      logger.debug('Refreshing BTP connectivity proxy token', {
        tokenUrl: btpConfig.connectivityTokenUrl,
      });
      const { accessToken, expiresIn } = await fetchClientCredentialsToken(
        btpConfig.connectivityTokenUrl,
        btpConfig.connectivityClientId,
        btpConfig.connectivitySecret,
      );

      cachedToken = accessToken;
      expiresAt = Date.now() + (expiresIn - 60) * 1000;
      return cachedToken;
    },
  };
}

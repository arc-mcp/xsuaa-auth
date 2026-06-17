/**
 * BTP VCAP_SERVICES parsing + the shared client-credentials token helper.
 *
 * When running on SAP BTP Cloud Foundry, the bound service credentials arrive
 * via the VCAP_SERVICES environment variable. `parseVCAPServices` extracts the
 * XSUAA, Destination Service, and Connectivity Service (Cloud Connector proxy)
 * credentials into a flat {@link BTPConfig}.
 *
 * `fetchClientCredentialsToken` is the OAuth2 client_credentials token helper
 * shared by the Destination Service lookup and the connectivity proxy descriptor.
 */

import { type Logger, noopLogger } from '../logger.js';

// ─── Types ───────────────────────────────────────────────────────────

/** BTP service binding credentials parsed from VCAP_SERVICES */
export interface BTPConfig {
  // XSUAA
  xsuaaUrl: string;
  xsuaaClientId: string;
  xsuaaSecret: string;

  // Destination Service
  destinationUrl: string;
  destinationClientId: string;
  destinationSecret: string;
  destinationTokenUrl: string;

  // Connectivity Service (Cloud Connector proxy)
  connectivityProxyHost: string;
  connectivityProxyPort: string;
  connectivityClientId: string;
  connectivitySecret: string;
  connectivityTokenUrl: string;
}

// ─── VCAP Parsing ────────────────────────────────────────────────────

interface VCAPBinding {
  name: string;
  credentials: Record<string, unknown>;
}

interface VCAPServices {
  xsuaa?: VCAPBinding[];
  destination?: VCAPBinding[];
  connectivity?: VCAPBinding[];
}

/**
 * Parse VCAP_SERVICES environment variable to extract BTP service credentials.
 * Returns null if not running on BTP (VCAP_SERVICES not set).
 *
 * @param env - environment to read from (defaults to {@link process.env}, so it's testable)
 */
export function parseVCAPServices(env: NodeJS.ProcessEnv = process.env, logger: Logger = noopLogger): BTPConfig | null {
  const vcapJson = env.VCAP_SERVICES;
  if (!vcapJson) return null;

  const vcap: VCAPServices = JSON.parse(vcapJson);
  const config: BTPConfig = {
    xsuaaUrl: '',
    xsuaaClientId: '',
    xsuaaSecret: '',
    destinationUrl: '',
    destinationClientId: '',
    destinationSecret: '',
    destinationTokenUrl: '',
    connectivityProxyHost: '',
    connectivityProxyPort: '',
    connectivityClientId: '',
    connectivitySecret: '',
    connectivityTokenUrl: '',
  };

  // XSUAA binding
  if (vcap.xsuaa?.[0]?.credentials) {
    const c = vcap.xsuaa[0].credentials;
    config.xsuaaUrl = (c.url as string) || '';
    config.xsuaaClientId = (c.clientid as string) || '';
    config.xsuaaSecret = (c.clientsecret as string) || '';
  }

  // Destination binding
  if (vcap.destination?.[0]?.credentials) {
    const c = vcap.destination[0].credentials;
    config.destinationUrl = (c.uri as string) || (c.url as string) || '';
    config.destinationClientId = (c.clientid as string) || '';
    config.destinationSecret = (c.clientsecret as string) || '';
    config.destinationTokenUrl = (c.token_service_url as string) || '';
    // Fallback: construct from URL
    if (!config.destinationTokenUrl && c.url) {
      config.destinationTokenUrl = `${(c.url as string).replace(/\/$/, '')}/oauth/token`;
    }
  }

  // Connectivity binding
  if (vcap.connectivity?.[0]?.credentials) {
    const c = vcap.connectivity[0].credentials;
    config.connectivityProxyHost = (c.onpremise_proxy_host as string) || '';
    config.connectivityProxyPort = (c.onpremise_proxy_http_port as string) || '';
    config.connectivityClientId = (c.clientid as string) || '';
    config.connectivitySecret = (c.clientsecret as string) || '';
    config.connectivityTokenUrl = (c.token_service_url as string) || '';
    // Fallback + ensure /oauth/token suffix
    if (!config.connectivityTokenUrl && c.url) {
      config.connectivityTokenUrl = `${(c.url as string).replace(/\/$/, '')}/oauth/token`;
    } else if (config.connectivityTokenUrl && !config.connectivityTokenUrl.endsWith('/oauth/token')) {
      config.connectivityTokenUrl = `${config.connectivityTokenUrl.replace(/\/$/, '')}/oauth/token`;
    }
  }

  logger.info('BTP VCAP_SERVICES parsed', {
    hasXsuaa: !!config.xsuaaUrl,
    hasDestination: !!config.destinationUrl,
    hasConnectivity: !!config.connectivityProxyHost,
  });

  return config;
}

// ─── Shared OAuth2 client_credentials token helper ───────────────────

/**
 * Fetch an OAuth2 client_credentials token.
 * Used for both Destination Service and Connectivity Service tokens.
 */
export async function fetchClientCredentialsToken(
  tokenUrl: string,
  clientId: string,
  clientSecret: string,
): Promise<{ accessToken: string; expiresIn: number }> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
  });

  const resp = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token endpoint returned HTTP ${resp.status}: ${text.slice(0, 200)}`);
  }

  const data = (await resp.json()) as { access_token: string; expires_in: number };
  return { accessToken: data.access_token, expiresIn: data.expires_in };
}

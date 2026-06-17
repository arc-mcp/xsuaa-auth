/**
 * `@arc-mcp/xsuaa-auth/btp` — Principal-propagation entrypoint (SPEC §7).
 *
 * BTP destination lookup, per-user PP token exchange, and the Cloud Connector
 * connectivity-proxy descriptor. Lifted near-verbatim from arc-1 `src/adt/btp.ts`;
 * the only refactor is the logger seam (optional trailing `logger?` param,
 * default no-op) plus the JWT-shape guard on `lookupDestinationWithUserToken`.
 *
 * The package returns credentials + a proxy descriptor; it never applies them.
 * The consumer's SAP HTTP client owns header assembly and proxy requests.
 *
 * Note: `fetchClientCredentialsToken` (in `./btp/vcap.js`) is an internal helper
 * shared by the lookup + proxy modules and is intentionally NOT part of the public
 * surface frozen in SPEC §7.
 */

export type { BTPProxyConfig } from './btp/connectivity.js';
export { createConnectivityProxy } from './btp/connectivity.js';
export type { Destination, PerUserAuthTokens } from './btp/destination.js';
export { lookupDestination, lookupDestinationWithUserToken, resolveBTPDestination } from './btp/destination.js';
export type { BTPConfig } from './btp/vcap.js';
export { parseVCAPServices } from './btp/vcap.js';

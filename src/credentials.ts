/**
 * Layer-0 plug-and-play config helpers: read the bound XSUAA service credentials
 * and resolve the public app URL from the Cloud Foundry environment.
 *
 * `loadXsuaaCredentials` parses `VCAP_SERVICES` directly (no `@sap/xsenv`
 * dependency); `resolveAppUrl` ports arc-1's `getAppUrl` (VCAP_APPLICATION route)
 * with a configurable public-URL override env var and a port-only fallback.
 */

import type { XsuaaCredentials } from './xsuaa.js';

// Minimal structural views of the CF env JSON we read.
interface VcapXsuaaBinding {
  credentials?: Record<string, unknown>;
}
interface VcapServicesShape {
  xsuaa?: VcapXsuaaBinding[];
}
interface VcapApplicationShape {
  application_uris?: unknown;
  uris?: unknown;
}

/**
 * Read + validate the bound XSUAA service credentials from `VCAP_SERVICES`.
 *
 * Finds the first `xsuaa` binding and maps its `credentials` to
 * {@link XsuaaCredentials}. Throws a clear Error if `VCAP_SERVICES` is absent /
 * unparseable, if there is no `xsuaa` binding, or if a required field
 * (`url`/`clientid`/`clientsecret`/`xsappname`/`uaadomain`) is missing.
 *
 * @param env Environment to read from (defaults to {@link process.env}).
 */
export function loadXsuaaCredentials(env: NodeJS.ProcessEnv = process.env): XsuaaCredentials {
  const raw = env.VCAP_SERVICES;
  if (!raw) {
    throw new Error('loadXsuaaCredentials: VCAP_SERVICES is not set — is the app bound to an XSUAA service on CF?');
  }

  let vcap: VcapServicesShape;
  try {
    vcap = JSON.parse(raw) as VcapServicesShape;
  } catch (err) {
    throw new Error(`loadXsuaaCredentials: VCAP_SERVICES is not valid JSON: ${(err as Error).message}`);
  }

  const binding = vcap.xsuaa?.[0];
  if (!binding?.credentials) {
    throw new Error(
      'loadXsuaaCredentials: no `xsuaa` binding found in VCAP_SERVICES — bind an XSUAA service instance.',
    );
  }

  const c = binding.credentials;
  const required = ['url', 'clientid', 'clientsecret', 'xsappname', 'uaadomain'] as const;
  const missing = required.filter((k) => typeof c[k] !== 'string' || (c[k] as string).length === 0);
  if (missing.length > 0) {
    throw new Error(`loadXsuaaCredentials: XSUAA binding is missing required field(s): ${missing.join(', ')}`);
  }

  return {
    url: c.url as string,
    clientid: c.clientid as string,
    clientsecret: c.clientsecret as string,
    xsappname: c.xsappname as string,
    uaadomain: c.uaadomain as string,
    verificationkey: typeof c.verificationkey === 'string' ? c.verificationkey : undefined,
  };
}

/**
 * Resolve the public URL the server advertises in OAuth metadata.
 *
 * Precedence:
 *   1. `env[options.publicUrlEnvVar]` (when `publicUrlEnvVar` is set and the var
 *      has a value) — set this when reached through a reverse proxy on a
 *      different host/base-path than the CF route. The trailing slash is stripped.
 *   2. First `https://` URI from `VCAP_APPLICATION.application_uris` (CF route).
 *   3. `http://localhost:${options.port ?? 8080}` (port-only fallback).
 *
 * @param env Environment to read from (defaults to {@link process.env}).
 */
export function resolveAppUrl(
  env: NodeJS.ProcessEnv = process.env,
  options: { publicUrlEnvVar?: string; port?: number } = {},
): string {
  // 1. Explicit public-URL override (e.g. ARC1_PUBLIC_URL).
  if (options.publicUrlEnvVar) {
    const override = env[options.publicUrlEnvVar]?.trim();
    if (override) {
      return override.replace(/\/$/, '');
    }
  }

  // 2. CF route from VCAP_APPLICATION.
  const vcapApp = env.VCAP_APPLICATION;
  if (vcapApp) {
    try {
      const app = JSON.parse(vcapApp) as VcapApplicationShape;
      const uris = app.application_uris ?? app.uris;
      if (Array.isArray(uris)) {
        const first = uris.find((u): u is string => typeof u === 'string' && u.length > 0);
        if (first) {
          // VCAP routes are bare hostnames; CF terminates TLS, so advertise https.
          return first.startsWith('http://') || first.startsWith('https://')
            ? first.replace(/\/$/, '')
            : `https://${first}`;
        }
      }
    } catch {
      // Not valid JSON — fall through to the port-only default.
    }
  }

  // 3. Port-only fallback.
  return `http://localhost:${options.port ?? 8080}`;
}

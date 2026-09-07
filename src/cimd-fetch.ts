/**
 * SSRF-hardened fetcher for OAuth Client ID Metadata Documents (CIMD, SEP-991).
 *
 * ── Why this module exists, and why it is paranoid ──
 * CIMD makes the `client_id` an HTTPS URL that the CLIENT hosts and the authorization
 * server fetches. That hands an unauthenticated caller, on the pre-authentication
 * `/authorize` path, the power to make this process issue an outbound request to a URL
 * of their choosing. arc-1 deploys on BTP Cloud Foundry beside a **Cloud Connector**,
 * whose whole purpose is to make otherwise unreachable on-premises SAP networks
 * reachable from the application — so an SSRF primitive here does not stop at cloud
 * metadata, it potentially reaches a customer's on-premises landscape.
 *
 * This module is therefore deliberately strict and single-purpose. It is NOT a general
 * HTTP client and must not become one: no other caller, no other content type, no
 * credentials, no redirects, no reuse.
 *
 * ── What it guarantees ──
 *  1. `https` only. There is no "allow http in development" switch, because that switch
 *     is the vulnerability.
 *  2. No userinfo, no fragment, a path is required, no dot segments (draft §Client
 *     Identifier URL).
 *  3. DNS is resolved ONCE, **every** returned address is validated, and the connection
 *     is PINNED to a validated address via a custom `lookup`. Validating a hostname and
 *     then letting the stack re-resolve is a textbook TOCTOU (DNS rebinding). The IETF
 *     draft does not ask for pinning — it states the requirement as an outcome ("MUST
 *     NOT fetch … that resolve to special-use IP addresses") — so this is a deliberate
 *     hardening beyond the specification, not a conformance item.
 *  4. Every RFC 6890 special-use range is blocked, IPv4 and IPv6, including both textual
 *     forms of IPv4-mapped IPv6 and the v4-embedding transition prefixes (6to4, Teredo,
 *     NAT64).
 *  5. Redirects are refused outright. Following one is the classic bypass, and a followed
 *     redirect is of little use anyway: the draft requires the document's `client_id` to
 *     equal the ORIGINAL URL.
 *  6. Connect deadline, global deadline, and a response-size cap enforced **while
 *     streaming** — never after buffering.
 *  7. The request carries no cookie, no `Authorization`, no ambient credential, and asks
 *     for no compression (a decompression bomb must not be reachable).
 *
 * ── What it deliberately does NOT do ──
 * It does not parse, validate, or interpret the document; that is the caller's job. It
 * does not dereference any URL found inside a document — the draft's SSRF rule extends to
 * `logo_uri`/`jwks_uri`/… and this package answers that by never fetching them at all.
 *
 * ── Forward proxies, without giving away the pin ──
 * Handing a hostname to a proxy would destroy every guarantee above: the proxy, not this
 * process, would resolve the name and choose the peer, so a `CONNECT` aimed at an internal
 * host would sail past the address checks. Naive proxy support is therefore not an option.
 *
 * What this module does instead is resolve and validate the address ITSELF, then ask the
 * proxy for a tunnel to that **IP** — `CONNECT 93.184.216.34:443`, never
 * `CONNECT client.example.com:443`. The proxy resolves nothing and substitutes nothing; it
 * only opens a pipe to an address this process already approved. TLS is then terminated
 * here, inside the tunnel, with SNI and certificate validation bound to the real hostname.
 * The pin survives the proxy.
 *
 * Two consequences operators must know:
 *  - A proxy that refuses `CONNECT` to a bare IP (many policy-enforcing proxies do, because
 *    their filtering wants a name) cannot be used. That surfaces as `proxy_refused`, not as
 *    a silent downgrade.
 *  - A TLS-INTERCEPTING proxy will fail certificate validation, because the certificate
 *    presented is the interceptor's. That is the correct outcome: failing is better than
 *    trusting an interceptor. Such a deployment must trust the interception CA at the
 *    process level (`NODE_EXTRA_CA_CERTS`) as an explicit operator decision.
 *
 * The proxy address itself is deliberately NOT subject to the special-use block. A
 * corporate proxy legitimately lives on 10.x or 127.0.0.1, and it is operator-configured
 * rather than attacker-chosen — the untrusted input here is the TARGET, never the proxy.
 *
 * ── Error discipline ──
 * A failure carries ONLY a reason code from a closed vocabulary. No exception text, no
 * resolved address, no hostname, no port ever travels back to the caller, so no network
 * topology can leak into an OAuth error response. Callers map every failure to the same
 * opaque outcome; the reason exists for the operator's audit trail.
 *
 * Range vectors are shared with arc-1's `validateGitRemoteUrl` / `literalHostIsPrivate`
 * (`src/adt/abapgit.ts`), which solves the neighbouring "SAP is about to call this URL"
 * problem. That helper checks a LITERAL hostname only; it never resolves DNS and never
 * pins, which is sufficient there and is not sufficient here.
 */

import { lookup as dnsLookupCb } from 'node:dns';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction, Socket } from 'node:net';
import { isIP, connect as netConnect } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { connect as tlsConnect } from 'node:tls';

/**
 * Closed vocabulary of refusal reasons. Audit-only — never surfaced to the OAuth client.
 *
 * `blocked_address` in particular confirms that a name resolved into a special-use range,
 * which is exactly the kind of probe signal an attacker would like back. It reaches the
 * audit sink and stops there.
 */
export type CimdFetchFailureReason =
  /** Not an `https:` URL. */
  | 'scheme'
  /** URL carried a `user[:pass]@` component. */
  | 'userinfo'
  /** Unparseable, no path, a fragment, or a `.`/`..` path segment. */
  | 'shape'
  /** Hostname is a loopback/internal-only name (`localhost`, `*.internal`, `*.local`, …). */
  | 'blocked_host'
  /** A host allowlist is configured and this host is not on it. Refused before any DNS or socket. */
  | 'host_not_allowed'
  /** Name did not resolve. */
  | 'dns_failure'
  /** At least one resolved address is in an RFC 6890 special-use range. */
  | 'blocked_address'
  /** Server answered 3xx. Redirects are never followed. */
  | 'redirect_refused'
  /** TLS handshake or certificate validation failed. */
  | 'tls_failure'
  /** Connect deadline or global deadline elapsed. */
  | 'timeout'
  /** Body exceeded the size cap (detected while streaming). */
  | 'too_large'
  /** Any status other than exactly 200 (draft requires 200 OK). */
  | 'bad_status'
  /** Missing or non-JSON `Content-Type`. */
  | 'bad_content_type'
  /** Response was compressed although no compression was requested. */
  | 'content_encoding_refused'
  /** Socket-level failure (refused, reset, unreachable). */
  | 'network_error'
  /** `proxyUrl` is not a usable absolute http(s) URL. Operator misconfiguration. */
  | 'proxy_config_invalid'
  /** The configured proxy could not be reached. */
  | 'proxy_unreachable'
  /** The proxy answered the CONNECT with a non-2xx status, or spoke it badly. */
  | 'proxy_refused';

export interface CimdFetchSuccess {
  ok: true;
  /**
   * Raw response body, bounded by `maxBytes`. NOT parsed and NOT validated — the caller
   * owns document validation (the `client_id`-equals-URL rule, redirect URIs, and the
   * rest of the draft's metadata requirements).
   */
  body: string;
  /** Raw `Cache-Control`, for the caller's RFC 9111 handling. Absent when not sent. */
  cacheControl?: string;
  /** Raw `Expires`, for the caller's RFC 9111 handling. Absent when not sent. */
  expires?: string;
  /** The validated address the document was actually fetched from. Audit only. */
  resolvedAddress: string;
}

export interface CimdFetchFailure {
  ok: false;
  reason: CimdFetchFailureReason;
}

export type CimdFetchResult = CimdFetchSuccess | CimdFetchFailure;

export interface CimdFetchOptions {
  /**
   * Optional host allowlist. Empty or omitted means open — which is the intended posture
   * once an operator has opted into CIMD at all, because a server that must list every
   * client in advance has reimplemented registration with extra steps.
   *
   * Entries are exact hosts (`claude.ai`) or single-label wildcards (`*.vscode.dev`,
   * which matches `a.vscode.dev` but neither `vscode.dev` nor `a.b.vscode.dev`).
   * Matching is against the parsed, lowercased hostname — never a substring test.
   */
  allowedHosts?: readonly string[];
  /** Milliseconds allowed to establish the TLS connection. Default 2000. */
  connectTimeoutMs?: number;
  /** Milliseconds allowed for the whole operation, connect included. Default 5000. */
  globalTimeoutMs?: number;
  /** Response-size cap in bytes, enforced while streaming. Default 5120 (draft §5 KiB). */
  maxBytes?: number;
  /**
   * Absolute URL of a forward proxy to tunnel through, e.g. `http://proxy.corp:3128` or
   * `http://user:pass@proxy.corp:3128`. Omitted means connect directly.
   *
   * Deliberately an explicit option rather than an implicit read of `HTTPS_PROXY`: whether
   * outbound traffic is proxied is a deployment policy the consumer owns, and a transport
   * that silently changes shape because an environment variable happens to be set is the
   * kind of surprise this module exists to avoid. Consumers that DO want the environment's
   * setting can opt in with {@link proxyFromEnvironment}.
   */
  proxyUrl?: string;
}

/**
 * Signature shared by `https.request` and `http.request` in their `(url, options, cb)` form.
 * Options are typed as the HTTPS superset so `servername` (SNI) is expressible; `http.request`
 * accepts the wider `ClientRequestArgs` and so satisfies this contravariantly.
 */
export type RequestImpl = (
  url: URL,
  options: RequestOptions,
  callback: (res: IncomingMessage) => void,
) => ClientRequest;

const DEFAULT_CONNECT_TIMEOUT_MS = 2_000;
const DEFAULT_GLOBAL_TIMEOUT_MS = 5_000;
/** The draft's recommended maximum read size is 5 kilobytes. */
const DEFAULT_MAX_BYTES = 5_120;

/**
 * Hostname suffixes that are internal by convention and must never be dereferenced,
 * refused before DNS so a resolver trick cannot even be attempted. `localhost` is
 * included as a bare name as well as a suffix.
 */
const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.svc.cluster.local', '.home.arpa'] as const;

// ─── Address classification (RFC 6890 special-use registries) ─────────

/** Parse a dotted-quad into its four octets, or null if it is not one. */
function parseIpv4(value: string): number[] | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    // Reject empty, non-numeric, and zero-padded forms (`010` is octal in some parsers).
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/**
 * IPv4 special-use ranges, as `[a, b, c, d, prefixLength]`. Sourced from the RFC 6890
 * IANA registry; the private/loopback/link-local/CGNAT entries mirror arc-1's
 * `literalHostIsPrivate`, and the remainder close the ranges that helper does not need.
 */
const IPV4_BLOCKED: ReadonlyArray<readonly [number, number, number, number, number]> = [
  [0, 0, 0, 0, 8], // "this host on this network"
  [10, 0, 0, 0, 8], // private
  [100, 64, 0, 0, 10], // carrier-grade NAT
  [127, 0, 0, 0, 8], // loopback
  [169, 254, 0, 0, 16], // link-local — includes the 169.254.169.254 metadata service
  [172, 16, 0, 0, 12], // private
  [192, 0, 0, 0, 24], // IETF protocol assignments
  [192, 0, 2, 0, 24], // TEST-NET-1
  [192, 88, 99, 0, 24], // 6to4 relay anycast (deprecated)
  [192, 168, 0, 0, 16], // private
  [198, 18, 0, 0, 15], // benchmarking
  [198, 51, 100, 0, 24], // TEST-NET-2
  [203, 0, 113, 0, 24], // TEST-NET-3
  [224, 0, 0, 0, 4], // multicast
  [240, 0, 0, 0, 4], // reserved, including 255.255.255.255
];

function ipv4ToInt(octets: readonly number[]): number {
  return (((octets[0] ?? 0) << 24) | ((octets[1] ?? 0) << 16) | ((octets[2] ?? 0) << 8) | (octets[3] ?? 0)) >>> 0;
}

function isBlockedIpv4(octets: readonly number[]): boolean {
  const addr = ipv4ToInt(octets);
  for (const [a, b, c, d, prefix] of IPV4_BLOCKED) {
    // `<<< 32` is undefined in JS; no entry uses /0, so the shift is always safe here.
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    if ((addr & mask) === (ipv4ToInt([a, b, c, d]) & mask)) return true;
  }
  return false;
}

/**
 * Expand an IPv6 literal into its eight hextets, handling `::` compression, an optional
 * zone index, and a trailing embedded IPv4 (`::ffff:127.0.0.1`, `64:ff9b::192.0.2.1`).
 * Returns null when the input is not a valid IPv6 address.
 *
 * Numeric expansion rather than string matching is deliberate: `::ffff:127.0.0.1` and
 * `::ffff:7f00:1` are the same address wearing different clothes, and a regex over the
 * text form has to know every disguise. Expanding first means each range is tested once.
 */
function parseIpv6(input: string): number[] | null {
  let value = input;
  const zone = value.indexOf('%');
  if (zone !== -1) value = value.slice(0, zone);

  // A trailing dotted-quad supplies the low 32 bits.
  let embeddedV4: number[] | null = null;
  const lastColon = value.lastIndexOf(':');
  if (lastColon !== -1 && value.slice(lastColon + 1).includes('.')) {
    embeddedV4 = parseIpv4(value.slice(lastColon + 1));
    if (!embeddedV4) return null;
    value = value.slice(0, lastColon + 1);
    // Re-express the embedded IPv4 as two hextets so the rest is uniform.
    value += `${(((embeddedV4[0] ?? 0) << 8) | (embeddedV4[1] ?? 0)).toString(16)}:${(
      ((embeddedV4[2] ?? 0) << 8) | (embeddedV4[3] ?? 0)
    ).toString(16)}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;

  const toHextets = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const piece of part.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      out.push(Number.parseInt(piece, 16));
    }
    return out;
  };

  if (halves.length === 1) {
    const all = toHextets(halves[0] ?? '');
    return all && all.length === 8 ? all : null;
  }

  const head = toHextets(halves[0] ?? '');
  const tail = toHextets(halves[1] ?? '');
  if (!head || !tail) return null;
  const gap = 8 - head.length - tail.length;
  if (gap < 1) return null;
  return [...head, ...Array<number>(gap).fill(0), ...tail];
}

function isBlockedIpv6(hextets: readonly number[]): boolean {
  const [h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0] = hextets;
  const topFiveZero = h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0;
  const embeddedV4 = (hi: number, lo: number): number[] => [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff];

  // Unspecified (::) and loopback (::1).
  if (topFiveZero && h5 === 0 && h6 === 0 && (h7 === 0 || h7 === 1)) return true;
  // IPv4-mapped ::ffff:0:0/96 — the address a dual-stack connect actually uses.
  if (topFiveZero && h5 === 0xffff) return isBlockedIpv4(embeddedV4(h6, h7));
  // IPv4-compatible ::/96 (deprecated but still parsed by some stacks).
  if (topFiveZero && h5 === 0) return isBlockedIpv4(embeddedV4(h6, h7));
  // NAT64 well-known prefix 64:ff9b::/96 — carries a v4 destination.
  if (h0 === 0x0064 && h1 === 0xff9b && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0) {
    return isBlockedIpv4(embeddedV4(h6, h7));
  }
  // 6to4 2002::/16 and Teredo 2001::/32 both tunnel to an embedded v4 destination, so
  // neither can be trusted to stay off the internal network. Refuse the prefixes whole.
  if (h0 === 0x2002) return true;
  if (h0 === 0x2001 && h1 === 0x0000) return true;
  if (h0 === 0x2001 && h1 === 0x0002 && h2 === 0x0000) return true; // benchmarking
  if (h0 === 0x2001 && h1 === 0x0db8) return true; // documentation
  if (h0 === 0x0100 && h1 === 0 && h2 === 0 && h3 === 0) return true; // discard-only
  if ((h0 & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((h0 & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((h0 & 0xff00) === 0xff00) return true; // multicast ff00::/8
  return false;
}

/**
 * True when `address` is in any RFC 6890 special-use range and must not be connected to.
 * Anything that does not parse as an IP is also refused: an unparseable address is not a
 * safe address, it is an unknown one.
 */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const octets = parseIpv4(address);
    return octets ? isBlockedIpv4(octets) : true;
  }
  if (family === 6) {
    const hextets = parseIpv6(address);
    return hextets ? isBlockedIpv6(hextets) : true;
  }
  return true;
}

// ─── URL shape + host admission ───────────────────────────────────────

/**
 * True when the RAW URL string carries a `.` or `..` path segment, including
 * percent-encoded spellings.
 *
 * This has to work on the raw input, not on `URL.pathname`: the WHATWG parser RESOLVES
 * dot segments while parsing, so `https://x/a/../b` arrives as `/b` and a check against
 * the parsed path would silently pass something the draft forbids. That silent rewrite is
 * itself the hazard — the identity is compared by simple string comparison against the
 * document's own `client_id`, so a URL that means something different after parsing than
 * it said before it cannot be a stable identity.
 */
function hasDotSegments(raw: string): boolean {
  const schemeEnd = raw.indexOf('://');
  if (schemeEnd === -1) return false;
  const afterAuthority = raw.slice(schemeEnd + 3);
  const pathStart = afterAuthority.search(/[/?#]/);
  if (pathStart === -1) return false;
  const rawPath = afterAuthority.slice(pathStart).split(/[?#]/)[0] ?? '';
  return rawPath.split('/').some((segment) => {
    const decoded = segment.replace(/%2e/gi, '.');
    return decoded === '.' || decoded === '..';
  });
}

/** Strip the root label so `foo.localhost.` is treated as `foo.localhost`. */
function normalizeHost(hostname: string): string {
  return hostname.replace(/\.+$/, '').toLowerCase();
}

/**
 * Unwrap an IPv6 literal hostname. `URL.hostname` keeps the brackets (`[::1]`), which
 * neither `isIP` nor `dns.lookup` accepts, so a literal target would otherwise reach the
 * resolver and come back as a confusing `dns_failure` instead of a precise refusal.
 */
function unwrapIpLiteral(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/**
 * Validate a Client Identifier URL's shape. Returns the parsed URL or a refusal reason.
 *
 * Exported for the caller's own pre-checks: classifying a `client_id` as CIMD and
 * validating its shape are the same decision, and doing it twice in two places is how
 * the two copies drift apart.
 */
export function validateClientIdUrl(
  raw: string,
  allowedHosts?: readonly string[],
): { ok: true; url: URL } | CimdFetchFailure {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'shape' };
  }
  if (url.protocol !== 'https:') return { ok: false, reason: 'scheme' };
  if (url.username !== '' || url.password !== '') return { ok: false, reason: 'userinfo' };
  // `URL` keeps the fragment in `hash`; the draft forbids one, and a fragment is never
  // sent on the wire anyway, so accepting it would silently change the identity.
  if (url.hash !== '') return { ok: false, reason: 'shape' };
  // A path is required, which also matches the SDK client's own `isHttpsUrl` gate.
  if (url.pathname === '' || url.pathname === '/') return { ok: false, reason: 'shape' };
  if (hasDotSegments(raw)) return { ok: false, reason: 'shape' };

  const host = normalizeHost(url.hostname);
  if (host === '' || host === 'localhost') return { ok: false, reason: 'blocked_host' };
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) return { ok: false, reason: 'blocked_host' };

  // An IP-literal target is settled here rather than at the resolver: it needs no lookup,
  // and refusing it pre-DNS gives the accurate reason instead of a puzzling `dns_failure`.
  const literal = unwrapIpLiteral(host);
  if (isIP(literal) !== 0 && isBlockedAddress(literal)) return { ok: false, reason: 'blocked_host' };

  if (!hostAllowed(host, allowedHosts)) return { ok: false, reason: 'host_not_allowed' };
  return { ok: true, url };
}

/**
 * Exact host or single-label wildcard match against the parsed hostname. An empty or
 * omitted list means open.
 *
 * Never a substring test: `evil-claude.ai` must not satisfy an entry of `claude.ai`.
 */
export function hostAllowed(hostname: string, allowedHosts?: readonly string[]): boolean {
  if (!allowedHosts || allowedHosts.length === 0) return true;
  const host = normalizeHost(hostname);
  for (const raw of allowedHosts) {
    const entry = normalizeHost(raw.trim());
    if (entry === '') continue;
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1); // ".vscode.dev"
      if (!host.endsWith(suffix)) continue;
      const label = host.slice(0, host.length - suffix.length);
      // Exactly one label, and a real one — `*.x.dev` covers `a.x.dev`, not `a.b.x.dev`
      // and not the bare `x.dev`.
      if (label !== '' && !label.includes('.')) return true;
      continue;
    }
    if (host === entry) return true;
  }
  return false;
}

/**
 * Read a proxy URL from the environment the way the surrounding ecosystem expects
 * (`HTTPS_PROXY`/`https_proxy`, with `NO_PROXY`/`no_proxy` exclusions), for consumers that
 * want to opt into the environment's setting.
 *
 * Provided as a helper rather than applied automatically: see the note on
 * {@link CimdFetchOptions.proxyUrl}. A `NO_PROXY` entry of `*` disables proxying entirely;
 * other entries match the host exactly or as a dot-suffix (`.corp` covers `a.corp`).
 */
export function proxyFromEnvironment(
  targetHost: string,
  env: Record<string, string | undefined> = process.env,
): string | undefined {
  const proxy = env.HTTPS_PROXY ?? env.https_proxy;
  if (!proxy || proxy.trim() === '') return undefined;

  const noProxy = env.NO_PROXY ?? env.no_proxy ?? '';
  const host = normalizeHost(targetHost);
  for (const rawEntry of noProxy.split(',')) {
    const entry = normalizeHost(rawEntry.trim());
    if (entry === '') continue;
    if (entry === '*') return undefined;
    const suffix = entry.startsWith('.') ? entry : `.${entry}`;
    if (host === entry.replace(/^\./, '') || host.endsWith(suffix)) return undefined;
  }
  return proxy.trim();
}

// ─── The fetch ────────────────────────────────────────────────────────

const dnsLookupAll = (hostname: string): Promise<Array<{ address: string; family: number }>> =>
  new Promise((resolve, reject) => {
    dnsLookupCb(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) reject(err);
      else resolve(addresses);
    });
  });

function isJsonContentType(raw: string | undefined): boolean {
  if (!raw) return false;
  const mediaType = raw.split(';')[0]?.trim().toLowerCase() ?? '';
  return mediaType === 'application/json' || /^application\/[a-z0-9!#$&^_.+-]*\+json$/.test(mediaType);
}

/**
 * Fetch a Client ID Metadata Document with every control in the module header applied.
 *
 * Never throws: every failure — including a programming error inside the request path —
 * comes back as a `CimdFetchFailure`, because a thrown exception on the `/authorize` path
 * would carry a stack and a message into an error response.
 */
export async function fetchClientIdMetadataDocument(
  clientIdUrl: string,
  options: CimdFetchOptions = {},
): Promise<CimdFetchResult> {
  const connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
  const globalTimeoutMs = options.globalTimeoutMs ?? DEFAULT_GLOBAL_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  const shape = validateClientIdUrl(clientIdUrl, options.allowedHosts);
  if (!shape.ok) return shape;
  const url = shape.url;

  // Resolve once. `dns.lookup` (not `resolve4`/`resolve6`) is deliberate: it is the same
  // path `net.connect` would take, so what we validate is what would have been dialled —
  // including any /etc/hosts entry.
  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await dnsLookupAll(url.hostname);
  } catch {
    return { ok: false, reason: 'dns_failure' };
  }
  if (addresses.length === 0) return { ok: false, reason: 'dns_failure' };

  // Refuse if ANY answer is blocked, not merely if the one we would pick is. A name that
  // resolves to a public and a private address is a rebinding attempt wearing a disguise,
  // and cherry-picking the acceptable answer would reward it.
  if (addresses.some((entry) => isBlockedAddress(entry.address))) {
    return { ok: false, reason: 'blocked_address' };
  }

  const pinned = addresses[0];
  if (!pinned) return { ok: false, reason: 'dns_failure' };

  if (options.proxyUrl !== undefined && options.proxyUrl.trim() !== '') {
    const startedAt = Date.now();
    const tunnel = await establishProxyTunnel(
      options.proxyUrl,
      {
        address: pinned.address,
        port: Number(url.port || 443),
        servername: url.hostname,
      },
      connectTimeoutMs,
    );
    if (!tunnel.ok) return tunnel;

    // The tunnel's cost comes out of the same overall budget, so a slow proxy cannot buy
    // the request a second full deadline.
    const remaining = globalTimeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) {
      tunnel.socket.destroy();
      return { ok: false, reason: 'timeout' };
    }
    return await performPinnedRequest(
      url,
      pinned,
      { connectTimeoutMs, globalTimeoutMs: remaining, maxBytes },
      httpsRequest,
      () => tunnel.socket,
    );
  }

  return await performPinnedRequest(url, pinned, { connectTimeoutMs, globalTimeoutMs, maxBytes });
}

/**
 * Open a CONNECT tunnel through `proxyUrl` to the already-validated `address:port`, then
 * complete the TLS handshake for `servername` inside it.
 *
 * The CONNECT target is the validated IP, never the hostname — that is the entire point.
 * The proxy therefore performs no resolution and cannot substitute a peer, so the pin
 * established before this call still holds on the far side of it.
 */
export function establishProxyTunnel(
  proxyUrl: string,
  target: { address: string; port: number; servername: string },
  timeoutMs: number,
): Promise<{ ok: true; socket: TLSSocket } | CimdFetchFailure> {
  return new Promise((resolve) => {
    let proxy: URL;
    try {
      proxy = new URL(proxyUrl);
    } catch {
      resolve({ ok: false, reason: 'proxy_config_invalid' });
      return;
    }
    if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
      resolve({ ok: false, reason: 'proxy_config_invalid' });
      return;
    }
    const proxyPort = Number(proxy.port || (proxy.protocol === 'https:' ? 443 : 80));
    if (!Number.isInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65535) {
      resolve({ ok: false, reason: 'proxy_config_invalid' });
      return;
    }

    let settled = false;
    let raw: Socket | undefined;
    let tls: TLSSocket | undefined;
    const timer = setTimeout(() => finish({ ok: false, reason: 'timeout' }), timeoutMs);

    const finish = (result: { ok: true; socket: TLSSocket } | CimdFetchFailure): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!result.ok) {
        tls?.destroy();
        raw?.destroy();
      }
      resolve(result);
    };

    // The proxy is operator-configured infrastructure, so its address is intentionally
    // exempt from the special-use block that governs the attacker-chosen target.
    raw = netConnect({ host: proxy.hostname, port: proxyPort });
    raw.on('error', () => finish({ ok: false, reason: 'proxy_unreachable' }));

    raw.on('connect', () => {
      const authority = `${target.address}:${target.port}`;
      const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
      if (proxy.username !== '' || proxy.password !== '') {
        // Credentials for the operator's OWN proxy. They ride the CONNECT only and never
        // enter the tunnel, so the request to the client's host stays unauthenticated.
        const creds = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
        lines.push(`Proxy-Authorization: Basic ${Buffer.from(creds, 'utf8').toString('base64')}`);
      }
      raw?.write(`${lines.join('\r\n')}\r\n\r\n`);
    });

    let head = '';
    const onData = (chunk: Buffer): void => {
      head += chunk.toString('binary');
      // Bound the handshake buffer; a proxy that streams headers forever is refused.
      if (head.length > 8192) {
        finish({ ok: false, reason: 'proxy_refused' });
        return;
      }
      const end = head.indexOf('\r\n\r\n');
      if (end === -1) return;
      raw?.removeListener('data', onData);

      const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1] ?? 0);
      if (status < 200 || status > 299) {
        finish({ ok: false, reason: 'proxy_refused' });
        return;
      }
      // Nothing may follow the CONNECT response: the tunnel is ours from here, and bytes
      // the proxy injected ahead of our TLS ClientHello are a protocol violation.
      if (head.length > end + 4) {
        finish({ ok: false, reason: 'proxy_refused' });
        return;
      }

      if (!raw) {
        finish({ ok: false, reason: 'proxy_unreachable' });
        return;
      }
      // Terminate TLS ourselves, bound to the REAL hostname, so SNI and certificate
      // validation are exactly what they would have been on a direct connection.
      tls = tlsConnect({ socket: raw, servername: target.servername, host: target.servername });
      tls.on('error', () => finish({ ok: false, reason: 'tls_failure' }));
      tls.on('secureConnect', () => {
        if (tls) finish({ ok: true, socket: tls });
      });
    };
    raw.on('data', onData);
  });
}

/**
 * The transport half: issue the pinned request and run the response state machine.
 *
 * `requestImpl` exists so tests can drive the whole state machine — status handling,
 * content-type, compression refusal, the streaming size cap, both deadlines, and the pin
 * itself — against a local server. It is NOT a security switch: a caller cannot reach
 * this function with an `http:` URL or a special-use address, because
 * `fetchClientIdMetadataDocument` gates both before calling, and `https:` is enforced in
 * `validateClientIdUrl`. Production never passes this argument.
 *
 * `createConnection` supplies an already-connected transport, which is how the proxy path
 * hands over its TLS-over-CONNECT socket. When it is present the pin has already been
 * enforced by the CONNECT target, so no `lookup` is installed.
 *
 * Exported for tests only; deliberately not re-exported from `index.ts`.
 */
export function performPinnedRequest(
  url: URL,
  pinned: { address: string; family: number },
  limits: { connectTimeoutMs: number; globalTimeoutMs: number; maxBytes: number },
  requestImpl: RequestImpl = httpsRequest,
  createConnection?: () => Socket,
): Promise<CimdFetchResult> {
  return new Promise<CimdFetchResult>((resolve) => {
    let settled = false;
    let globalTimer: NodeJS.Timeout | undefined;
    let connectTimer: NodeJS.Timeout | undefined;

    const settle = (result: CimdFetchResult): void => {
      if (settled) return;
      settled = true;
      if (globalTimer) clearTimeout(globalTimer);
      if (connectTimer) clearTimeout(connectTimer);
      req.destroy();
      resolve(result);
    };

    // Always hand back the address we already validated, whatever hostname is asked for.
    // This is the pin: the stack never gets a second chance to resolve, so the answer
    // cannot change between the check and the connect.
    const pinnedLookup: LookupFunction = (_hostname, opts, callback) => {
      if (typeof opts === 'object' && opts !== null && opts.all === true) {
        callback(null, [{ address: pinned.address, family: pinned.family }]);
      } else {
        callback(null, pinned.address, pinned.family);
      }
    };

    const req = requestImpl(
      url,
      {
        method: 'GET',
        ...(createConnection ? { createConnection } : { lookup: pinnedLookup }),
        // SNI and certificate validation stay bound to the real hostname — pinning
        // changes which address we dial, never whether the certificate must match.
        servername: url.hostname,
        // No connection reuse. A pooled keep-alive socket would outlive the validation
        // that authorised it, quietly reintroducing the TOCTOU the pin just closed.
        agent: false,
        headers: {
          accept: 'application/json',
          // Refuse compression rather than defend against a decompression bomb.
          'accept-encoding': 'identity',
          'user-agent': 'arc-mcp-xsuaa-auth-cimd/1',
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;

        if (status >= 300 && status < 400) {
          res.resume();
          settle({ ok: false, reason: 'redirect_refused' });
          return;
        }
        // The draft requires exactly 200; every other code is an error response.
        if (status !== 200) {
          res.resume();
          settle({ ok: false, reason: 'bad_status' });
          return;
        }
        const encoding = res.headers['content-encoding'];
        if (encoding && encoding.toLowerCase() !== 'identity') {
          res.resume();
          settle({ ok: false, reason: 'content_encoding_refused' });
          return;
        }
        if (!isJsonContentType(res.headers['content-type'])) {
          res.resume();
          settle({ ok: false, reason: 'bad_content_type' });
          return;
        }
        // Fast path: an honest oversize declaration saves us the transfer. The streaming
        // cap below is the real control — Content-Length is advisory and may lie.
        const declared = Number(res.headers['content-length']);
        if (Number.isFinite(declared) && declared > limits.maxBytes) {
          res.resume();
          settle({ ok: false, reason: 'too_large' });
          return;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > limits.maxBytes) {
            settle({ ok: false, reason: 'too_large' });
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const cacheControl = res.headers['cache-control'];
          const expires = res.headers.expires;
          settle({
            ok: true,
            body: Buffer.concat(chunks).toString('utf8'),
            ...(typeof cacheControl === 'string' ? { cacheControl } : {}),
            ...(typeof expires === 'string' ? { expires } : {}),
            resolvedAddress: pinned.address,
          });
        });
        res.on('error', () => settle({ ok: false, reason: 'network_error' }));
      },
    );

    // Two deadlines: one for reaching a usable TLS connection, one for the whole
    // operation, so a server that connects instantly and then dribbles bytes forever is
    // still bounded.
    connectTimer = setTimeout(() => settle({ ok: false, reason: 'timeout' }), limits.connectTimeoutMs);
    globalTimer = setTimeout(() => settle({ ok: false, reason: 'timeout' }), limits.globalTimeoutMs);
    req.on('socket', (socket) => {
      socket.on('secureConnect', () => {
        if (connectTimer) clearTimeout(connectTimer);
        connectTimer = undefined;
      });
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      // Certificate and handshake failures are worth separating in audit; everything else
      // is an ordinary socket failure. Neither carries the underlying message onward.
      const code = err.code ?? '';
      const tlsFailure =
        code.startsWith('ERR_TLS') ||
        code.startsWith('CERT_') ||
        code.startsWith('UNABLE_TO_') ||
        code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
        code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
        code === 'EPROTO';
      settle({ ok: false, reason: tlsFailure ? 'tls_failure' : 'network_error' });
    });

    req.end();
  });
}

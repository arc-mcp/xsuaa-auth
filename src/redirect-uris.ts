/**
 * Redirect-URI validation + allowlist matching for the XSUAA OAuth proxy.
 *
 * Lifted from arc-1's stateless-client-store.ts. The crypto/control-flow logic
 * is verbatim; the only changes are parameterizing the pattern list (it now
 * defaults to {@link XSUAA_DEFAULT_REDIRECT_URI_PATTERNS} but a consumer can
 * pass its own) and the renamed public exports per SPEC §6.
 */

/**
 * Built-in redirect_uris for the pre-registered XSUAA client. These cover the
 * common MCP clients out of the box; additional URIs can be added at
 * `/authorize` time via `ensureRedirectUri()`. With the `/oauth/callback`
 * proxy (see {@link XSUAA_DEFAULT_REDIRECT_URI_PATTERNS}) XSUAA never sees these
 * client URIs — this package validates them. They do not have to be registered
 * in `xs-security.json`, and the custom-scheme entries cannot be.
 */
export const XSUAA_DEFAULT_REDIRECT_URIS = [
  'http://localhost:6274/oauth/callback', // MCP Inspector
  'http://localhost:3000/oauth/callback', // Local dev
  'https://claude.ai/api/mcp/auth_callback', // Claude Desktop
  'cursor://anysphere.cursor-retrieval/oauth/callback', // Cursor
  'vscode://vscode.microsoft-authentication/callback', // VS Code
] as const;

/**
 * Client redirect-URI allowlist for the pre-registered XSUAA client.
 *
 * The callback proxy sends its own /oauth/callback URI to XSUAA and carries
 * the client's URI in signed state. This allowlist gates ensureRedirectUri()
 * and the callback; accepting arbitrary URIs would expose authorization codes.
 *
 * Configure the two boundaries separately:
 * - xs-security.json allows this server's /oauth/callback.
 * - redirectUriPatterns allows the default client's callbacks.
 *   XSUAA rejects custom schemes such as cursor:// and vscode:// (#812 in ARC-1),
 *   so those client URIs belong only here. Keep patterns narrow.
 * DCR separately uses validateRedirectUri() at registration and exact URI
 * matching at the callback; these patterns only add extra DCR custom schemes.
 * The separate dcrRedirectUriPatterns option can further restrict DCR redirects.
 *
 * Glob semantics: `*` stays within a host/path segment; `**` can cross segments.
 */
export const XSUAA_DEFAULT_REDIRECT_URI_PATTERNS = [
  'http://localhost:*/**',
  'https://*.hana.ondemand.com/**',
  'https://*.applicationstudio.cloud.sap/**',
  'https://claude.ai/api/mcp/auth_callback',
  'https://callback.mistral.ai/v1/integrations_auth/oauth2_callback',
  'cursor://anysphere.cursor-retrieval/**',
  'cursor://anysphere.cursor-mcp/**',
  'vscode://vscode.microsoft-authentication/**',
  'https://global.consent.azure-apim.net/redirect/**',
] as const;

/** Translate one redirect-URI glob into an anchored,
 *  case-insensitive RegExp. `**` → `.*` (crosses `/`); `*` → `[^/]*` (within a
 *  segment); every other character is matched literally. The trailing `/` and
 *  anchoring mean a host-label `*` (e.g. `*.hana.ondemand.com`) cannot be widened
 *  to a different registrable domain. */
function redirectPatternToRegExp(pattern: string, caseSensitive = false): RegExp {
  // Split on the wildcard tokens, keeping them (the capturing group keeps the
  // delimiters in the result array). `**` is tried before `*`, so it tokenizes
  // as a single token.
  const body = pattern
    .split(/(\*\*|\*)/)
    .map((segment) => {
      if (segment === '**') return '.*'; // crosses path separators
      if (segment === '*') return '[^/]*'; // within a single segment (never `/`)
      return segment.replace(/[.+?^${}()|[\]\\]/g, '\\$&'); // escape literal regex metachars
    })
    .join('');
  return new RegExp(`^${body}$`, caseSensitive ? '' : 'i');
}

/**
 * Is `uri` an allowed redirect target for the pre-registered XSUAA default
 * client? True iff it matches a `patterns` entry (defaults to
 * {@link XSUAA_DEFAULT_REDIRECT_URI_PATTERNS}). Stateless, so it gives the same
 * answer on every instance — used both to gate dynamic registration
 * (`ensureRedirectUri`) and to validate the redirect target at `/oauth/callback`
 * (`checkRedirectUri`).
 *
 * SECURITY — match the CANONICAL parsed URL, never the raw input: the value
 * matched here is later re-parsed with `new URL()` and used as the 302 target
 * that carries the OAuth `code`, so the glob decision MUST agree with how the URL
 * actually parses. Matching the raw string is exploitable because the WHATWG URL
 * parser relocates the authority on characters a naive glob treats as literal:
 *   - `https://evil.com\@x.hana.ondemand.com/cb` — the `\` is normalised to `/`,
 *     so the real `host` is `evil.com` while the raw string matches
 *     `https://*.hana.ondemand.com/**`.
 *   - `https://evil.com#@x.hana.ondemand.com/cb` / `…?@…` — the `#`/`?` start the
 *     fragment/query, leaving `host === 'evil.com'` but a raw string that still
 *     contains `.hana.ondemand.com`.
 *   - `http://localhost:x@evil.com/cb` — userinfo `@` rides inside the
 *     same-segment port wildcard yet `host === 'evil.com'`.
 * Fix (mirrors arc-1's canonical-subject approach): reject anything that doesn't
 * parse, reject any userinfo (`user[:pass]@` — no legitimate OAuth redirect_uri
 * carries credentials), then build a canonical string from the RESOLVED parse
 * (protocol + `//` + host + pathname + search, host lowercased — `host` keeps the
 * port so the `localhost:[port]` patterns still work) and match the glob against
 * THAT, not the raw input. After this, a glob match implies the parsed host is the
 * literal host in the pattern.
 */
export function matchesRedirectPattern(
  uri: string,
  patterns: readonly string[] = XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.username !== '' || parsed.password !== '') return false;
  // Canonicalize from the resolved parse so a backslash/`#`/`?` that relocates the
  // host cannot smuggle a foreign authority past a string glob. `host` (not
  // `hostname`) preserves any `:port` the localhost pattern depends on; lowercasing
  // matches the case-insensitive regex and the case-insensitive nature of hosts.
  const canonical = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}${parsed.search}`;
  return patterns.some((pattern) => redirectPatternToRegExp(pattern).test(canonical));
}

/** DCR admission policy: host/scheme are case-insensitive, path/query are not.
 * Authorization and callback still require the exact registered URI. */
export function matchesDcrRedirectPattern(uri: string, patterns: readonly string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.username || parsed.password || parsed.hash || uri.includes('#')) return false;
  const canonical = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}${parsed.search}`;
  return patterns.some((pattern) => {
    const normalized = pattern.replace(
      /^([^:]+:\/\/[^/]+)(.*)$/,
      (_match, authority: string, rest: string) => authority.toLowerCase() + rest,
    );
    return redirectPatternToRegExp(normalized, true).test(canonical);
  });
}

/**
 * Validate a redirect URI against the allowed scheme/host policy.
 *
 * Allowed: `https://*`, `http://` to localhost / 127.0.0.1 / [::1], the known
 * MCP-client custom schemes (`claude:`, `cursor:`, `vscode:`, `vscode-insiders:`),
 * and any URI explicitly allowlisted by `patterns` (so a deployment that registers
 * an extra native-client scheme in its `redirectUriPatterns` can use it —
 * `xs-security.json` cannot hold custom schemes, see
 * {@link XSUAA_DEFAULT_REDIRECT_URI_PATTERNS}).
 *
 * Rejected: `javascript:`, `data:`, `file:`, `ftp:`, any `http://` to a
 * non-loopback host, and — fail-closed — ANY other unknown/custom scheme that is
 * neither a known-good scheme nor matched by `patterns`.
 *
 * Rejected inputs throw (SPEC §6). Unknown schemes require an explicit matching
 * pattern; there is no permissive fallback.
 */
export function validateRedirectUri(
  uri: string,
  patterns: readonly string[] = XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
): void {
  const ALLOWED_CUSTOM_SCHEMES = ['claude:', 'cursor:', 'vscode:', 'vscode-insiders:'];
  const BLOCKED_SCHEMES = ['javascript:', 'data:', 'file:', 'ftp:'];

  for (const scheme of BLOCKED_SCHEMES) {
    if (uri.toLowerCase().startsWith(scheme)) {
      throw new Error(
        `Redirect URI rejected: '${scheme}' scheme is not allowed. Use https:// or a registered custom scheme.`,
      );
    }
  }

  for (const scheme of ALLOWED_CUSTOM_SCHEMES) {
    if (uri.toLowerCase().startsWith(scheme)) return;
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    // Unparseable input is not a valid redirect target — fail closed.
    throw new Error(`Redirect URI rejected: not a parseable URI. Got: '${uri}'`);
  }

  if (parsed.protocol === 'https:') return;
  if (parsed.protocol === 'http:') {
    const host = parsed.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1') return;
    throw new Error(`Redirect URI rejected: http:// is only allowed for localhost/127.0.0.1. Got: '${uri}'`);
  }

  // Unknown/custom scheme (e.g. `myapp://…`): allowed ONLY if explicitly
  // allowlisted by `patterns`. This is the wired-in fail-closed gate — without a
  // matching pattern an unregistered scheme is rejected rather than auto-trusted.
  if (matchesRedirectPattern(uri, patterns)) return;
  throw new Error(
    `Redirect URI rejected: scheme '${parsed.protocol}' is not allowed and no allowlisted pattern matches. Got: '${uri}'`,
  );
}

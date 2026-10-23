# @arc-mcp/xsuaa-auth

**XSUAA / OAuth authentication + SAP BTP principal propagation for [Model Context Protocol](https://modelcontextprotocol.io) servers** built on Express and [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk).

[![CI](https://github.com/arc-mcp/xsuaa-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/arc-mcp/xsuaa-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/arc-mcp/xsuaa-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/arc-mcp/xsuaa-auth/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/arc-mcp/xsuaa-auth/badge)](https://scorecard.dev/viewer/?uri=github.com/arc-mcp/xsuaa-auth)
[![npm](https://img.shields.io/npm/v/@arc-mcp/xsuaa-auth.svg)](https://www.npmjs.com/package/@arc-mcp/xsuaa-auth)

It gives an MCP server the SAP-native client→server auth stack: an **XSUAA OAuth proxy provider**, a stateless **RFC 7591 Dynamic Client Registration** store (HMAC-signed `client_id`s, restart-resilient), the OAuth-state callback codec that works around XSUAA's un-encoded `+` in `state`, a chained bearer verifier (**XSUAA → OIDC → API-key**, each optional), and a thin `setupHttpAuth` facade. A separate [`./btp`](#principal-propagation-btp) entrypoint adds **per-user principal propagation** via the BTP Destination Service + Cloud Connector.

Two API layers, same package: a **plug-and-play facade** for the common flow, and the **building blocks** it composes for full control.

> Extracted from [arc-1](https://github.com/marianfoo/arc-1)'s production auth stack and designed so arc-1, calmcp, and LISA can adopt it with a minimal diff. The full design rationale is frozen in [`docs/SPEC.md`](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/SPEC.md) and [`docs/RESEARCH.md`](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/RESEARCH.md).

---

## Install

```bash
npm install @arc-mcp/xsuaa-auth
```

ESM-only, Node **>= 22**. You also need these **peer dependencies** (the package shares the host's Express + MCP SDK instances rather than bundling its own):

| Peer | Range | Required? |
|------|-------|-----------|
| [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk) | `>=1.18.2 <2` | **yes** — `1.18.2` is the first version exposing `mcpAuthRouter({ resourceServerUrl })` |
| [`express`](https://www.npmjs.com/package/express) | `^5.0.1` | **yes** — the SDK hard-depends on Express 5; v4 cannot coexist with its router |
| [`jose`](https://www.npmjs.com/package/jose) | `>=5 <7` | **optional** — only for the OIDC verifier; lazy-imported, so non-OIDC consumers can skip it |

```bash
npm install @modelcontextprotocol/sdk express
npm install jose            # only if you use createOidcVerifier / AuthOptions.oidc
```

`@sap/xssec` and `@sap-cloud-sdk/connectivity` are regular dependencies and install automatically.

---

## Quickstart

### Layer 1 — the `setupHttpAuth` facade (plug-and-play)

The facade composes the standard XSUAA + DCR + callback + bearer flow and returns the bearer middleware for your `/mcp` route. On Cloud Foundry, `loadXsuaaCredentials()` and `resolveAppUrl()` read the bound XSUAA service and the public route straight from the environment — no hand-parsed binding.

```ts
import express from 'express';
import { setupHttpAuth, loadXsuaaCredentials, resolveAppUrl } from '@arc-mcp/xsuaa-auth';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const bearer = setupHttpAuth(
  app,
  {
    apiKeys: process.env.API_KEYS,                 // string | ApiKeyEntry[]
    xsuaa: {
      credentials: loadXsuaaCredentials(),         // from VCAP_SERVICES
      appUrl: resolveAppUrl(process.env, { publicUrlEnvVar: 'PUBLIC_URL', port: 8080 }),
      clientIdPrefix: 'myapp-',
      resourceName: 'My MCP Server',
      // requiredScopes: ['Viewer'],               // enforced via requireBearerAuth
    },
    oidc: { issuer: process.env.OIDC_ISSUER!, audience: process.env.OIDC_AUDIENCE! },
    allowedOrigins: ['https://claude.ai'],          // CORS for browser MCP clients
    required: true,                                 // fail closed if nothing is configured
  },
  logger,                                           // optional Logger (default: no-op)
);

// Mount your MCP transport behind the returned middleware.
app.all('/mcp', bearer!, myMcpHandler);
```

What the facade does in XSUAA mode: applies CORS (if `allowedOrigins` set) → builds the chained verifier → creates the XSUAA OAuth provider → mounts the pattern-gated `/authorize` `ensureRedirectUri` shim, the `/oauth/callback` proxy, and the SDK `mcpAuthRouter` (discovery + `authorize`/`token`/`register`/`revoke`) → returns `requireBearerAuth`. With **no** `xsuaa` block (API-key/OIDC only) it returns bearer middleware **without** mounting the OAuth router. With **no** method configured it throws when `required: true`, else logs a loud warning and returns `undefined` (open).

It deliberately sets **no restrictive `Cross-Origin-Opener-Policy`** — popup-based OAuth (Copilot Studio, claude.ai) breaks under `COOP: same-origin`. Broader hardening (helmet CSP/HSTS) stays yours to add.

Expired or revoked refresh grants return `400 invalid_grant` so clients can sign in
again. Other upstream refresh failures remain `500 server_error`.

### Layer 2 — building blocks (full control)

When you orchestrate the HTTP server yourself (arc-1, LISA), call the same primitives the facade uses:

```ts
import {
  createXsuaaOAuthProvider,
  createXsuaaTokenVerifier,
  createOidcVerifier,
  createApiKeyVerifier,
  createChainedTokenVerifier,
  createOAuthCallbackHandler,
  StatelessDcrClientStore,
  OAuthStateCodec,
  validateRedirectUri,
} from '@arc-mcp/xsuaa-auth';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';

// 1. The XSUAA OAuth provider also hands you the DCR store + state codec.
const { provider, clientStore, stateCodec } = createXsuaaOAuthProvider(credentials, appUrl, {
  clientIdPrefix: 'myapp-',
  dcrSigningSecret: process.env.DCR_SIGNING_SECRET, // stabilizes client_ids across restarts
});

// 2. Chain the verifiers (XSUAA → OIDC → api-key; each optional).
//    Pass expandScopes to EACH sub-verifier — that's the layer that applies it
//    (the chain does not re-apply it; see the note below). The chain's own
//    `{ expandScopes }` only configures the api-key verifier it builds internally.
const verifier = createChainedTokenVerifier(
  { apiKeys: process.env.API_KEYS },
  createXsuaaTokenVerifier(credentials, { expandScopes }),
  createOidcVerifier(issuer, audience, { algorithms: ['RS256', 'ES256', 'PS256'], expandScopes }),
  { expandScopes },
);

// 3. Wire it onto your app exactly how you need (callback proxy, /authorize shim, router…).
app.get('/oauth/callback', createOAuthCallbackHandler(stateCodec, clientStore, { logger }));
app.use(mcpAuthRouter({ provider, issuerUrl, baseUrl, resourceServerUrl, scopesSupported, resourceName }));
app.all('/mcp', requireBearerAuth({ verifier: { verifyAccessToken: verifier }, resourceMetadataUrl }), myMcpHandler);
```

Each verifier accepts an optional injected **`expandScopes`** policy hook (default identity), applied **exactly once** by the sub-verifier that produces the `AuthInfo`. `createChainedTokenVerifier` does **not** re-apply it on top of a sub-verifier's result (so a non-idempotent expander runs once, not twice) — it only uses the hook for the api-key verifier it builds from `config.apiKeys`. arc-1 passes its `authz/policy` function so `AuthInfo` carries expanded scopes; other consumers omit it. The package owns **no** scope/tool policy — it's injected, never owned.

Each verifier also accepts **`acceptedScopes`** (default the arc-1 set `['read','write','data','sql','transports','git','admin']`) — the scope-name allowlist applied to a token's claims. Override it (e.g. `['Viewer']`) when your scopes differ, or, via the facade, set `xsuaa.scopesSupported` (which the facade threads to both verifiers).

`createOidcVerifier` additionally accepts **`fallbackScopes`** (default `[]`, **fail closed**) — the scopes granted when a *verified* OIDC token carries no accepted scope (no `scope`/`scp` claim, or claims that match none of `acceptedScopes`). The empty default means an IdP misconfigured to drop scope claims grants **no** access rather than silently falling back to read-only. Opt into the legacy read-only behavior with `fallbackScopes: ['read']` (via the facade, `oidc.fallbackScopes`). It is not run through `expandScopes`.

### Verified user attributes (optional building block)

`createXsuaaTokenVerifier` accepts `userAttributeNames` and `requireUserToken` for applications
that authorize individual user principals with XSUAA attributes. Omitting both options preserves
the existing verifier behavior and `AuthInfo` shape. This is not enabled by `setupHttpAuth`.

```ts
const verify = createXsuaaTokenVerifier(credentials, {
  userAttributeNames: ['arc1_targets'],
  requireUserToken: true,
});
const authInfo = await verify(accessToken);
// authInfo.extra.xsuaaUserAttributes: { arc1_targets: ['A4H/001', 'A4H/100'] }
// authInfo.extra.xsuaaUserAttributeStatus: { arc1_targets: 'valid' }
```

Only allowlisted attributes from the successfully validated SAP security context are copied.
The arrays and records are frozen; missing, malformed, and over-limit values carry distinct safe
status codes. Target syntax and application policy stay in the consumer. Do not request an OAuth
scope named `user_attributes` to activate this feature.

`requireUserToken` rejects machine or unknown principals with the exported
`XsuaaUserTokenRequiredError`. It extends the MCP SDK's `InsufficientScopeError`, so
`requireBearerAuth` returns **403** with this package's `forbidden` wire code, not an
`insufficient_scope` step-up challenge; ordinary `InvalidTokenError` remains
**401**. A custom adapter can instead map its stable `XSUAA_USER_TOKEN_REQUIRED` code to a generic
403. A machine principal cannot satisfy this policy by requesting more scopes. Do not parse error
messages or retry another authentication method after this terminal error; the package's chain
preserves the terminal decision in either JWT verifier slot. It unwraps own `Error.cause` wrappers
and normalizes errors from separately loaded package copies to the fixed local error. Ordinary
missing-scope challenges remain `insufficient_scope`. The tested TypeScript SDK clients do not
retry OAuth on `forbidden`; other MCP clients may recover on any 403 and need separate validation.

The chain still tries other verifiers after an ordinary validation/JWKS failure. Do not configure
an alternative verifier that accepts the same XSUAA tokens with a weaker principal policy. For a
user-only XSUAA route, use the configured XSUAA verifier directly. Attribute extraction alone is
not proof of a user principal or application permission; enforce the required local scopes too.
See [the attribute/principal contract and live-evidence gates](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/USER-ATTRIBUTES.md).

---

## `AuthOptions`

The facade's configuration object. All fields are optional except where noted.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `apiKeys` | `string \| ApiKeyEntry[]` | — | A single static key, or `[{ key, scopes?, clientId? }]`. Matched in constant time. **A bare string key grants `scopes: []`** — it authenticates but fails any `requiredScopes`; use `[{ key, scopes: [...] }]` to grant scopes. |
| `xsuaa` | `object` | — | Present ⇒ XSUAA OAuth proxy is mounted (see sub-fields below). Omit for API-key/OIDC-only. |
| `xsuaa.credentials` | `XsuaaCredentials` | **required** | `{ url, clientid, clientsecret, xsappname, uaadomain, verificationkey? }`. Use `loadXsuaaCredentials()`. |
| `xsuaa.appUrl` | `string` | **required** | Public URL the OAuth metadata advertises. Use `resolveAppUrl()`. |
| `xsuaa.clientIdPrefix` | `string` | `'mcp-'` | Prefix for issued DCR `client_id`s — set a per-deployment value. |
| `xsuaa.dcrKdfLabel` | `string` | `'mcp-dcr/v1'` | Domain-separation label for DCR `client_id` signing. Bumping it revokes all issued client_ids. |
| `xsuaa.stateKdfLabel` | `string` | `'mcp-oauth-state/v1'` | Domain-separation label for OAuth-state tokens. |
| `xsuaa.resourceName` | `string` | SDK default | `resource_name` in the protected-resource metadata. |
| `xsuaa.scopesSupported` | `string[]` | — | Advertised in OAuth metadata. **Also threaded to the XSUAA + OIDC verifiers as `acceptedScopes`** — set it to your own scope names (e.g. `['Viewer']`) so non-arc-1 scopes aren't filtered out of verified tokens. |
| `xsuaa.requiredScopes` | `string[]` | — | Enforced via the SDK's `requireBearerAuth({ requiredScopes })`. |
| `xsuaa.redirectUriPatterns` | `readonly string[]` | `XSUAA_DEFAULT_REDIRECT_URI_PATTERNS` | Redirect allowlist for the pre-registered default client; also permits extra DCR custom schemes. See [Redirect validation](#redirect-validation). |
| `xsuaa.dcrRedirectUriPatterns` | `readonly string[]` | unset | Optional allowlist for DCR redirect URIs. Registration rejects non-matching URIs; earlier client_ids keep only matching URIs. `[]` rejects every DCR redirect. See [Redirect validation](#redirect-validation). |
| `xsuaa.defaultRedirectUris` | `readonly string[]` | `XSUAA_DEFAULT_REDIRECT_URIS` | Initial URIs for the default client; each must also match `redirectUriPatterns` at the callback. Narrow both lists together. |
| `xsuaa.dcrEnabled` | `boolean` | `true` | Set `false` to remove `/register` and its discovery metadata. Existing registrations and manual clients remain usable, with browser approval. |
| `xsuaa.dcrTtlSeconds` | `number` | `2592000` (30d) | DCR `client_id` lifetime. `0` disables expiry (recommended for clients that don't auto-re-register on `invalid_client`). |
| `xsuaa.stateTtlSeconds` | `number` | `600` | Legacy codec state lifetime. Browser-approved flows always expire within ten minutes, even when set to `0`. |
| `xsuaa.dcrSigningSecret` | `string` | XSUAA `clientsecret` | Dedicated HMAC secret for DCR `client_id`s — set a ≥32-byte value so a `clientsecret` rotation doesn't invalidate cached client_ids. |
| `xsuaa.callbackUrl` | `string` | `${appUrl}/oauth/callback` | This server's callback URL sent to XSUAA. Must share the configured `appUrl` origin; HTTPS required except HTTP loopback development. Allow it in `xs-security.json` `redirect-uris`; it need not match the client patterns. |
| `oidc` | `object` | — | `{ issuer, audience, clockToleranceSec?, algorithms?, scopeClaim?, acceptedScopes?, fallbackScopes? }`. Lazy-imports `jose`. `algorithms` defaults to `['RS256','ES256','PS256']`; `scopeClaim` overrides the primary scope-claim name (default `scope`); `acceptedScopes` is the scope-name allowlist for **OIDC-only** deployments with custom scope names (defaults to `xsuaa.scopesSupported`, else the arc-1 set); `fallbackScopes` (default `[]`, fail closed) is the scope set granted when a verified token carries no accepted scope — set `['read']` for legacy read-only fallback. |
| `allowedOrigins` | `string[]` | — | Exact-match CORS allowlist (with `credentials`) for browser MCP clients. Unset = no CORS. |
| `required` | `boolean` | `false` | `true` ⇒ throw if no method configured; `false` ⇒ warn + return `undefined` (open). |
| `expandScopes` | `(scopes: string[]) => string[]` | identity | Injected scope-expansion policy, applied by every verifier. |

`setupHttpAuth(app, options, logger?)` returns the `/mcp` bearer `RequestHandler`, or `undefined` when no method is configured and `required` is falsy.

### Browser approval

Every authorization request presents an approval page before forwarding to XSUAA,
including requests from manual clients and previously registered clients. The page
shows the self-declared client name, actual return address, and requested permissions.
An existing identity-provider SSO session does not skip this approval.

Approval requires a same-origin form submission bound to a host-only, HttpOnly cookie
and the exact OAuth request. A separate ten-minute cookie binds the XSUAA callback to
the browser that approved it. Local authorization codes are signed and bound to the
client and return address before token exchange; XSUAA continues to enforce PKCE and
single use. Concurrent tabs and multiple instances work without a shared session store
when their public URL and signing secret agree. Reverse proxies must preserve Cookie
and Origin headers and advertise the correct public `appUrl`, including its path prefix.

Existing client IDs remain valid. Sign-ins in flight during the upgrade must restart:
legacy unbound state and raw upstream authorization codes are rejected. Existing
refresh tokens are not invalidated by this upgrade. If exposure is suspected, use
documented XSUAA incident controls and verify token invalidation independently.
Rotating the DCR signing key alone does not revoke upstream tokens.
Disabling DCR blocks new registrations, not existing clients or stolen tokens.

### Upgrading deployments

Provider construction rejects an `appUrl` that is not HTTPS, except HTTP on
`localhost`, `127.0.0.1` or `[::1]`. The callback must share that public origin.
Configure the public URL explicitly outside Cloud Foundry; a non-loopback HTTP
bind address is not a public OAuth URL. Existing API-key or OIDC authentication
does not remove these requirements when XSUAA is enabled alongside it.
For HTTP development with the SDK router, use `localhost` or `127.0.0.1`: the
currently tested SDK rejects an IPv6 HTTP issuer. IPv6 client callback URLs remain supported.

Use the same canonical public origin in every client and browser. Alternate routes
or custom-domain aliases can lose the host-only approval cookie and require sign-in
to restart at the configured origin. Proxies must preserve `Cookie`, `Set-Cookie`
and `Origin`, and must not overwrite the approval page's `Referrer-Policy: origin`.

An ordinary sign-in uses two `/authorize` requests: the approval page and its form
submission. Both count toward the existing authorization endpoint limit. Account for
shared-IP traffic without disabling that protection. Upgrade every instance before
resuming sign-ins; a mixture of old and new OAuth implementations is not supported.

## Redirect validation

XSUAA validates the server's callback URL; this package validates client redirects.
For the pre-registered default client, `redirectUriPatterns` gates added URIs and
the callback. Keep patterns narrow and align `defaultRedirectUris` with them.

DCR registration separately accepts HTTPS, loopback HTTP and the known schemes
`claude:`, `cursor:`, `vscode:` and `vscode-insiders:`; patterns can permit extra
custom schemes. DCR callbacks must exactly match a URI in the signed registration.
Narrowing the patterns does **not** restrict DCR HTTPS domains or known schemes.
To restrict them, set `dcrRedirectUriPatterns` (same glob syntax; schemes and hosts
are case-insensitive, paths and queries are case-sensitive; write hosts in ASCII
form). It only narrows the policy above: extra custom schemes still need a
`redirectUriPatterns` entry, and the pre-registered default client keeps its separate
policy. If **any** redirect URI fails to match, the whole registration is rejected
with HTTP 400 `invalid_client_metadata`. Allowlist every URI a client registers;
for example, `http://127.0.0.1:*/**` does not cover port-less `http://127.0.0.1/`.

Earlier signed client IDs are filtered at lookup. Excluded URIs are ignored while
the restriction applies; widening the policy restores them. A client without an
allowed URI cannot start authorization. Update its callbacks to allowed addresses
and re-register, or adjust the policy deliberately. Rotate the signing secret or
`dcrKdfLabel` to revoke previously issued client IDs permanently. `[]` rejects every
DCR redirect but keeps `/register` mounted; `dcrEnabled: false` removes new
registration. Unset adds no restriction to the default DCR policy.

DCR registration rejects userinfo and fragments even when the allowlist is unset.
Invalid or disallowed redirects now return HTTP 400 `invalid_client_metadata`
instead of HTTP 500 `server_error`. Direct `registerClient` callers receive
`InvalidClientMetadataError` with a generic message; do not match the previous
error text. Rejection audits include the parsed host and the reason
`invalid_redirect_uri` or `redirect_uri_not_allowlisted`, without the submitted URL.

Every authorization still requires explicit client approval, including loopback and
VS Code return addresses. The allowlist restricts where a client may return; it does
not establish the client's identity or the user's consent. It does not revoke
already-issued access or refresh tokens. Keep this policy identical on every instance.
Upgrade every instance to a supporting library version before enabling the policy;
a mixed deployment can still handle a request on an instance using the old policy.
Client custom schemes belong in this package's configuration, not `xs-security.json`.

---

## Principal propagation (`./btp`)

The `./btp` entrypoint maps the authenticated MCP user to their own SAP identity via the BTP Destination Service + Cloud Connector. The handoff from the auth layer is just the **raw, already-verified bearer JWT** (`authInfo.token`).

```ts
import {
  listDestinationsAtLevel,
  lookupDestinationWithUserToken,
  lookupDestinationWithUserTokenUncached,
  parseVCAPServices,
  resolveBTPDestination,
} from '@arc-mcp/xsuaa-auth/btp';

// Technical (shared) destination — no per-user identity:
const { url, username, password, client, proxy } = await resolveBTPDestination('SAP_TRIAL', logger);

// Per-user principal propagation — pass the verified user JWT:
const btpConfig = parseVCAPServices(process.env)!;
btpConfig.requestTimeoutMs = 15_000; // optional; defaults to 10s and is capped at 60s
const subaccountDestinations = await listDestinationsAtLevel(btpConfig, 'subaccount', logger);
const { destination, authTokens } = await lookupDestinationWithUserToken(
  btpConfig,
  'MY_PP_DESTINATION',
  authInfo.token,    // the verified bearer JWT (guarded: must be a 3-segment JWT, not an API key)
  logger,
);
// authTokens: { sapConnectivityAuth?, bearerToken?, ppProxyAuth?, samlAssertionAuthorization? }

// Drift-sensitive per-request lookup: bypasses both reads and writes of the SDK cache.
await lookupDestinationWithUserTokenUncached(btpConfig, 'MY_PP_DESTINATION', authInfo.token, logger);
```

**The package returns credentials + a proxy descriptor; it never applies them.** Your SAP HTTP client owns header assembly (`Authorization` / `SAP-Connectivity-Authentication` / `Proxy-Authorization`) and the forward-proxy request. What to do when no PP token is produced (throw vs. fall back to BasicAuth) is **your** policy.

Which `PerUserAuthTokens` field is populated depends on the destination's `Authentication` type (they're mutually exclusive). Apply whichever one is set:

| `PerUserAuthTokens` field | Destination `Authentication` | Apply as |
|---|---|---|
| `sapConnectivityAuth` | `PrincipalPropagation` (Cloud Connector) | `SAP-Connectivity-Authentication` header, alongside `Proxy-Authorization` from the connectivity proxy |
| `bearerToken` | `OAuth2UserTokenExchange` / `OAuth2SAMLBearerAssertion` | `Authorization: Bearer <bearerToken>` |
| `samlAssertionAuthorization` | `SAMLAssertion` (e.g. S/4HANA Public Cloud developer extensibility — the same flow [SAP Business Application Studio](https://help.sap.com/docs/bas) uses) | `Authorization: <value>` **verbatim** (already prefixed, e.g. `SAML2.0 …`), alongside `x-sap-security-session: create` |
| `ppProxyAuth` | — | Reserved (jwt-bearer "Option 1" → `Proxy-Authorization`); never produced by `lookupDestinationWithUserToken`, a consumer assigns it itself |

| Export | Purpose |
|--------|---------|
| `parseVCAPServices(env?)` | Build a `BTPConfig` from `VCAP_SERVICES` (XSUAA + destination + connectivity bindings). |
| `listDestinationsAtLevel(cfg, level, logger?)` | Fetch the complete `subaccount` or `instance` collection without the SDK cache. Basic credentials remain only in the explicit `User`/`Password` fields; `originalProperties` excludes known credential, token, authorization-header, and certificate material while preserving non-secret custom properties. |
| `lookupDestination(cfg, name, logger?)` | Resolve a destination (works with BasicAuth destinations, no user JWT). |
| `lookupDestinationWithUserToken(cfg, name, userJwt, logger?)` | The PP primitive — per-user destination + `PerUserAuthTokens`. JWT-only (anti-footgun). |
| `lookupDestinationWithUserTokenUncached(cfg, name, userJwt, logger?)` | Same PP result with `useCache:false`; failed or successful resolutions cannot affect a later lookup. |
| `createConnectivityProxy(cfg, locationId?, logger?)` | A `BTPProxyConfig` descriptor for the Cloud Connector connectivity proxy. |
| `resolveBTPDestination(name, logger?)` | Convenience: destination → `{ url, username, password, client, proxy }`. |
| `BTPRequestTimeoutError` | Typed timeout from direct BTP requests that are not intentionally wrapped in a more specific service error. Its `timeoutMs` field contains the effective bounded timeout. |
| `DEFAULT_BTP_REQUEST_TIMEOUT_MS` / `MAX_BTP_REQUEST_TIMEOUT_MS` | Public 10-second default and 60-second hard cap for consumers that expose the setting. |

Direct Destination and Connectivity Service requests use one abortable timeout for the fetch and response body together. Configure it with `BTPConfig.requestTimeoutMs`; invalid or non-positive values use the 10-second default, and values above 60 seconds are capped. This applies to service-token acquisition, collection/Find calls, Connectivity proxy tokens, and the direct principal-propagation fallback. The SAP Cloud SDK-owned per-user destination lookup manages its own transport and is not covered by this option.

---

## `@sap/xssec` is CommonJS — interop note

`@sap/xssec` is **pure CommonJS** (no ESM entry). This package consumes it with a default import + destructure under `esModuleInterop`, which is the supported pattern from an ESM module on Node 22+:

```ts
import xssec from '@sap/xssec';
const { XsuaaService, createSecurityContext } = xssec;   // NOT `import { XsuaaService } from '@sap/xssec'`
```

You don't need to do this yourself — the package handles XSUAA validation internally. It's documented here because it's the one interop sharp edge if you extend the package or import `@sap/xssec` alongside it. A named ESM import (`import { XsuaaService } from '@sap/xssec'`) will fail.

---

## What's **not** included

By design, the package's job ends at producing `AuthInfo` + the raw bearer token (and, via `./btp`, destination credentials). These stay with the consuming server:

- **Rate limiting** — per-IP and per-user limiters are deferred (see [`docs/SPEC.md §14`](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/SPEC.md)); each consumer keeps its own for now.
- **Scope / tool policy** — `expandScopes` is an injected hook; the package owns no `ACTION_POLICY` or scope semantics.
- **The MCP transport** — you own `/mcp` (stdio / Streamable HTTP); the package contributes middleware + the OAuth router.
- **The SAP HTTP client** — header assembly, CSRF, cookies, stateful sessions, and the forward-proxy request are yours.
- **Safety ceiling / server config / the MCP tools** — entirely consumer-owned.
- **Helmet / CSP / HSTS** — broader HTTP hardening is yours (and must keep COOP unset for popup OAuth).

---

## Documentation

- **[`docs/SPEC.md`](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/SPEC.md)** — the frozen API contract: every public signature, the dependency ranges, the logger contract, the auth↔PP coupling, and the adoption path for each consumer.
- **[`docs/RESEARCH.md`](https://github.com/arc-mcp/xsuaa-auth/blob/main/docs/RESEARCH.md)** — extraction research, the three-way (arc-1 / calmcp / LISA) reality check, and the Architecture Decision Records.
- **[`SECURITY.md`](./SECURITY.md)** — vulnerability reporting + the security-relevant configuration knobs.

### A note on the logger

Token-exchange failure events log the HTTP status, never the upstream body, which
may echo secrets.

The injected `Logger` uses `(message, data?)` argument order:

```ts
interface Logger {
  debug(message: string, data?: Record<string, unknown>): void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
  emitAudit?(event: Record<string, unknown>): void;   // optional; always null-guarded
}
```

It's optional everywhere and defaults to a no-op (`noopLogger`). [pino](https://github.com/pinojs/pino) users (`(obj, msg)` order) pass a thin adapter:

```ts
const adapter: Logger = {
  debug: (m, d) => log.debug(d ?? {}, m),
  info: (m, d) => log.info(d ?? {}, m),
  warn: (m, d) => log.warn(d ?? {}, m),
  error: (m, d) => log.error(d ?? {}, m),
};
```

---

## License

[MIT](./LICENSE) © Marian Zeis

# Security Policy

`@arc-mcp/xsuaa-auth` is an authentication library for [Model Context Protocol](https://modelcontextprotocol.io) servers: XSUAA / OAuth 2.0 + RFC 7591 Dynamic Client Registration + SAP BTP principal propagation. Because it sits on the authentication path, security reports are taken seriously — please follow this policy when reporting.

## Supported Versions

The latest published `1.x` release receives security fixes. Upgrade older releases to the latest fixed version; consult the advisory for the affected and patched versions of each issue.

| Version | Supported            |
| ------- | -------------------- |
| Latest 1.x | :white_check_mark: |
| Older releases | :x: — please upgrade |


## Reporting a Vulnerability

**Preferred — GitHub Private Vulnerability Reporting:**
[Open a private advisory](https://github.com/arc-mcp/xsuaa-auth/security/advisories/new). This routes the report directly to the maintainers, keeps it confidential, and gives us a private workspace to coordinate the fix. (Private vulnerability reporting must be enabled in the repository Settings → Security → Advanced Security before this link works.)

**Fallback — email:**
`marianbsp@gmail.com`. Please include "@arc-mcp/xsuaa-auth security" in the subject line. If you need to send encrypted email, request a public key in the first message.

**Please do _not_** open a public GitHub issue, post on the SAP Community, or share details on social media until a fix is published. Coordinated disclosure protects users running affected versions.

## Response Times (best-effort, non-contractual)

| Stage                                   | Target                 |
| --------------------------------------- | ---------------------- |
| Acknowledgement of report               | within 3 business days |
| Initial triage and severity assessment  | within 7 business days |
| Critical fix or mitigation              | within 14 days         |
| High fix or mitigation                  | within 30 days         |
| Moderate fix or mitigation              | within 60 days         |
| Low fix or mitigation                   | best-effort            |

Severity follows [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document) where applicable.

## CVE Handling

Confirmed vulnerabilities receive a [GitHub Security Advisory (GHSA)](https://github.com/arc-mcp/xsuaa-auth/security/advisories) and, where applicable, a CVE assigned via GitHub's CNA. Patches publish through the normal release flow ([release-please](https://github.com/googleapis/release-please) → npm via OIDC trusted publishing with provenance); the advisory marks affected versions and the fixed version. Where the patch warrants user action (for example a config change or a key/label rotation), the advisory and the release notes call it out explicitly.

## Out of Scope

- **SAP system or XSUAA service vulnerabilities.** This package is a client of XSUAA / the BTP Destination Service. Vulnerabilities in SAP BTP, XSUAA, the Cloud Connector, or the SAP backend itself belong to SAP — please report via [SAP's responsible-disclosure channel](https://www.sap.com/about/trust-center/security/incident-management.html).
- **Vulnerabilities in the MCP SDK, Express, `jose`, `@sap/xssec`, or other dependencies** with no `@arc-mcp/xsuaa-auth`-specific exposure (i.e. the upstream advisory does not impact how this package uses the dependency). Please report upstream to the affected project; this package tracks affected upstream advisories via Dependabot.
- **Theoretical vulnerabilities** without a concrete exploitation path against the package's documented usage. Design-hardening discussions are welcome in a regular GitHub issue, not the private advisory channel.
- **Misconfiguration in a consuming application** — e.g. setting an over-broad `redirectUriPatterns`, leaving `required: false` in production, or reusing the default `dcrSigningSecret`. The README documents the secure configuration; deployment hardening is the operator's responsibility.
- **Issues in unsupported versions** (see Supported Versions above).

## Temporary dependency risk acceptance

Until **31 December 2026, 00:00 Europe/Berlin**, CI and publishing accept only
[GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv), through
`@sap-cloud-sdk/connectivity@4.9.1 → jks-js@1.1.7 → node-forge@1.4.0`.
The maintainer renewed this exception on **24 October 2026**, based on
[SAP's completed assessment of 23 October](https://github.com/SAP/cloud-sdk-js/issues/7023#issuecomment-6365515697).
SAP concludes that the vulnerable RSA verifier is unreachable through Cloud SDK's use of
`jks-js`: keystore parsing and conversion use Forge, while certificate verification uses
Node's native TLS stack. This agrees with the review of this package's destination lookup
and the SDK's keystore conversion. Incoming token verification uses `@sap/xssec` and `jose`.

The assessment supports low practical risk for the reviewed usage. As of the renewal date,
no patched Forge release is available; downstream consumers still receive the affected
dependency and may flag it. The exception does not cover other uses of Forge in a consuming
application.

All production and development dependencies remain audited. Other high/critical findings
and audit failures block. [audit-ci.json](./audit-ci.json) enforces expiry. Upgrade and remove
the exception when a validated upstream fix is available; reassess sooner if dependency
versions or usage change, or SAP revises its assessment. Review before the expiry date;
any extension requires a new maintainer decision. Concrete exposure through this package
remains reportable.

## Safe Harbor

This project supports good-faith security research. Researchers acting in good faith and following this policy will not face legal action.

We commit to:
- Responding within the timelines above.
- Working with you to reproduce and understand the issue.
- Crediting you in the resulting GHSA / CVE if you wish (or honoring an anonymous-disclosure request).
- Not pursuing legal action against research conducted in accordance with this policy.

## Security-relevant configuration

The package ships fail-closed defaults, but a few knobs are load-bearing for security and are documented in the [README](./README.md) and [`docs/SPEC.md`](./docs/SPEC.md):

- **`redirectUriPatterns`** gates additions and callbacks for the pre-registered default client. Keep it narrow and ensure every `defaultRedirectUris` entry matches it; otherwise sign-in fails at the callback. XSUAA's `xs-security.json` allows the server callback, not client custom schemes.
- **Browser approval is mandatory:** every authorization request, including manual and previously registered clients, requires explicit approval before XSUAA; token refresh does not repeat approval. The displayed client name is unverified and is not an identity signal. The callback must return with the separate browser-binding cookie, and local codes are bound to the client and return address. Existing sign-ins in flight must restart after upgrading. Existing upstream refresh tokens require separate revocation if compromised.
- **`dcrEnabled: false`** removes new registrations and registration metadata; it does not revoke existing client IDs or upstream tokens. Registration audit events include parsed redirect hosts.
- **DCR uses a separate redirect policy:** HTTPS, loopback HTTP and known native schemes are accepted independently of these patterns; extra custom schemes can be pattern-allowed. The callback checks the exact URI in the signed registration. Narrowing `redirectUriPatterns` does not restrict DCR HTTPS domains or known schemes. Set `dcrRedirectUriPatterns` to restrict those at registration and when earlier client IDs are looked up; `[]` rejects all DCR redirects. This does not revoke access or refresh tokens and never skips browser approval. Any non-matching URI rejects the whole registration. Filtering existing client IDs is reversible when the policy is widened; rotate the signing secret or DCR KDF label for permanent client-ID revocation. The manual client stays separate, and `[]` leaves `/register` mounted. Upgrade every instance before enabling the policy, then apply the same policy on every instance. See [Redirect validation](./README.md#redirect-validation).
- **`dcrSigningSecret`** stabilizes DCR `client_id`s across restarts and should be a dedicated ≥32-byte secret. Rotating it (or bumping `dcrKdfLabel` / `stateKdfLabel`) is the revocation knob for issued client_ids and OAuth-state tokens.
- **`createOidcVerifier({ algorithms })`** defaults to `['RS256','ES256','PS256']` — an explicit allowlist that closes `alg:none` and algorithm-confusion. Do not widen it to include symmetric algorithms.
- **`createOidcVerifier({ fallbackScopes })`** defaults to `[]` (**fail closed**). When a verified OIDC token carries no accepted scope — no `scope`/`scp` claim, or claims that match none of `acceptedScopes` — the verifier grants `fallbackScopes`. The empty default means an IdP misconfigured to drop scope claims grants **no** privileges instead of silently falling back to read-only access. Only set `fallbackScopes: ['read']` (or wider) if you deliberately want an unscoped-but-authenticated token to receive a baseline grant.
- **`required: true`** on `setupHttpAuth` fails closed when no auth method is configured; leaving it `false` (the default) logs a loud warning and serves `/mcp` open.

## Principal-propagation destination cache isolation

The per-user destination lookup (`lookupDestinationWithUserToken` in `./btp`) resolves a PrincipalPropagation destination to a **per-user** credential (a SAML assertion or bearer token bound to the calling user's identity). To prevent one user's propagated identity from being served to another from a shared cache entry, the lookup pins the SAP Cloud SDK's `isolationStrategy: 'tenant-user'` on the cached `getDestination()` call. This is the SDK's default today, but pinning it explicitly keeps the per-user guarantee load-bearing in code: a future SDK default change — or accidentally reusing this path for a non-PP/technical destination — cannot silently widen the cache key to tenant-only and leak a propagated user identity across users. The startup (non-PP) resolver uses a direct `fetch` with no user-scoped cache, so it is unaffected.

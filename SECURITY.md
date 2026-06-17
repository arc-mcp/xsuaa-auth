# Security Policy

`@arc-mcp/xsuaa-auth` is an authentication library for [Model Context Protocol](https://modelcontextprotocol.io) servers: XSUAA / OAuth 2.0 + RFC 7591 Dynamic Client Registration + SAP BTP principal propagation. Because it sits on the authentication path, security reports are taken seriously — please follow this policy when reporting.

## Supported Versions

Pre-1.0 (current state): only the latest published `0.x` minor line receives security fixes. The API is still settling across the consuming MCP servers, so please track the latest release.

| Version | Supported            |
| ------- | -------------------- |
| 0.1.x   | :white_check_mark:   |
| < 0.1   | :x: — please upgrade |

After 1.0, this table will reflect the documented support window for each major.

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
- **Misconfiguration in a consuming application** — e.g. failing to set `redirectUriPatterns` in sync with the XSUAA `xs-security.json`, leaving `required: false` in production, or reusing the default `dcrSigningSecret`. The README documents the secure configuration; deployment hardening is the operator's responsibility.
- **Issues in unsupported versions** (see Supported Versions above).

## Safe Harbor

This project supports good-faith security research. Researchers acting in good faith and following this policy will not face legal action.

We commit to:
- Responding within the timelines above.
- Working with you to reproduce and understand the issue.
- Crediting you in the resulting GHSA / CVE if you wish (or honoring an anonymous-disclosure request).
- Not pursuing legal action against research conducted in accordance with this policy.

## Security-relevant configuration

The package ships fail-closed defaults, but a few knobs are load-bearing for security and are documented in the [README](./README.md) and [`docs/SPEC.md`](./docs/SPEC.md):

- **`redirectUriPatterns` / `defaultRedirectUris`** must stay in sync with the XSUAA service's `xs-security.json` `oauth2-configuration.redirect-uris`. The `/authorize` redirect-URI shim is pattern-gated; a too-broad pattern weakens it.
- **`dcrSigningSecret`** stabilizes DCR `client_id`s across restarts and should be a dedicated ≥32-byte secret. Rotating it (or bumping `dcrKdfLabel` / `stateKdfLabel`) is the revocation knob for issued client_ids and OAuth-state tokens.
- **`createOidcVerifier({ algorithms })`** defaults to `['RS256','ES256','PS256']` — an explicit allowlist that closes `alg:none` and algorithm-confusion. Do not widen it to include symmetric algorithms.
- **`createOidcVerifier({ fallbackScopes })`** defaults to `[]` (**fail closed**). When a verified OIDC token carries no accepted scope — no `scope`/`scp` claim, or claims that match none of `acceptedScopes` — the verifier grants `fallbackScopes`. The empty default means an IdP misconfigured to drop scope claims grants **no** privileges instead of silently falling back to read-only access. Only set `fallbackScopes: ['read']` (or wider) if you deliberately want an unscoped-but-authenticated token to receive a baseline grant.
- **`required: true`** on `setupHttpAuth` fails closed when no auth method is configured; leaving it `false` (the default) logs a loud warning and serves `/mcp` open.

## Principal-propagation destination cache isolation

The per-user destination lookup (`lookupDestinationWithUserToken` in `./btp`) resolves a PrincipalPropagation destination to a **per-user** credential (a SAML assertion or bearer token bound to the calling user's identity). To prevent one user's propagated identity from being served to another from a shared cache entry, the lookup pins the SAP Cloud SDK's `isolationStrategy: 'tenant-user'` on the cached `getDestination()` call. This is the SDK's default today, but pinning it explicitly keeps the per-user guarantee load-bearing in code: a future SDK default change — or accidentally reusing this path for a non-PP/technical destination — cannot silently widen the cache key to tenant-only and leak a propagated user identity across users. The startup (non-PP) resolver uses a direct `fetch` with no user-scoped cache, so it is unaffected.

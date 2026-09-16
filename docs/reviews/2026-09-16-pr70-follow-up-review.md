# PR #70: follow-up review of Claude's second report

Starting revision: `fa8907a56900003361233a9e0a9c584c82eafbeb` in
[PR #70](https://github.com/arc-mcp/xsuaa-auth/pull/70). The report is input to independent
verification, not authority to change the security contract. This work changes the library
candidate and its tests/docs only; no BTP/IAS/SAP configuration, release or deployment is changed.

## Findings and decisions

| # | Reported issue | Disposition |
|---|---|---|
| 1 | Principal 403 triggers OAuth scope escalation | **Fixed.** The SDK selects 403 by `instanceof InsufficientScopeError`, but clients interpret its wire `insufficient_scope` as a step-up challenge. Retain the subclass and override its wire code to the package-specific `forbidden`. Real middleware plus interactive/machine MCP transport tests require a single request and no authorization redirect, token request or token save. Genuine missing-scope challenges remain `insufficient_scope`. |
| 2 | Terminal denial lost in the OIDC slot or an error cause | **Fixed narrowly.** Recognize this specific principal denial in both JWT slots, including own data `Error.cause` wrappers and other package copies. Follow finite cause chains with cycle detection, not an arbitrary depth after which denial would become fallback. Do not change every generic `InsufficientScopeError` into a terminal error: that would silently broaden this opt-in feature's chain semantics. |
| 3 | Inherited exception `code` changes authentication selection | **Fixed.** Own data descriptors only; neither inherited fields nor code/cause getters count as principal-policy evidence. Tests include getters, inheritance, cycles and a long cause chain. No prototype-pollution entry point in this package was established. |
| 4 | Exported dictionary types reject literals and Records | **Fixed.** Reproduced TypeScript errors for empty/populated values, statuses and typed Records. Intersect sparse dictionaries with non-callable `unknown` Object members. Positive compile fixtures now accompany the original negative unsafe-access/mutation fixtures; runtime null prototypes and freezing are unchanged. |
| 5 | Single-option validate-before-classify coverage absent | **Added.** Real signed machine fixtures exercise wrong signature, expired and wrong audience with both options, attributes only and principal only. Neither classification nor extraction may run before successful validation. |
| 6 | Empty/unrelated extension fallback and precise limit values not pinned | **Added.** Empty `ext_cxt` and unrelated extension fields retain an own root attribute. ASCII value/entry and UTF-8 boundary cases now assert complete returned values or their absence, not only status/length. Existing aggregate-byte tests already assert complete values. |
| 7 | Stable principal-denial code repeated and unpinned | **Fixed.** One internal constant backs the class and verifier diagnostic; chain normalization uses it and logs the resulting error's code. A separate literal assertion pins the public compatibility code, so renaming the constant is detectable. |
| 8 | Adapter guidance and aggregate-budget wording stale | **Corrected.** No custom HTTP adapter is required. Document non-retryable principal denial separately from actual missing scopes. The combined budget counts only otherwise-valid candidates. |
| 9 | New README docs link breaks in npm rendering | **Corrected.** Use an absolute repository link, consistent with documents that are not packed in the npm artifact. |
| 10 | First review overstates full-value limit assertions | **Corrected transparently.** Preserve historical test counts, identify the original status-only cases, link this follow-up, and fix the assertions. Historical `insufficient_scope` advice is explicitly superseded. ARC live-evidence links are pinned to a verified commit rather than a disposable feature branch. |
| 11 | Chain has no terminal-denial diagnostic | **Added.** Fixed event/code plus the verifier method, with no provider message, token, attributes or user identifiers. A chain-only logger observes the denial. This remains diagnostic logging, not a newly promised audit-delivery mechanism. |
| 12 | Throwing diagnostic sink can replace denial and permit fallback | **Fixed.** An internal best-effort diagnostic logger covers verifier start/result/denial and chain selection, plus OIDC/API-key diagnostics. Synchronous logging failures cannot change the authentication result or select another verifier. Audit hooks are not wrapped or suppressed. Tests cover rejected principals, successful users, successful first-verifier selection, API keys and real OIDC scope/invalid-audience behavior. |
| 13 | Make XSUAA JWKS/network failures terminal | **Not adopted.** SAP checks audience before signature/JWKS, but the audience is still unsigned. A network failure does not authenticate the principal or issuer. Making it terminal is a separate availability/composition policy and would change the documented OR behavior. Keep independent-verifier fallback and the direct-XSUAA-only guidance; never use a weaker alternative for the same XSUAA trust. |
| 14 | Inherited scopes and identity metadata | **Narrow hardening applied.** The real SDK reproduces an inherited local Admin scope on an otherwise signed token without an own scope. Require an own scope claim before SAP scope checks, with default and opt-in controls. This is pre-existing defense in depth, not evidence of a remotely reachable pollution source. Do not rewrite every SAP identity/audience accessor or assert complete SDK prototype resistance; delegated metadata semantics remain SAP-owned and metadata is not a target grant. |
| 15 | Consumers can inherit optional `extra` fields | **Consumer guidance clarified.** Optional chaining is not provenance validation. Check own data fields and valid status/shape, or consume the configured XSUAA verifier directly. ARC-1 already checks every relevant layer; no ARC runtime change or new public principal/provenance API is needed here. |

## Reproduction and patch boundary

Before production edits, new real-SDK tests failed in eight cases: two HTTP wire-code assertions,
two MCP client flows, three throwing-logger stages, and inherited local scope extraction.
The chain regression group failed in ten cases, and five positive type fixtures failed compilation.
After the patch, the same triggers pass. Fixtures use generated local RSA keys, reserved synthetic
issuers and loopback HTTP; only the SAP SDK's JWKS retrieval is stubbed. They do not prove live
XSUAA issuance or customer IAM behavior.

The shared boundaries remain the SDK-verified security context, the principal-specific error,
and verifier composition. No JWT decoder, new OAuth scope, blanket client-ID restriction,
target policy, implicit facade option or persistence layer is introduced. Diagnostic failures
are isolated rather than treated as authentication failures. Existing valid users, machine-token
compatibility when not opting into user-only mode, ordinary independent fallback, required-scope
checks and the existing sparse/frozen attribute contract remain covered.

## Verification

1. **Static/API:** `npm run typecheck` passed, including positive literal/Record fixtures and
   negative unsafe-access/mutation fixtures. `npm run lint` and `git diff --check` passed.
   The existing Biome schema-version information notice remains (2.5.12 config / 2.5.13 tool).
2. **Triggers and legitimate controls:** `npm test` passed **374 tests / 15 files** on Node
   22.18.0 and 24.11.1. The same cases that reproduced the failures above now reject terminally,
   preserve independent fallback, or return the expected safe attributes/scopes. Native middleware
   still returns 200 for valid access, 401 for invalid tokens and an ordinary scope challenge for
   insufficient scopes; forbidden principals do not start another OAuth flow.
3. **Peer matrix:** typecheck and all 374 tests passed with SDK/Express **1.18.2/5.0.1**,
   **1.25.3/5.0.1**, **1.28/5.2.1**, **1.29/5.2.1**, and the restored lockfile's
   **1.30.0/5.2.1**. The first floor run exposed two test assumptions about newer SDK diagnostics
   (structured error `.code`, optional scope header parameter); tests now assert behavior shared
   by all supported peers without removing the one-request/no-OAuth-work checks. The floor rerun
   passed. `npm ci` restored the lockfile installation and the checks were rerun; neither manifest
   nor lockfile changed.
4. **Package:** `npm run build`, `npm run check:exports` (publint and attw's existing ESM-only
   profile), and `npm audit --audit-level=high` passed. Audit reported **zero vulnerabilities**.
5. **Independent candidate review:** a fresh read-only reviewer found no concrete surviving
   bypass or regression. Its 14 bounded runtime checks covered both JWT slots, direct/cross-copy/
   wrapped/256-deep denials, inherited exception fields, throwing diagnostics, signed real-SDK
   user/machine tokens, inherited scope versus an own-scope control, and native forbidden 403.
   It also compiled the public-type fixture. This is an additional local check, not live SAP proof.

## Deliberately open release evidence

This follow-up does **not** re-run live BTP acceptance or close two-human-application/same-name
attribute provenance, distinct-origin/tenant isolation, or stale-session/refresh/revocation
acceptance. See the [current contract](../USER-ATTRIBUTES.md) and
[immutable ARC-1 live record](https://github.com/arc-mcp/arc-1/blob/cb7da96672915b0ab82e3e3724bcd0418f2564d5/docs/research/2026-09-15-pr677-target-authorization-implementation.md).
Do not treat the earlier machine wrong-audience test or new local signed fixtures as human
cross-application proof. The PR remains a draft candidate, not a released dependency.

## Primary protocol/SDK evidence

- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization):
  403 scope challenges initiate scope step-up; a principal-policy denial is not solvable by more scopes.
- [RFC 6750 §3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1): the semantics of
  `insufficient_scope`. `forbidden` here is explicitly a library wire code, not a claim that RFC 6750
  registers that error value.
- Installed MCP SDK `server/auth/middleware/bearerAuth` and `client/streamableHttp`, and SAP
  `@sap/xssec` 4.15 `service/Service`, `service/XsuaaService`, `token/XsuaaToken`: traced directly
  and exercised with the package's peer matrix rather than relying on mocked HTTP error semantics.

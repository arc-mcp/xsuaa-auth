# PR #70: third Claude review, independently checked

Starting revision: `885f5ae932f80e9076663ece4ddfba9691a2f0e8` in
[PR #70](https://github.com/arc-mcp/xsuaa-auth/pull/70). This follow-up changes only the
library candidate, tests and documentation. It does not release, merge, deploy, change IAM
configuration, or enable ARC-1 target enforcement. The supplied review is evidence to check,
not authority to broaden the authorization contract.

## Disposition

| Reported issue | Decision and implementation |
|---|---|
| Async logger rejection terminates Node | **Fixed.** Consume returned Promise/thenable rejections as well as synchronous sink exceptions. Do not await diagnostic delivery. Strict-policy child processes exercise native and foreign-realm rejected Promises, rejecting thenables and throwing `then` getters. Real SAP-SDK user/machine fixtures cover async failures at verifier start, denial and success. Unreturned async work and synchronously blocking consumer loggers are not supervised. Audits remain outside this wrapper. |
| Default-path SDK test doubles break | **Defensive normalization, not a production compatibility rollback.** Missing/malformed `token.payload` becomes `InvalidTokenError` rather than a raw TypeError. Actual validated xssec contexts contain a payload. Test doubles must model an own signed scope claim to grant scopes; a `checkLocalScope()`-only double is not evidence that inherited scopes should be accepted. No unsafe scope fallback is restored. |
| `Object.entries` / `Object.values` infer `unknown` | **Fixed and compile-tested.** Replace the unknown intersection with a sparse-Record/null-prototype union. Preserve readonly arrays, absent-key `undefined`, ordinary literal/Record assignment and rejection of unguarded Object-method calls. Positive iteration and negative mutation/type-erasure fixtures pin the contract. The report did not supply its proposed interface patch; do not assume every interface rewrite preserves these properties. Runtime extraction/freezing is unchanged. |
| Proxy exception/cause traps throw or invent endless causes | **Fixed with controlled failure.** Recognize local denials by a private WeakSet brand, not prototype-traversing `instanceof`; normalize foreign own data codes as before. Detect Proxies before reflection, including revoked/callable causes. Opaque representations terminate with a fixed integration error (native middleware: generic 500), not fallback access and not a fabricated principal denial. Ordinary own-data cause chains and cycles retain their behavior. |
| OIDC inherits primary / `scp` grants | **Narrow defense in depth.** Read only own primary and secondary scope claims after jose validation. Preserve string/array precedence, accepted-scope filtering and the explicit fallback option. Signed fixtures assert inherited claims grant nothing while own claims still work. No remotely reachable prototype-pollution source was established. |
| Diagnostic argument construction can select fallback | **Fixed with a separate core-result boundary.** Guard optional diagnostic projection and safe exception formatting. Keep successful verifier results outside the validation-failure catch. Reject malformed core `AuthInfo` terminally instead of silently accepting it or granting via fallback. HTTP tests include middleware without required scopes: a future-expiry malformed result must not become 200. Valid results retain their identity and ordinary independently trusted alternatives still work. |
| Logger gets an extra `undefined` argument | **Fixed.** Calls without fields pass one argument; calls with fields pass two. Preserve the sink's receiver. Tests assert both outside the best-effort wrapper, so a swallowed test assertion cannot hide a failure. |
| Shared constant breaks `--isolatedDeclarations` | **Fixed locally.** Explicitly annotate the denial code with its literal constant type. A separate consumer fixture pins the literal. The repository still has a pre-existing annotation error on `RESERVED_OAUTH_SCOPES`; this patch does not enable the flag globally or claim a clean full isolated-declarations build. |
| Principal denial prevents retries in every MCP client | **Narrowed documentation.** The runtime one-request/no-OAuth assertions cover the tested TypeScript SDK versions only. Inspector and VS Code source recovery paths are broader; their installed-client behavior remains a separate acceptance test. Removing challenge headers does not establish a fix. Keep the native 403 mapping; do not add an unproven custom adapter. |
| README says it “preserves” rebuilt errors | **Clarified.** Preserve the terminal decision. Unwrapping a locally constructed denial retains that denial's identity; cross-copy own-code errors are normalized to the fixed local SDK-compatible error. No original wrapper/provider message is promised. |
| Three boundary mutants survive | **Unverified.** No mutation patches, exact locations, commands or outputs were supplied. Do not invent the mutants, mark them fixed, or claim complete mutation coverage. Obtain those artifacts for a targeted follow-up. New regression cases here cover independently reproduced behavior. |

The report's discarded `AggregateError`, consumer-wrapped direct-route error and inherited-expiry
proposals are not adopted. Only own `cause` wrappers are promised; the library does not inspect
arbitrary error collections or replace SAP validation. A blanket terminal XSUAA JWKS/network
policy remains declined: unsigned claims cannot establish a principal denial, and independent
OR-composition is an existing API contract. Use the XSUAA verifier directly on user-only routes.

## Reproduction and controls

Before production edits:

- `npm run typecheck` failed with five errors in new iteration fixtures: values/entries became
  `unknown`, preventing normal typed loops.
- `npx vitest run tests/diagnostic-logger.test.ts` failed six cases: three argument-count checks
  and three child-process crashes under `--unhandled-rejections=strict`. The pending-sink/audit
  control passed.
- `npx vitest run tests/verifier-boundaries.test.ts tests/verifiers.test.ts` failed 31 cases and
  passed 53: optional metadata, malformed results, unsafe exception inspection/coercion, opaque
  causes, own denial codes on Proxy prototypes, and inherited OIDC claims reproduced the issues.
  The pre-fix fresh-cause fixture deliberately caps its trap calls instead of hanging the runner.
- `npm exec tsc -- --noEmit --isolatedDeclarations` reported the new denial-code annotation
  error and the existing `RESERVED_OAUTH_SCOPES` error. After the annotation fix only the latter
  remains.

New post-patch regressions also cover malformed SDK doubles, asynchronous logging through actual
SAP signature validation, and safe HTTP 500 responses with no alternative-verifier grant. Existing
tests retain native 200/401/403, genuine missing-scope challenges, signed user/machine fixtures,
single-option/default compatibility, ordinary independent fallback, finite/deep/cyclic causes,
cross-copy normalization, attribute limits and immutable outputs. Generated local RSA keys and
loopback servers are test fixtures, not evidence of live customer IAM behavior.

The independent candidate review found one regression in the initial patch: requiring a string
client ID rejected SAP-valid multi-audience tokens without `azp`, whose SDK accessor returns
`null`. Two real-SDK regressions reproduced the candidate failure with options off/on. The final
check validates token/scopes without adding a client-ID gate; both regressions also require
native HTTP 200, no fallback call, and a successful single-audience control. No metadata is
invented or substituted, and this is not a same-application provenance check.

## Verification record

1. **Static/API:** `npm run typecheck` passes, including the positive/negative consumer fixtures.
   The iteration fixtures also compile using the installed transitive TypeScript 5.6.1-rc
   compiler, in addition to the project's TypeScript 7.0.2. `npm run lint` and `git diff --check`
   pass; the pre-existing Biome schema-version information notice remains. The optional
   `--isolatedDeclarations` probe has only the pre-existing constant error described above.
2. **Triggers and legitimate behavior:** `npm test` passes **427 tests / 17 files** on Node
   **22.18.0** and **24.11.1**. The reproduced issues no longer occur: diagnostics do not crash
   the strict child processes or change selection; opaque causes terminate without traps;
   malformed results never grant fallback access; inherited OIDC scope claims grant nothing;
   typed iteration compiles. SAP-valid multi-audience and ordinary/default flows remain accepted.
3. **Peer matrix:** typecheck and all 427 tests pass with SDK/Express **1.18.2/5.0.1**,
   **1.25.3/5.0.1**, **1.28.0/5.2.1**, **1.29.0/5.2.1**, and the restored lockfile's
   **1.30.0/5.2.1**. The first harness attempt stopped because `npm ls` flags deliberate
   lower-peer installs as inconsistent with the newer root devDependency ranges; no test ran in
   that attempt. Direct package-version inspection replaced that harness gate, and the matrix
   passed. `npm ci` restored the committed dependency graph; manifest and lockfile are unchanged.
4. **Package:** `npm run build`, `npm run check:exports` (the existing ESM-only profile), and
   `npm audit --audit-level=high` pass on the restored graph, with **zero vulnerabilities**.
   The temporary legacy floor installation reported dependency advisories; compatibility tests
   are not a recommendation to deploy old dependencies or an assertion that those graphs are
   advisory-free.
5. **Independent review:** the fresh read-only candidate reviewer identified the nullable-client
   regression above. The parent reproduced it, corrected the check, and reran the focused tests,
   full suite, peer matrix and package checks. The reviewer reported no other concrete bypass;
   this was one independent review cycle, not a claim of exhaustive security proof.

No live BTP/IAS test is needed to reproduce these JavaScript/type issues, and none of these checks
closes the remaining live release gates below. No temporary generated JavaScript remains in
`src/`, and no credentials, tokens, dependency/version changes or unrelated edits are included.

## Release gates deliberately still open

Finish two-human-application/same-name attribute provenance, distinct-origin/tenant isolation,
and the customer's acceptable stale-session/refresh/revocation window. Validate retry/recovery
behavior in the actual supported customer client versions. Do not turn the earlier machine-token
wrong-audience check, synthetic signed fixtures or a passing TypeScript SDK transport test into
broader proof. See the [current contract](../USER-ATTRIBUTES.md) and
[immutable ARC-1 live record](https://github.com/arc-mcp/arc-1/blob/cb7da96672915b0ab82e3e3724bcd0418f2564d5/docs/research/2026-09-15-pr677-target-authorization-implementation.md).

## Primary implementation evidence

- [Node unhandled-rejection policy](https://nodejs.org/api/cli.html#--unhandled-rejectionsmode)
  and [TypeScript void-return assignability](https://www.typescriptlang.org/docs/handbook/2/functions.html#return-type-void)
  explain why a void-typed logger can still return a rejected Promise.
- Inspector source at `2e90a628e6296c62e4bef942afbb43d3faa4baf4`:
  [challenge classification](https://github.com/modelcontextprotocol/inspector/blob/2e90a628e6296c62e4bef942afbb43d3faa4baf4/core/auth/challenge.ts#L263),
  [401/403 interception](https://github.com/modelcontextprotocol/inspector/blob/2e90a628e6296c62e4bef942afbb43d3faa4baf4/core/mcp/node/authChallengeFetch.ts#L15),
  and [client recovery](https://github.com/modelcontextprotocol/inspector/blob/2e90a628e6296c62e4bef942afbb43d3faa4baf4/core/mcp/inspectorClient.ts#L3115).
  These are source observations, not an executed Inspector acceptance test.
- VS Code source at `d211d0584defa3fe9adce93b2ee971981162abeb`:
  [MCP authentication recovery](https://github.com/microsoft/vscode/blob/d211d0584defa3fe9adce93b2ee971981162abeb/src/vs/workbench/api/common/extHostMcp.ts#L805).
  It handles 401/403 independently of this package's denial code. Header removal alone is not
  sufficient evidence of non-retry behavior; no custom adapter is added on that assumption.

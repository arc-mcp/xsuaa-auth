# PR #70: independent review of Claude's findings

Scope: the candidate verified XSUAA attributes / optional user-principal enforcement in
[PR #70](https://github.com/arc-mcp/xsuaa-auth/pull/70), reviewed against starting revision
`5329061` and SAP `@sap/xssec` 4.15.0. Claude's findings are inputs, not established facts.
No IAM configuration, CF deployment, package publication or default auth policy is changed by
this review. Both verifier options remain opt-in; the facade does not enable them implicitly.

## Disposition of all 15 findings

| # | Finding | Decision and evidence |
|---|---|---|
| 1 | Foreign-client XSUAA tokens supply user attributes | **Live proof still required; no blanket client-ID restriction.** A signed local fixture with a foreign `azp`/client ID and accepted local audience passes the actual SAP SDK and exposes attributes. This proves SDK behavior, not that live XSUAA issues the claimed cross-application grants. SAP supports delegated audiences/foreign scopes; requiring equality with the binding client ID can break that legitimate flow. Document provenance limits and retain two-human-application/same-name-attribute and cross-origin gates. |
| 2 | JWKS outage lets a machine token fall through to OIDC | **Composition risk documented; generic fallback preserved.** An ordinary XSUAA validation failure permits independent alternatives by contract. If an alternative trusts the same tokens with a weaker principal policy, the consumer has overlapping policies. Unverified claims cannot safely trigger terminal user classification. ARC-1's enforced routes use XSUAA directly, so the proposed chain bypass is not their path. |
| 3 | Forbidden-principal rejection emits no log line | **Fixed.** Add a fixed debug denial code, without token contents, attributes, email or username. Tests assert the event and absence of those values. The logger remains injected/no-op by default. |
| 4 | Principal rejection maps to HTTP 500 in `requireBearerAuth` | **Fixed.** Reproduced through Express and the actual MCP SDK. The exported error now extends `InsufficientScopeError`, preserving its stable principal-specific code/message while native middleware returns 403. Wrong signatures remain 401 and valid users 200; direct and chained paths are covered. |
| 5 | `getUserName()` comparison is always true with real xssec | **Simplified, not a separate bypass.** The SDK formats the same origin/logon fields. Remove the redundant equality and impossible mock-only mismatch expectation, retaining grant/type/nonblank/origin-slash checks. This never establishes physical human presence or an SAP account. |
| 6 | Validate-before-classify ordering not tested | **Coverage added.** Signed but expired, wrong-signature and wrong-audience machine fixtures must fail as invalid tokens. Spies assert neither principal classification nor attribute extraction runs before successful SDK validation. |
| 7 | Single-option valid-user paths untested | **Coverage added.** Actual-SDK valid users succeed in attributes-only, principal-only and neither-option modes; shape assertions distinguish the two optional outputs. |
| 8 | Inherited Object.prototype values become valid grants | **Hardening fixed.** The old accessor could return inherited values as grants in an already prototype-polluted process. No prototype-pollution entry point in this package was established. Require own fields at every attribute-container level of the SDK-verified payload and an own allowlisted name. The independent candidate review also found inherited principal evidence; reproduced and added own `grant_type`/`origin`/`user_name` guards. Attribute nesting, principal fields individually/together, valid signed-user controls and malformed array/string containers are covered. |
| 9 | Machine token indistinguishable from attribute-less user | **Intentional compatibility behavior clarified.** Attribute-only mode does not enforce a user principal; its `missing` statuses are not an authentication decision. Consumers needing user-only behavior must also set `requireUserToken`. Do not add a new principal API or break existing machine-token consumers to change this status. |
| 10 | Attribute record type hides omitted names and null prototype | **Fixed.** Public sparse dictionaries include `undefined` for absent keys and exclude Object.prototype methods. Compile-only negative tests cover unsafe indexing, instance-method calls and mutations; documented safe alternatives are optional access and `Object.hasOwn`. |
| 11 | Rejected names' bytes count toward the global budget | **Fixed.** Accumulate a name's bytes only after that candidate passes per-name validation. A malformed/oversized name no longer poisons an unrelated valid name; overflow across valid candidates still rejects all names without truncation and independently of allowlist order. |
| 12 | Chain terminal rethrow keyed only on class identity | **Fixed.** Recognize `XSUAA_USER_TOKEN_REQUIRED` on a verifier exception from another package copy and normalize to the local SDK-compatible error. Never trust a request/token field or copy an arbitrary exception message. A regression test asserts no alternative verifier runs. |
| 13 | Chain JSDoc/SPEC stale after terminal rethrow | **Fixed.** Document the difference between authentication failures and authenticated-principal authorization denial. Remove the false claim that configured JWT trust domains must be disjoint. |
| 14 | Documented limits not pinned by boundary tests | **Coverage added.** Include exact 64-character names, 1,023/1,024/1,025 value-byte and entry boundaries, multibyte UTF-8, and 65,535/65,536/65,537 aggregate bytes. Exact-boundary acceptance asserts the full values, not statuses alone. Oversized arrays remain untraversed. |
| 15 | Public export section comment misplaced | **Corrected.** Label the verified-attribute/principal exports separately from OAuth provider exports. No API or runtime change. |

## Boundary and compatibility checks

The narrow enforcement point is the already SDK-verified security context. No new JWT decoder,
unverified claim classification, target wildcard interpretation, IAM storage, scope expansion or
cross-application trust rule is introduced. Extraction preserves nullish extension/root
precedence and the SDK's individual falsy-value compatibility; malformed containers and inherited
values cannot become grants. Default verifier behavior is unchanged when both options are omitted.

The foreign-client fixture with no local scopes is not itself an ARC-1 access bypass: ARC-1's
multi-target HTTP boundary separately requires local `read` before exposing target membership,
and its dispatcher enforces scopes again. Delegated tokens with local scopes still require the
unresolved live same-named-attribute provenance check; this distinction does not dismiss that gate.

The 403 transport uses the SDK's existing `insufficient_scope` error category. Applications that
want a principal-specific response can retain their custom adapter and use the stable code. A
machine principal cannot fix this rejection by consenting to more scopes. The special chain
handling only applies after a verifier returns the typed/coded terminal denial; independent
authentication failures continue to fall back.

### Reproduction and regression evidence

Before the production changes, focused regression tests reproduced native SDK HTTP 500, inherited
attribute lookup, malformed container acceptance, missing denial logging, aggregate-byte
contamination and cross-copy terminal-error fallback. After the changes, these same triggers must
yield the specified 403/empty-or-invalid attributes/safe logs/isolated limits/terminal error.
The classification-order and single-option findings were coverage gaps, not observed production
failures. The independent read-only candidate review found the sibling principal-field inheritance
path. Separate real-SDK regression tests reproduced it before the guard and verify its rejection
afterward, including the same valid signed user under the polluted prototype. No other concrete
regression was reported. Compile-only fixtures are part of `npm run typecheck`, not assertions
hidden in Vitest's transpile-only path.

Final local verification after the candidate-review correction:

1. **Static/API gate:** `npm run typecheck` (including the negative compile fixtures),
   `npm run lint` and `git diff --check` passed. Biome emits a pre-existing non-failing schema
   version notice (2.5.12 configuration / 2.5.13 tool); this review does not change that setting.
2. **Trigger and legitimate controls:** `npm test` passed **342 tests in 15 files**, on Node 22
   and Node 24. This includes real-SDK invalid-token rejection, own-property guards, 200/401/403
   HTTP behavior, all option combinations and default compatibility.
3. **Supported peers:** after each `npm install --no-save` peer override, `npm run typecheck`
   and `npm test` passed (342 tests each) for SDK/Express **1.18.2/5.0.1**, **1.25.3/5.0.1**,
   **1.28/5.2.1** and **1.29/5.2.1**. `npm ci` restored the committed lockfile afterward;
   no dependency/version changes are included.
4. **Package gate:** `npm run build`, `npm run check:exports` (publint and attw's existing
   ESM-only profile), and `npm audit --audit-level=high` passed; audit reported zero vulnerabilities.
   The restored lockfile installation was typechecked, tested, built and export-checked again.

Local signed-token fixtures use real signature, expiry and audience validation with only JWKS
retrieval stubbed; they are not a substitute for real XSUAA issuance. This review does not claim
to rerun live BTP acceptance or close the remaining live gates below.

## Remaining release evidence

The resumed ARC-1 live tests already established IAS-only/static-plus-IAS union, two-human
disjoint concurrency, unrelated-group exclusion and fresh-session recovery after group removal.
Do not list those as untested. Conversely, do not call old-token or stale-refresh access a
revocation pass: refresh retained the removed grant and issued a new one-hour token lifetime.

Still required for the promised deployment recipe: two human applications sharing an attribute
name, distinct identity-origin/tenant isolation, and agreement/testing of the operational
stale-session recovery/revocation window. A simple `cid === binding.clientid` rule, extra scope
request or short access-token lifetime has not been demonstrated to solve those questions.

See the [contract and SAP sources](../USER-ATTRIBUTES.md) and
[ARC-1's detailed live record](https://github.com/arc-mcp/arc-1/blob/codex/xsuaa-target-authorization-spec/docs/research/2026-09-15-pr677-target-authorization-implementation.md).

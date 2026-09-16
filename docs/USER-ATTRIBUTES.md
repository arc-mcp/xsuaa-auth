# Verified XSUAA user attributes

Status: additive implementation candidate for ARC-1 PR 677; not released. No XSUAA service,
role, assignment, deployed application, or package version is changed by this document.

## Public contract

`createXsuaaTokenVerifier(credentials, { userAttributeNames, requireUserToken })` retains its
existing `Verifier` return type. Both options default to omitted. Do not enable them implicitly
in the facade or for existing library consumers.

After successful `@sap/xssec` verification, the allowlisted values appear in
`AuthInfo.extra.xsuaaUserAttributes` with an accompanying
`AuthInfo.extra.xsuaaUserAttributeStatus` record. These records and value arrays are readonly
and frozen; the source token arrays are never retained as the returned arrays.
Both records have a null prototype and sparse string keys. Their types include `undefined` for
absent names and exclude Object.prototype methods: use optional access (for example,
`attributes.arc1_targets?.includes('A4H/100')`) and `Object.hasOwn(record, name)`, not
`record.hasOwnProperty(name)`. The enclosing SDK `AuthInfo.extra` object is not promised to be frozen.

| Status | Values record |
|---|---|
| `valid` | A copied string array, including valid-empty `[]` |
| `missing` | Name omitted |
| `invalid` | Name omitted; no partly accepted list |
| `limit_exceeded` | Name omitted; no partly accepted list |

Allowlist limits: 16 distinct printable-ASCII names, 64 characters per name, no whitespace or
prototype-reserved names. Duplicate names are deduplicated; the validated allowlist is copied
at verifier construction. Invalid runtime option types fail construction without exposing input.

Extraction limits: 1,024 entries per attribute, 1,024 UTF-8 bytes per string, and 64 KiB combined
bytes from otherwise valid candidates. Oversized arrays are rejected before traversal/copying;
their values are not extracted. An individually oversized string or malformed list rejects only
that name and does not consume the aggregate budget for other names. A combined-byte
overflow invalidates every requested name, including otherwise missing names, independent of
allowlist order. Duplicates count toward limits; application-specific normalization is not done
here. Empty strings/whitespace elements, mixed arrays, and non-string scalar values are invalid.

The package reads only **own properties of the SDK-verified payload**. It preserves the SDK's
`ext_cxt['xs.user.attributes'] ?? payload['xs.user.attributes']` precedence, but rejects non-record
containers and never promotes inherited properties into signed grants. It does not decode an
unverified JWT. SAP's `getAttribute()` falsy-to-null compatibility is retained for individual
values: an empty scalar string, false or zero is `missing`, not `invalid`. This does not make a
malformed attributes container valid. An empty own extension record overrides the root record;
a missing/null extension claim can fall back to an own root claim, a malformed one cannot.

## User-principal classification

The candidate accepts only `authorization_code`, `refresh_token`, and
`urn:ietf:params:oauth:grant-type:jwt-bearer` grant values, together with nonblank SAP `getOrigin()`
and `getLogonName()` strings. The verified payload must own the `grant_type`, `origin` and
`user_name` fields that back these accessors; inherited values cannot establish a principal.
SAP's `getUserName()` formats those same values as
`user/<origin>/<logonName>`; comparing that formatted string supplies no independent evidence.
SAP rejects `/` in the origin when constructing that principal, so this guard is retained.
An email, arbitrary subject,
or nonempty attributes is not evidence of a user. A machine token carrying Admin scopes still
fails. Unknown grants fail closed; old `user_token` and password flows are not silently added.

This is a user-principal test, not proof that a physical human is currently present or that SAP
has an account for the user. Only a context returned by `XsuaaService.createSecurityContext()`
may reach the classifier. A refreshed token can retain the original authorization-code grant;
that is already accepted.

When only attribute extraction is enabled, a machine/unknown principal has no exposed attributes
and all requested names are `missing`. With `requireUserToken: true`, it throws
`XsuaaUserTokenRequiredError` before returning `AuthInfo`. The error has a fixed message and code,
no claims, raw token, or provider error. The application's HTTP adapter maps this type to generic
403 and ordinary token-validation failures to 401. The class extends the SDK's
`InsufficientScopeError`: native `requireBearerAuth` works directly and returns 403 with
`insufficient_scope`. Custom adapters can use the stable `XSUAA_USER_TOKEN_REQUIRED` code to
return their own generic 403. Extra scope consent cannot convert a machine principal into a user.
Only the fixed denial code is logged; no token, attributes or user identifiers are added.

The chained verifier never falls through to OIDC/API-key authentication after this failure. It
also recognizes the stable code from another installed copy of this package and normalizes it
to the local SDK-compatible error, without copying an arbitrary provider message. This code is
read from a **verifier exception**, never a token claim or request parameter.

Attribute-only mode intentionally retains machine authentication compatibility: `missing` is
an extraction status, not proof that the principal is a user. Consumers that need user-only
authorization must also set `requireUserToken: true`.

## Trust and composition boundaries

- **Independent verifier alternatives:** the chain is an OR composition, not a shared user-policy
  wrapper. A signature/JWKS/expiry/audience failure still tries the next verifier. The package
  cannot classify unverified JWT claims as a terminal principal rejection. Avoid overlapping
  XSUAA/OIDC trust with a weaker OIDC policy (especially broad fallback scopes); use XSUAA directly
  on an XSUAA-user-only route. ARC-1 PR #677's enforced routes do so.
- **Audience is not same-client provenance:** SAP supports delegated/foreign-scope audiences. A
  locally signed fixture with another client ID and an accepted local audience demonstrates SDK
  acceptance, not that live XSUAA will issue arbitrary cross-application attributes. Neither
  verified attributes nor `AuthInfo.clientId` prove which application's role contributed a
  same-named attribute. The SDK's client accessor can derive from `azp` or a sole audience; it is
  not a substitute for a proven provenance rule. Require local scopes as well as attributes and
  retain the live two-application/same-name-attribute gate. A blanket client-ID-equality check is
  not added because it can reject legitimate SAP delegation.
- **SAP authorization remains separate:** these attributes do not establish a SAP account,
  Principal Propagation mapping, or permission to execute a particular SAP operation.

## Validation and what remains unproven

Local tests cover normalization/bounds, immutable results, option compatibility, machine and
unknown-principal rejection, terminal chain behavior, and real SAP SDK RSA signature/expiry/
audience validation with only the remote JWKS fetch stubbed. Synthetic grant fixtures are
**not live evidence** of XSUAA's emitted shape or role/IAS union behavior.

Live tests on 2026-09-15 used the candidate with an isolated ARC-1 CF application and XSUAA service:

- Actual IAS-backed authorization-code logins and user JWT-bearer exchanges passed SAP SDK
  verification and user classification. Verified contexts had nonblank origin/logon values and
  SAP's `user/<origin>/<logonName>` principal. Static attributes arrived as string arrays.
- A refreshed user token retained `grant_type=authorization_code` and passed classification.
  Refresh after a role addition retained old attributes; a reused browser login after Admin removal
  also retained old capabilities. Token exchange and interactive login are distinct test flows.
- Real client-credentials tokens with zero ARC scopes and with explicit `read`/`admin` authorities
  failed the user-only contract and received 403 from ARC's enforced HTTP routes.
- A real second application's machine token verified against its own service but failed with
  SAP SDK `wrong_audience` against the first. ARC returned 401. This does not yet prove the
  same-named-attribute boundary for two human application tokens or another identity origin.
- Exact values from multiple static roles were unioned. Real tokens with 50, 100 and 256 values
  retained every value and passed the CF edge; measured sizes were 3,473, 4,406 and 7,318 bytes
  for those fixtures. ARC's narrower target-grammar/size limits independently denied malformed
  or over-limit grants; the generic library correctly retained valid bounded string arrays.
- The resumed secondary-user session verified IAS-only values, exact static+IAS union, exclusion
  of an unrelated group and two distinct users' disjoint grants under concurrent calls. These
  are stronger than the earlier synthetic fixtures, but do not establish cross-origin or
  cross-application isolation.
- After temporary IAS group removal, an old positive token still worked. Refresh and a new code
  in a reused SSO session retained the old grant; refresh gave it a new one-hour token lifetime.
  A fresh private login and its refresh each passed 59 no-grant assertions. Fresh-session recovery
  is proven for this fixture; **one-hour token expiry is not a one-hour IAM revocation guarantee**.

Before release, finish cross-origin and same-named-attribute human-application isolation and agree
the customer's acceptable stale-session/refresh window and operational sign-out/re-login recipe.
If a supported flow's claim shape differs, adjust the narrow classifier and replay it; do not
relax it to email/sub presence. Never commit JWTs, credentials, user identifiers or full claims.
Detailed test boundaries and remaining gates are maintained in
[ARC-1 PR #677's validation record](https://github.com/arc-mcp/arc-1/blob/codex/xsuaa-target-authorization-spec/docs/research/2026-09-15-pr677-target-authorization-implementation.md).

The `@sap/xssec` 4.15 source validates XSUAA expiry/nbf, audience and signature; its binding-controlled
JWKS endpoint uses the token's zone and service credentials. It does not implement a simple
`iss === binding.url` string comparison. Tests must not claim a mocked local issuer mismatch
proves tenant isolation. The live wrong-application machine test above does not replace real
wrong-tenant/human-application tests.

## Source evidence

- SAP's published [`@sap/xssec` package](https://www.npmjs.com/package/@sap/xssec), version 4.15.0:
  `src/context/XsuaaSecurityContext.js` (`getAttribute`, `getUniquePrincipalName`, `getUserName`),
  `src/token/XsuaaToken.js` (verified attribute location and `sub` fallback), and
  `src/service/{Service,XsuaaService}.js` (validation and binding-controlled JWKS retrieval).
- [SAP Help: client libraries](https://help.sap.com/docs/authorization-and-trust-management-service/authorization-and-trust-management/client-libraries-for-sap-btp-security-services).
- [SAP token-client documentation](https://github.com/SAP/cloud-security-services-integration-library/blob/main/token-client/README.md):
  user JWT-bearer, refresh, and client-credentials are different flows; using a token exchange
  does not by itself prove the resulting principal is a user.
- [SAP Help: foreign scopes for tightly coupled developments](https://help.sap.com/docs/btp/sap-business-technology-platform/use-foreign-scope-option-for-principal-propagation-with-tightly-coupled-developments):
  explicit cross-application delegation is supported; equality to the receiving binding's client
  ID must not be assumed to be a universal SAP validation rule.

The [PR #70 review disposition](reviews/2026-09-16-pr70-claude-review.md) separates implemented
corrections, compatibility decisions and outstanding live proof.

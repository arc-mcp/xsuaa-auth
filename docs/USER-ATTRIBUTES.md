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
bytes from bounded candidates. Oversized arrays are rejected before traversal/copying; their
values are not extracted. An individually oversized string rejects that name. A combined-byte
overflow invalidates every requested name, including otherwise missing names, independent of
allowlist order. Duplicates count toward limits; application-specific normalization is not done
here. Empty strings/whitespace elements, mixed arrays, and non-string scalar values are invalid.

SAP's `getAttribute()` accessor uses a falsy-to-null compatibility rule: an empty scalar string,
false or zero can therefore appear as `missing`, not `invalid`. The package does not use a raw
JWT decoder to infer distinctions erased by that accessor.

## User-principal classification

The candidate accepts only `authorization_code`, `refresh_token`, and
`urn:ietf:params:oauth:grant-type:jwt-bearer` grant values, together with nonblank SAP `getOrigin()`
and `getLogonName()` strings and a matching `getUserName()` of `user/<origin>/<logonName>`.
SAP rejects `/` in the origin when constructing that principal. An email, arbitrary subject,
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
403 and ordinary token-validation failures to 401. The chained verifier must never fall through
to OIDC/API-key authentication after this typed failure.

## Validation and what remains unproven

Local tests cover normalization/bounds, immutable results, option compatibility, machine and
unknown-principal rejection, terminal chain behavior, and real SAP SDK RSA signature/expiry/
audience validation with only the remote JWKS fetch stubbed. Synthetic grant fixtures are
**not live evidence** of XSUAA's emitted shape or role/IAS union behavior.

Before release, preserve sanitized verified-context shape evidence from actual authorization-code,
refreshed user and JWT-bearer exchanges. Test machine tokens, two isolated application identities,
same-named attributes, wrong audiences, and IAS/static unions. If a supported flow's claim shape
differs, adjust the narrow classifier and replay it; do not relax it to email/sub presence. Never
commit JWTs, credentials, user identifiers, or full claims as fixtures.

The `@sap/xssec` 4.15 source validates XSUAA expiry/nbf, audience and signature; its binding-controlled
JWKS endpoint uses the token's zone and service credentials. It does not implement a simple
`iss === binding.url` string comparison. Tests must not claim a mocked local issuer mismatch
proves tenant isolation. Real wrong-tenant/application tests remain necessary.

## Source evidence

- SAP's published [`@sap/xssec` package](https://www.npmjs.com/package/@sap/xssec), version 4.15.0:
  `src/context/XsuaaSecurityContext.js` (`getAttribute`, `getUniquePrincipalName`, `getUserName`),
  `src/token/XsuaaToken.js` (verified attribute location and `sub` fallback), and
  `src/service/{Service,XsuaaService}.js` (validation and binding-controlled JWKS retrieval).
- [SAP Help: client libraries](https://help.sap.com/docs/authorization-and-trust-management-service/authorization-and-trust-management/client-libraries-for-sap-btp-security-services).
- [SAP token-client documentation](https://github.com/SAP/cloud-security-services-integration-library/blob/main/token-client/README.md):
  user JWT-bearer, refresh, and client-credentials are different flows; using a token exchange
  does not by itself prove the resulting principal is a user.

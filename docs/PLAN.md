# Auth Module — Implementation Plan

> **Refs:** [`SPEC.md`](./SPEC.md) (frozen contract), [`RESEARCH.md`](./RESEARCH.md) (rationale).
> **Hard constraints:** build + test **locally only** — **no GitHub repo**, no publish. **No auth-replacement PR in arc-1** (integration is a local worktree validation). The **only** arc-1 PR is the research + spec docs, at the very end.

## 0. Phases & gates

```
P1 Plan (this) ─ done ─▶ P2 Scaffold ─▶ P3 Core auth ─▶ P4 ./btp ─▶ P5 Tests+gates green
   ─▶ P6 arc-1 integration (worktree, local) ─▶ P7 BTP/CF live test ─▶ P8 arc-1 docs-PR
```
**Check-in gates:** after **P5** (module green standalone), after **P6** (arc-1 green with module), and **before P7 deploys anything** (confirm target app). cf-probe discipline throughout P7.

## 1. Folder layout (repo root)

```
package.json  tsconfig.json  biome.json  vitest.config.ts  .gitignore  README.md
RESEARCH.md  SPEC.md  PLAN.md
src/
  index.ts            # core `.` exports
  btp.ts              # `./btp` exports (PP)
  logger.ts           # Logger interface + noop default
  internal/sdk.ts     # ALL @modelcontextprotocol/sdk/server/auth/* imports (insulation, SPEC §8)
  redirect-uris.ts    # XSUAA_DEFAULT_* + validateRedirectUri/matchesRedirectPattern (fail-closed)
  dcr-client-store.ts # StatelessDcrClientStore (+ options)
  oauth-state.ts      # OAuthStateCodec (#214)
  xsuaa.ts            # XsuaaCredentials, createXsuaaTokenVerifier, qualifyXsuaaScopes
  oauth-provider.ts   # XsuaaProxyOAuthProvider, createXsuaaOAuthProvider
  verifiers.ts        # createApiKeyVerifier, createOidcVerifier (lazy jose), createChainedTokenVerifier
  callback.ts         # createOAuthCallbackHandler
  cors.ts             # built-in exact-match CORS (no `cors` dep)
  credentials.ts      # loadXsuaaCredentials, resolveAppUrl
  facade.ts           # setupHttpAuth
  btp/                # split of arc-1 src/adt/btp.ts
    vcap.ts           # parseVCAPServices, BTPConfig
    destination.ts    # lookupDestination, lookupDestinationWithUserToken (+JWT guard), resolveBTPDestination, Destination/PerUserAuthTokens
    connectivity.ts   # createConnectivityProxy, BTPProxyConfig
tests/                # vitest unit tests + fixtures (ported from arc-1)
examples/             # (later) minimal runnable consumer
```

## 2. package.json (deps per SPEC §4)
peer: `@modelcontextprotocol/sdk >=1.18.2 <2`, `express ^5.0.1`, `jose >=5 <7` (optional). dep: `@sap/xssec ^4`, `@sap-cloud-sdk/connectivity ^4.7.0`, `undici ^8`. dev: those peers (concrete in-range) + types + typescript + vitest + biome + publint + attw. ESM-only, `engines.node>=22`, exports map (`.`, `./btp`, `./package.json`).

## 3. Module port mapping (arc-1 → package)

| arc-1 source | → package | Changes |
|---|---|---|
| `src/server/stateless-client-store.ts` | `src/dcr-client-store.ts` + `src/redirect-uris.ts` | `ID_PREFIX`/`KDF_LABEL`→ctor opts; `XSUAA_*` lists → exported defaults + opts; **logger injected** (drop `./logger` import); `matchesXsuaaRedirectPattern`→`matchesRedirectPattern(uri, patterns?)` fail-closed |
| `src/server/oauth-state.ts` | `src/oauth-state.ts` | `KDF_LABEL`→opt; `ttl<=0`→no-expiry; else verbatim (no coupling today) |
| `src/server/xsuaa.ts` | `src/xsuaa.ts` + `src/oauth-provider.ts` + `src/verifiers.ts` | drop `expandScopes`(policy) + `API_KEY_PROFILES`(config) imports → **inject `expandScopes`**, accept `ApiKeyEntry[]`; logger injected; split provider/verifiers from token-verifier |
| `src/server/http.ts` (auth slice) | `src/verifiers.ts` (`createOidcVerifier` + `algorithms`), `src/callback.ts`, `src/facade.ts`, `src/cors.ts`, `src/credentials.ts` | lift `createOidcVerifier`/`extractOidcScopes`/`createStandardVerifier`/`createOAuthCallbackHandler` + the `applySecurityMiddleware` CORS bits + `getAppUrl`/binding-load helpers; assemble `setupHttpAuth` |
| `src/adt/btp.ts` | `src/btp/*` | **logger injected**; `parseVCAPServices(env?)`; **JWT-shape guard** in `lookupDestinationWithUserToken`; else verbatim |

## 4. New / changed logic vs arc-1
- **Logger:** structural `Logger` + noop default, optional trailing/`options.logger` param everywhere; `emitAudit?.()` null-guarded.
- **Knobs:** `clientIdPrefix`, `dcrKdfLabel`, `stateKdfLabel`, ttls, redirect patterns/defaults, `resourceName`, `scopesSupported`, `requiredScopes` as options (defaults per SPEC §6/§8).
- **Facade `setupHttpAuth`:** compose provider + chained verifier + `mcpAuthRouter` + callback + CORS; `required?` flag (warn/throw when open); no-XSUAA mode; **sets no restrictive COOP**.
- **`createOidcVerifier`:** `algorithms?` allowlist (default `['RS256','ES256','PS256']`).
- **`createApiKeyVerifier`:** `string | ApiKeyEntry[]`.
- **Helpers:** `loadXsuaaCredentials(env?)`, `resolveAppUrl(env?, {publicUrlEnvVar, port})`.
- **`./btp`:** JWT-shape guard; `parseVCAPServices(env?)`.
- **SDK insulation:** `internal/sdk.ts` is the only file importing the SDK auth subpaths.
- **tsconfig `isolatedDeclarations`:** OFF during the port (avoids fighting the compiler on lifted code); flip ON as a P5 polish once it compiles, adding explicit export types where needed.

## 5. Test plan — port arc-1 + add more (SPEC requires "same and maybe more")
**Port (adapt to injected logger/opts):** `stateless-client-store.test`, `oauth-state.test`, `xsuaa.test`, the btp tests.
**Add:**
- `verifiers.test` — chained order `XSUAA→OIDC→api-key`; api-key single vs list; **OIDC `alg:none`/disallowed-alg rejected**; `expandScopes` applied to output.
- `facade.test` — mounts router+callback; returns bearer middleware; `required:true` throws / default warns; no-XSUAA mode skips router; **CORS headers present for allowed origin, absent for others; no `COOP` header set**.
- `credentials.test` — `loadXsuaaCredentials` parse/validate (missing binding → throws); `resolveAppUrl` precedence (`publicUrlEnvVar` > VCAP route > host:port).
- `redirect-uris.test` — `validateRedirectUri` throws on malformed/disallowed; `matchesRedirectPattern` false on parse failure; **azure-apim (MS Copilot) + claude.ai patterns match**.
- `callback.test` — #214 state round-trip (`+` preserved); redirect_uri client-binding check fails closed.
- `btp/*.test` — `parseVCAPServices`; `lookupDestinationWithUserToken` **JWT guard throws on non-JWT**; the 3 PerUserAuthTokens shapes (mock `@sap-cloud-sdk/connectivity`); connectivity proxy descriptor + Option-2 jwt-bearer fallback.
**Local gates:** `npm run typecheck`, `npm test` (+ coverage), `npm run lint`, `npm run check:exports` (publint + attw esm-only). All green = P5 gate.

## 6. arc-1 integration (P6 — local worktree)
1. `git worktree add ../arc-1-authmod -b test/auth-module-integration main` (off arc-1 **main**, isolated from the MSAG branch / shared tree).
2. Add `"@arc-mcp/xsuaa-auth": "file:../arc-mcp-auth"` to the worktree's package.json (or `npm link`); `npm install`.
3. Apply SPEC §11 edits: swap imports in `src/server/http.ts` (auth slice) + `src/server/server.ts` + `src/adt/*`; **delete** `src/server/{stateless-client-store,xsuaa,oauth-state}.ts` + `src/adt/btp.ts`; map `ServerConfig`→`AuthOptions`; inject `config.logger` + `authz/policy.expandScopes`; build `ApiKeyEntry[]` from `API_KEY_PROFILES`.
4. Run arc-1's full local gate: `npm run build`, `npm run typecheck`, `npm run lint`, `npm test`. Fix to green. Confirm the auth + btp behavior is unchanged (existing arc-1 tests are the oracle). This **proves the minimal-diff + drop-in claims**.
5. Worktree is throwaway validation — not committed/pushed, not the docs-PR.

## 7. BTP/CF live test (P7)
- **cf liveness:** run `cf target` first and re-probe every few operations; if the token expired, pause and ask the user to `cf login` (interactive). Don't assume the session persists across long runs.
- **Deploy target — CONFIRM WITH USER FIRST.** Candidates: redeploy `arc1-mcp-test` (bound to `arc1-xsuaa-test`) from the integrated build, or a scratch app. **Do not touch `arc1-mcp-joule2`.** Deploying is outward-facing → explicit go-ahead before `cf push`.
- **Verify:** XSUAA OAuth + DCR round-trip (register → authorize → token), API-key path, `/mcp` bearer, `.well-known` OAuth metadata, the **azure-apim redirect (MS Copilot)** + claude.ai origin/CORS. Module must behave identically to current arc-1 in the live XSUAA flow.
- PP path not exercised (live uses the shared technical destination `SAP_TRIAL`).

## 8. Final — arc-1 docs-PR (P8)
- Branch off arc-1 **main** (clean; NOT `fix/msag-blank-sprsl-language`). Add `RESEARCH.md` + `SPEC.md` (+ `PLAN.md`) under e.g. `docs/research/auth-module/`.
- Commit **docs only**; push to `origin` (marianfoo); open PR. No module code, no auth replacement.

## 9. Risks / notes
- `isolatedDeclarations` friction → deferred to P5 polish (§4).
- `@sap/xssec` CJS interop in ESM → default-import+destructure (SPEC §12); verify at first compile.
- SDK floor typecheck (1.18.2) → add a floor-pinned `tsc` check in P5.
- Long BTP run → cf token expiry is the top operational risk (§7 probe discipline).
- Each phase reports before advancing past a gate.

# Examples

Runnable examples for `@arc-mcp/xsuaa-auth`. They are **not** part of the
published package (`files` ships `dist` only) and are **not** compiled by the
package build (`tsconfig.json` includes `src` only).

## `express-setup-http-auth.ts`

A tiny Express app that protects `/mcp` with the `setupHttpAuth` facade using an
API key, and additionally XSUAA OAuth when the process is bound to an XSUAA
service (`VCAP_SERVICES` set).

Run it with [`tsx`](https://github.com/privatenumber/tsx) (no build step needed):

```bash
# from the package root, after `npm run build`:
ARC_API_KEY=dev-secret-key npx tsx examples/express-setup-http-auth.ts
```

Then:

```bash
curl -H 'Authorization: Bearer dev-secret-key' http://localhost:3000/mcp   # authenticated stub
curl http://localhost:3000/mcp                                             # 401
curl http://localhost:3000/healthz                                         # public { status: ok }
```

The example imports from `@arc-mcp/xsuaa-auth`, so resolve the package first —
either install it (`npm i @arc-mcp/xsuaa-auth`) in a separate project, or run
the example from a checkout where the package is linked (`npm link` /
`file:` dependency).

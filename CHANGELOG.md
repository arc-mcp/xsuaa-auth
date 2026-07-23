# Changelog

## [1.0.0](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.8...v1.0.0) (2026-07-23)


### Bug Fixes

* align Biome schema with installed version ([4afc543](https://github.com/arc-mcp/xsuaa-auth/commit/4afc5438751c8a7ca8574c4936158560bf2462fc))

## [0.1.8](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.7...v0.1.8) (2026-07-20)


### Features

* add uncached and level-specific destination APIs ([#31](https://github.com/arc-mcp/xsuaa-auth/issues/31)) ([a54cbc5](https://github.com/arc-mcp/xsuaa-auth/commit/a54cbc5d9001ffeb9f4a4f0ee98f5ad1c94374d4))
* arc-mcp-xsuaa-auth 0.1.0 — XSUAA/OAuth + BTP PP auth for MCP servers ([245795d](https://github.com/arc-mcp/xsuaa-auth/commit/245795d36088f449868b8ba9e47c1f8af53bed34))
* **facade:** add oidc.acceptedScopes for OIDC-only deployments ([#14](https://github.com/arc-mcp/xsuaa-auth/issues/14)) ([35a9364](https://github.com/arc-mcp/xsuaa-auth/commit/35a9364b6e6a6b579bfd73811ce53f66ab8873e7))
* support for saml assertion destinations ([#21](https://github.com/arc-mcp/xsuaa-auth/issues/21)) ([645e998](https://github.com/arc-mcp/xsuaa-auth/commit/645e9985710a2afd04f04fd0770f189accad5419))


### Bug Fixes

* do not issue client_secret for public DCR clients (auth method "none") ([#6](https://github.com/arc-mcp/xsuaa-auth/issues/6)) ([a756986](https://github.com/arc-mcp/xsuaa-auth/commit/a7569860f0f49adc13c9f3ab0751771a8ba47c0f))
* exclude package.json from biome so release-please bumps do not break lint ([#8](https://github.com/arc-mcp/xsuaa-auth/issues/8)) ([c03413f](https://github.com/arc-mcp/xsuaa-auth/commit/c03413f4a47d725cd49ef3efd58c2db2482686a5))
* harden Destination Service Find handling ([#33](https://github.com/arc-mcp/xsuaa-auth/issues/33)) ([ba30e8d](https://github.com/arc-mcp/xsuaa-auth/commit/ba30e8de544d973fa5f6a60e7c97b1fc11123dca))
* harden XSUAA verifier + OAuth callback, export DEFAULT_ACCEPTED_SCOPES ([#17](https://github.com/arc-mcp/xsuaa-auth/issues/17)) ([84f7526](https://github.com/arc-mcp/xsuaa-auth/commit/84f7526cb76bc2315970dfb001775698832ec097))
* time out BTP service requests ([#35](https://github.com/arc-mcp/xsuaa-auth/issues/35)) ([70196f9](https://github.com/arc-mcp/xsuaa-auth/commit/70196f9d928cf990e80eb02d35abd41474020c50))

## [0.1.7](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.6...v0.1.7) (2026-07-20)


### Bug Fixes

* time out BTP service requests ([#35](https://github.com/arc-mcp/xsuaa-auth/issues/35)) ([70196f9](https://github.com/arc-mcp/xsuaa-auth/commit/70196f9d928cf990e80eb02d35abd41474020c50))

## [0.1.6](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.5...v0.1.6) (2026-07-19)


### Bug Fixes

* harden Destination Service Find handling ([#33](https://github.com/arc-mcp/xsuaa-auth/issues/33)) ([ba30e8d](https://github.com/arc-mcp/xsuaa-auth/commit/ba30e8de544d973fa5f6a60e7c97b1fc11123dca))

## [0.1.5](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.4...v0.1.5) (2026-07-17)


### Features

* add uncached and level-specific destination APIs ([#31](https://github.com/arc-mcp/xsuaa-auth/issues/31)) ([a54cbc5](https://github.com/arc-mcp/xsuaa-auth/commit/a54cbc5d9001ffeb9f4a4f0ee98f5ad1c94374d4))

## [0.1.4](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.3...v0.1.4) (2026-06-26)


### Features

* support for saml assertion destinations ([#21](https://github.com/arc-mcp/xsuaa-auth/issues/21)) ([645e998](https://github.com/arc-mcp/xsuaa-auth/commit/645e9985710a2afd04f04fd0770f189accad5419))


### Bug Fixes

* harden XSUAA verifier + OAuth callback, export DEFAULT_ACCEPTED_SCOPES ([#17](https://github.com/arc-mcp/xsuaa-auth/issues/17)) ([84f7526](https://github.com/arc-mcp/xsuaa-auth/commit/84f7526cb76bc2315970dfb001775698832ec097))

## [0.1.3](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.2...v0.1.3) (2026-06-18)


### Features

* **facade:** add oidc.acceptedScopes for OIDC-only deployments ([#14](https://github.com/arc-mcp/xsuaa-auth/issues/14)) ([35a9364](https://github.com/arc-mcp/xsuaa-auth/commit/35a9364b6e6a6b579bfd73811ce53f66ab8873e7))

## [0.1.2](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.1...v0.1.2) (2026-06-17)


### Bug Fixes

* exclude package.json from biome so release-please bumps do not break lint ([#8](https://github.com/arc-mcp/xsuaa-auth/issues/8)) ([c03413f](https://github.com/arc-mcp/xsuaa-auth/commit/c03413f4a47d725cd49ef3efd58c2db2482686a5))

## [0.1.1](https://github.com/arc-mcp/xsuaa-auth/compare/v0.1.0...v0.1.1) (2026-06-17)


### Features

* arc-mcp-xsuaa-auth 0.1.0 — XSUAA/OAuth + BTP PP auth for MCP servers ([245795d](https://github.com/arc-mcp/xsuaa-auth/commit/245795d36088f449868b8ba9e47c1f8af53bed34))


### Bug Fixes

* do not issue client_secret for public DCR clients (auth method "none") ([#6](https://github.com/arc-mcp/xsuaa-auth/issues/6)) ([a756986](https://github.com/arc-mcp/xsuaa-auth/commit/a7569860f0f49adc13c9f3ab0751771a8ba47c0f))

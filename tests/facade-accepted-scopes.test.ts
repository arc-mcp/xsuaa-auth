/**
 * M2 (facade threading): `setupHttpAuth` must pass `xsuaa.scopesSupported` (when
 * set) as `acceptedScopes` to BOTH the XSUAA and OIDC verifiers, so a consumer
 * with non-arc-1 scope names (e.g. calmcp's `Viewer`) does not lose its scopes.
 * S6 (facade threading): it must also thread `oidc.scopeClaim` and
 * `xsuaa.callbackUrl` through to the underlying factories.
 *
 * The verifier + provider factory modules are mocked so the test asserts the
 * OPTIONS the facade hands them (the real token path is covered in
 * verifiers.test.ts / xsuaa.test.ts). The mocks are isolated to this file (a
 * `vi.mock` is module-global within a file) so they can't leak into the
 * behavioral facade tests.
 */

import express from 'express';
import { afterEach, describe, expect, it, vi } from 'vitest';

// ── Capture-mocks for the factories the facade composes ──
const createXsuaaTokenVerifier = vi.fn(() => async () => ({ token: 't', clientId: 'c', scopes: [], extra: {} }));
const createOidcVerifier = vi.fn(() => async () => ({ token: 't', clientId: 'c', scopes: [], extra: {} }));
const createChainedTokenVerifier = vi.fn(() => async () => ({ token: 't', clientId: 'c', scopes: [], extra: {} }));
const createXsuaaOAuthProvider = vi.fn();

vi.mock('../src/xsuaa.js', () => ({ createXsuaaTokenVerifier }));
vi.mock('../src/verifiers.js', () => ({ createOidcVerifier, createChainedTokenVerifier }));
vi.mock('../src/oauth-provider.js', () => ({ createXsuaaOAuthProvider }));

// A minimal StatelessDcrClientStore + OAuthStateCodec stand-in for the provider
// mock. `registerClient` must exist — mcpAuthRouter probes it to decide whether to
// advertise the registration endpoint. The provider mock must expose `clientsStore`
// too (mcpAuthRouter reads `provider.clientsStore`).
const fakeClientStore = { ensureRedirectUri: vi.fn(), getClient: vi.fn(), registerClient: vi.fn() };
const fakeStateCodec = { encode: vi.fn(), decode: vi.fn() };
function fakeProviderResult(): {
  provider: { clientsStore: typeof fakeClientStore };
  clientStore: typeof fakeClientStore;
  stateCodec: typeof fakeStateCodec;
} {
  return { provider: { clientsStore: fakeClientStore }, clientStore: fakeClientStore, stateCodec: fakeStateCodec };
}
createXsuaaOAuthProvider.mockReturnValue(fakeProviderResult());

// Import the facade AFTER the mocks are registered.
const { setupHttpAuth } = await import('../src/facade.js');

const XSUAA_CREDS = {
  clientid: 'sb-x!t1',
  clientsecret: 'stub-secret-40-chars-long-AAAAAAAAAAAAAAAA',
  url: 'https://stub.authentication.eu10.hana.ondemand.com',
  xsappname: 'calmcp!t1',
  uaadomain: 'authentication.eu10.hana.ondemand.com',
};
const APP_URL = 'https://calmcp.example.com';

afterEach(() => {
  vi.clearAllMocks();
  // Re-prime the provider return after clearAllMocks wiped it.
  createXsuaaOAuthProvider.mockReturnValue(fakeProviderResult());
});

describe('setupHttpAuth — M2 acceptedScopes threading', () => {
  it('passes xsuaa.scopesSupported as acceptedScopes to the XSUAA + OIDC verifiers', () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    setupHttpAuth(app, {
      xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL, scopesSupported: ['Viewer'] },
      oidc: { issuer: 'https://issuer.example.com', audience: 'aud' },
    });

    expect(createXsuaaTokenVerifier).toHaveBeenCalledTimes(1);
    expect(createXsuaaTokenVerifier.mock.calls[0][1]).toMatchObject({ acceptedScopes: ['Viewer'] });

    expect(createOidcVerifier).toHaveBeenCalledTimes(1);
    expect(createOidcVerifier.mock.calls[0][2]).toMatchObject({ acceptedScopes: ['Viewer'] });
  });

  it('passes acceptedScopes:undefined (→ default set) when scopesSupported is unset', () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    setupHttpAuth(app, {
      xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL },
      oidc: { issuer: 'https://issuer.example.com', audience: 'aud' },
    });
    expect(createXsuaaTokenVerifier.mock.calls[0][1]).toMatchObject({ acceptedScopes: undefined });
    expect(createOidcVerifier.mock.calls[0][2]).toMatchObject({ acceptedScopes: undefined });
  });
});

describe('setupHttpAuth — S6 scopeClaim + callbackUrl threading', () => {
  it('threads oidc.scopeClaim into createOidcVerifier', () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    setupHttpAuth(app, {
      apiKeys: 'k',
      oidc: { issuer: 'https://issuer.example.com', audience: 'aud', scopeClaim: 'roles' },
    });
    expect(createOidcVerifier.mock.calls[0][2]).toMatchObject({ scopeClaim: 'roles' });
  });

  it('threads xsuaa.callbackUrl into createXsuaaOAuthProvider', () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    const callbackUrl = 'https://calmcp.example.com/custom/oauth/callback';
    setupHttpAuth(app, {
      xsuaa: { credentials: XSUAA_CREDS, appUrl: APP_URL, callbackUrl },
    });
    expect(createXsuaaOAuthProvider).toHaveBeenCalledTimes(1);
    expect(createXsuaaOAuthProvider.mock.calls[0][2]).toMatchObject({ callbackUrl });
  });
});

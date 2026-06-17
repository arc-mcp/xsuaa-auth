/**
 * XSUAA-proxying OAuth provider for MCP-native clients.
 *
 * Lifted from arc-1's `XsuaaProxyOAuthProvider` + `createXsuaaOAuthProvider`.
 * The crypto / control-flow is verbatim — the only adaptations are:
 *   - the package's `StatelessDcrClientStore` + `OAuthStateCodec` (parameterized
 *     via {@link CreateXsuaaOAuthProviderOptions}) instead of arc-1's local copies,
 *   - the injected structural logger (default no-op),
 *   - the SDK insulation import (SPEC §8).
 *
 * Extends ProxyOAuthServerProvider to replace the MCP client's local client_id
 * with the XSUAA service binding client_id when forwarding to XSUAA.
 *
 * Problem: MCP clients register via DCR and get a local client_id (e.g. "mcp-…").
 * But XSUAA only knows about its own client_id ("sb-arc1-mcp!t498139"). The
 * standard ProxyOAuthServerProvider forwards the local client_id to XSUAA, which
 * rejects it.
 *
 * Solution: override `authorize()` to swap the client_id and use a custom
 * `fetch()` for the token exchange to inject the XSUAA credentials. `authorize()`
 * additionally routes the OAuth return through this server's own `/oauth/callback`
 * (issue #214 callback proxy — XSUAA echoes a literal `+` in `state`).
 */

import { StatelessDcrClientStore } from './dcr-client-store.js';
import { ProxyOAuthServerProvider } from './internal/sdk.js';
import type { OAuthClientInformationFull } from './internal/sdk.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import { OAuthStateCodec } from './oauth-state.js';
import type { Verifier } from './types.js';
import type { XsuaaCredentials } from './xsuaa.js';
import { createXsuaaTokenVerifier, qualifyXsuaaScopes } from './xsuaa.js';

// ─── Types ───────────────────────────────────────────────────────────

/** OAuth token endpoint response shape */
interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

/**
 * XSUAA-proxying OAuth provider.
 *
 * Overrides `authorize`, `exchangeAuthorizationCode`, `exchangeRefreshToken`, and
 * `revokeToken` so every upstream call uses the XSUAA service-binding credentials
 * rather than the per-client DCR credentials.
 */
export class XsuaaProxyOAuthProvider extends ProxyOAuthServerProvider {
  private xsuaaClientId: string;
  private xsuaaClientSecret: string;
  private xsuaaTokenUrl: string;
  private xsuaaAuthUrl: string;
  private xsuaaXsappname: string;
  private _localClientStore: StatelessDcrClientStore;
  /** This server's own callback URL, sent to XSUAA as the redirect_uri so the
   *  server sits in the return path and can re-encode the client's `state`
   *  correctly (issue #214 — XSUAA emits literal `+`). */
  private callbackUrl: string;
  /** Signs/verifies the opaque, URL-safe state token sent to XSUAA. */
  private stateCodec: OAuthStateCodec;
  private readonly logger: Logger;

  constructor(
    credentials: XsuaaCredentials,
    verifier: Verifier,
    localClientStore: StatelessDcrClientStore,
    callbackUrl: string,
    stateCodec: OAuthStateCodec,
    logger: Logger = noopLogger,
  ) {
    const authUrl = `${credentials.url}/oauth/authorize`;
    const tokenUrl = `${credentials.url}/oauth/token`;

    super({
      endpoints: {
        authorizationUrl: authUrl,
        tokenUrl: tokenUrl,
        revocationUrl: `${credentials.url}/oauth/revoke`,
      },
      verifyAccessToken: verifier,
      getClient: (clientId: string) => localClientStore.getClient(clientId),
    });

    this.xsuaaClientId = credentials.clientid;
    this.xsuaaClientSecret = credentials.clientsecret;
    this.xsuaaTokenUrl = tokenUrl;
    this.xsuaaAuthUrl = authUrl;
    this.xsuaaXsappname = credentials.xsappname;
    this._localClientStore = localClientStore;
    this.callbackUrl = callbackUrl;
    this.stateCodec = stateCodec;
    this.logger = logger;
    this.skipLocalPkceValidation = true;
  }

  /**
   * Override clientsStore to expose registerClient for DCR.
   * The MCP SDK checks this to decide whether to advertise
   * registration_endpoint in OAuth metadata and handle POST /register.
   */
  override get clientsStore(): StatelessDcrClientStore {
    return this._localClientStore;
  }

  /**
   * Override authorize to replace the MCP client's local client_id
   * with the XSUAA service binding client_id.
   */
  override async authorize(
    _client: OAuthClientInformationFull,
    params: {
      state?: string;
      scopes?: string[];
      codeChallenge: string;
      redirectUri: string;
      resource?: URL;
    },
    res: { redirect(url: string): void },
  ): Promise<void> {
    // ── Callback proxy (issue #214) ──────────────────────────────────
    // Instead of sending XSUAA the client's redirect_uri and the client's
    // raw `state`, we send XSUAA this server's OWN /oauth/callback and an
    // opaque, URL-safe state token that carries the client's real redirect_uri
    // + state. XSUAA then redirects back to this server (not the client), and
    // the /oauth/callback route re-emits the client's ORIGINAL state with
    // proper `%2B` encoding. This sidesteps XSUAA's bug of echoing a literal
    // `+` for any state containing `+` (standard base64 states hit this ~50%
    // of the time; VS Code surfaces it as "State does not match").
    //
    // The token is base64url (no `+`/`/`), so XSUAA has nothing to mangle on
    // the round trip and Express's `+`→space decode is a no-op on it.
    //
    // WORKAROUND removal condition + upstream tracking (XSUAA root cause,
    // arc-1#214, vscode#314715) are documented at the top of oauth-state.ts.
    const proxyState = this.stateCodec.encode({
      clientState: params.state,
      clientRedirectUri: params.redirectUri,
      clientId: _client.client_id,
    });

    const targetUrl = new URL(this.xsuaaAuthUrl);
    const searchParams = new URLSearchParams({
      client_id: this.xsuaaClientId, // Use XSUAA client, not local DCR client
      response_type: 'code',
      redirect_uri: this.callbackUrl, // this server's callback, not the client's
      code_challenge: params.codeChallenge, // client's PKCE challenge, forwarded as-is
      code_challenge_method: 'S256',
      state: proxyState,
    });

    if (params.scopes?.length) {
      // Qualify short MCP scopes (read, write, admin) with the xsappname prefix
      // XSUAA requires, while leaving reserved OIDC scopes (openid, …) alone.
      const qualifiedScopes = qualifyXsuaaScopes(params.scopes, this.xsuaaXsappname);
      if (qualifiedScopes.length > 0) {
        searchParams.set('scope', qualifiedScopes.join(' '));
      }
    }
    if (params.resource) searchParams.set('resource', params.resource.toString());

    targetUrl.search = searchParams.toString();

    this.logger.debug('XSUAA authorize redirect (callback proxy)', {
      xsuaaClient: this.xsuaaClientId,
      clientRedirectUri: params.redirectUri,
      callbackUrl: this.callbackUrl,
    });

    res.redirect(targetUrl.toString());
  }

  /**
   * Override exchangeAuthorizationCode to use XSUAA credentials
   * instead of the local DCR client credentials.
   */
  override async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    _redirectUri?: string,
  ): Promise<{
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
  }> {
    this.logger.debug('XSUAA token exchange: authorization_code', {
      hasCodeVerifier: !!codeVerifier,
    });
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authorizationCode,
      client_id: this.xsuaaClientId,
      client_secret: this.xsuaaClientSecret,
    });
    if (codeVerifier) params.set('code_verifier', codeVerifier);
    // OAuth requires the token-exchange redirect_uri to match the one sent at
    // authorize time. Since the callback proxy sent XSUAA this server's own
    // /oauth/callback (not the client's redirect_uri), the exchange must use
    // the same value. The client's redirect_uri (_redirectUri) is irrelevant
    // to XSUAA here — XSUAA only ever saw this server's callback.
    params.set('redirect_uri', this.callbackUrl);

    const response = await fetch(this.xsuaaTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!response.ok) {
      const text = await response.text();
      this.logger.error('XSUAA token exchange failed', { status: response.status, body: text.slice(0, 200) });
      throw new Error(`XSUAA token exchange failed: ${response.status}`);
    }

    const data = (await response.json()) as TokenResponse;
    this.logger.debug('XSUAA token exchange: success', {
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      hasRefreshToken: !!data.refresh_token,
      scope: data.scope,
    });
    return {
      access_token: data.access_token,
      token_type: data.token_type ?? 'bearer',
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      scope: data.scope,
    };
  }

  /**
   * Override exchangeRefreshToken to use XSUAA credentials.
   */
  override async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
  ): Promise<{
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
  }> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.xsuaaClientId,
      client_secret: this.xsuaaClientSecret,
    });

    const response = await fetch(this.xsuaaTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error(`XSUAA refresh token exchange failed: ${response.status}`);
    }

    const data = (await response.json()) as TokenResponse;
    return {
      access_token: data.access_token,
      token_type: data.token_type ?? 'bearer',
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      scope: data.scope,
    };
  }

  /**
   * Override revokeToken to use XSUAA service credentials consistently.
   * Without this override, the base class would attempt revocation with
   * the local client credentials, which don't match the XSUAA binding.
   *
   * Declared as a property (arrow function) to match the base class declaration.
   */
  override revokeToken = async (
    _client: OAuthClientInformationFull,
    request: { token: string; token_type_hint?: string },
  ): Promise<void> => {
    const revokeUrl = this.xsuaaTokenUrl.replace('/oauth/token', '/oauth/revoke');

    const params = new URLSearchParams({ token: request.token });
    if (request.token_type_hint) {
      params.set('token_type_hint', request.token_type_hint);
    }

    try {
      const response = await fetch(revokeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${this.xsuaaClientId}:${this.xsuaaClientSecret}`).toString('base64')}`,
        },
        body: params.toString(),
      });

      if (!response.ok) {
        this.logger.warn('XSUAA token revocation failed', { status: response.status, url: revokeUrl });
      } else {
        this.logger.debug('XSUAA token revoked successfully');
      }
    } catch (err) {
      this.logger.warn('XSUAA token revocation error', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  };
}

// ─── Provider factory ────────────────────────────────────────────────

/**
 * Options for {@link createXsuaaOAuthProvider}. All knobs are threaded into the
 * underlying {@link StatelessDcrClientStore} + {@link OAuthStateCodec}.
 */
export interface CreateXsuaaOAuthProviderOptions {
  /** Prefix for DCR-issued client_ids. Threaded into the store. */
  clientIdPrefix?: string;
  /** Domain-separation label for the DCR client_id signing key. */
  dcrKdfLabel?: string;
  /** Domain-separation label for the OAuth-state signing key. */
  stateKdfLabel?: string;
  /** Lifetime of issued DCR client_ids in seconds. `0` disables expiration. */
  dcrTtlSeconds?: number;
  /** Lifetime of OAuth-state tokens in seconds. `0` disables expiration. */
  stateTtlSeconds?: number;
  /**
   * Optional dedicated secret for HMAC-signing DCR client_ids + OAuth state.
   * When set, the signing key derives from this secret instead of the XSUAA
   * `clientsecret`. Use this to keep cached client_ids valid across redeploys
   * that rotate the XSUAA binding's clientsecret. Defaults to
   * `credentials.clientsecret` (legacy behavior).
   */
  dcrSigningSecret?: string;
  /** Redirect-URI allowlist (xs-security.json mirror) for the default client. */
  redirectUriPatterns?: readonly string[];
  /** Built-in redirect_uris baked into the pre-registered default client. */
  defaultRedirectUris?: readonly string[];
  /**
   * This server's own OAuth callback URL (e.g. `https://app.../oauth/callback`),
   * sent to XSUAA as the redirect_uri so the server sits in the return path and
   * can fix XSUAA's `+`-in-state encoding bug (issue #214). Must be absolute and
   * match a `redirectUriPatterns` entry. When omitted, falls back to
   * `${appUrl}/oauth/callback`.
   */
  callbackUrl?: string;
  /** Injected structural logger. Default: silent no-op. */
  logger?: Logger;
}

/**
 * Create an {@link XsuaaProxyOAuthProvider} that proxies OAuth to XSUAA, along
 * with the {@link StatelessDcrClientStore} and {@link OAuthStateCodec} it uses
 * (returned so the transport can wire the `/authorize` redirect-uri shim and the
 * `/oauth/callback` proxy).
 *
 * `dcrSigningSecret` defaults to `credentials.clientsecret`.
 */
export function createXsuaaOAuthProvider(
  credentials: XsuaaCredentials,
  appUrl: string,
  options: CreateXsuaaOAuthProviderOptions = {},
): { provider: XsuaaProxyOAuthProvider; clientStore: StatelessDcrClientStore; stateCodec: OAuthStateCodec } {
  const logger = options.logger ?? noopLogger;

  // The signing secret defaults to the XSUAA `clientsecret`, which is the trust
  // anchor for "this server can mint client_ids". The downside: a redeploy that
  // recreates the service binding rotates the clientsecret — every redeploy then
  // invalidates every cached client_id. To opt out, pass a dedicated secret via
  // `dcrSigningSecret` (survives the redeploy). Re-setting it doubles as the
  // explicit revocation knob.
  //
  // Empty / whitespace-only input falls back to the XSUAA `clientsecret` (legacy
  // mode) with a warning instead of crashing — `??` only falls back on
  // null/undefined, so an empty value would otherwise reach the store
  // constructor's non-empty guard and kill startup. Compute the source label
  // from the effective secret, not the raw input.
  const trimmedDcrSecret = options.dcrSigningSecret?.trim();
  let dcrSigningSecret: string;
  let dcrSigningSource: 'override' | 'xsuaa';
  if (trimmedDcrSecret) {
    dcrSigningSecret = trimmedDcrSecret;
    dcrSigningSource = 'override';
  } else {
    if (options.dcrSigningSecret !== undefined) {
      logger.warn(
        'dcrSigningSecret was set but is empty or whitespace-only — falling back to XSUAA clientsecret. Set a real secret with `openssl rand -base64 48` or omit it.',
      );
    }
    dcrSigningSecret = credentials.clientsecret;
    dcrSigningSource = 'xsuaa';
  }

  const clientStore = new StatelessDcrClientStore(credentials.clientid, credentials.clientsecret, dcrSigningSecret, {
    clientIdPrefix: options.clientIdPrefix,
    kdfLabel: options.dcrKdfLabel,
    ttlSeconds: options.dcrTtlSeconds,
    redirectUriPatterns: options.redirectUriPatterns,
    defaultRedirectUris: options.defaultRedirectUris,
    logger,
  });
  // The provider's own verifyAccessToken (used for the OAuth /token introspection
  // path) does not apply scope expansion — the request-time chained verifier (see
  // the facade) owns that. Default identity here keeps the provider self-contained.
  const verifier = createXsuaaTokenVerifier(credentials, { logger });

  // The state codec reuses the same resolved signing secret as DCR (distinct
  // KDF label keeps the two key spaces separate), so it inherits the same
  // "survives redeploy" property when dcrSigningSecret is set. State tokens are
  // short-lived (single OAuth flow), so the codec uses its own TTL by default.
  const stateCodec = new OAuthStateCodec(dcrSigningSecret, {
    kdfLabel: options.stateKdfLabel,
    ttlSeconds: options.stateTtlSeconds,
  });

  const callbackUrl = options.callbackUrl ?? `${appUrl.replace(/\/$/, '')}/oauth/callback`;

  const provider = new XsuaaProxyOAuthProvider(credentials, verifier, clientStore, callbackUrl, stateCodec, logger);

  logger.info('XSUAA OAuth provider created (stateless DCR + callback proxy)', {
    xsappname: credentials.xsappname,
    authorizationUrl: `${credentials.url}/oauth/authorize`,
    appUrl,
    callbackUrl,
    dcrTtlSeconds: options.dcrTtlSeconds,
    dcrSigningSource,
  });
  if (dcrSigningSource === 'override') {
    logger.info(
      'DCR signing key uses a dedicated signing secret — cached client_ids survive redeploys that rotate the XSUAA clientsecret.',
    );
  }
  if (options.dcrTtlSeconds !== undefined && options.dcrTtlSeconds <= 0) {
    logger.info(
      'DCR client_id TTL is disabled — registrations never expire by time; revocation is via signing-secret rotation.',
    );
  }

  return { provider, clientStore, stateCodec };
}

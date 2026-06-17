/**
 * OAuth callback handler — the second half of the XSUAA callback proxy that
 * fixes the `+`-in-state bug (issue #214).
 *
 * Ported verbatim from arc-1's `createOAuthCallbackHandler`. The only changes are
 * the injected structural logger (default no-op) and the package's
 * {@link OAuthStateCodec} / {@link StatelessDcrClientStore} imports.
 *
 * XSUAA redirects here (not to the client) with an opaque base64url `state` token
 * that the provider's `authorize()` minted. We verify + decode it to recover the
 * client's ORIGINAL `redirect_uri` and `state`, then 302 to the client re-emitting
 * the state via `URL.searchParams` — whose serializer encodes a literal `+` as
 * `%2B`, exactly the encoding the client's parser expects.
 *
 * SECURITY (authorization-code interception, security audit 2026-06): the signed
 * state carries the originating DCR `client_id`. Before forwarding the auth code
 * (or an error) to the recovered redirect_uri, we verify that redirect_uri is
 * actually registered for that client. The signature alone is insufficient: all
 * DCR clients share one XSUAA app, so a forged-state attack is blocked by the
 * HMAC, but the redirect target must still belong to the client that will exchange
 * the code. `clientStore.checkRedirectUri` makes that decision per client type and
 * the handler fails CLOSED on any lookup error. When `clientStore` is omitted the
 * binding check is skipped (legacy round-trip tests).
 */

import type { RequestHandler } from 'express';
import type { StatelessDcrClientStore } from './dcr-client-store.js';
import type { Logger } from './logger.js';
import { noopLogger } from './logger.js';
import type { OAuthStateCodec } from './oauth-state.js';

/**
 * Minimal HTML-escape for embedding untrusted text (e.g. an OAuth
 * `error_description` from the query string) into the error page below.
 */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Is this a loopback HTTP redirect URI (`http://localhost|127.0.0.1|[::1]`)?
 * Such callbacks are ephemeral local listeners that native MCP clients (GitHub
 * Copilot, MCP Inspector) tear down on failure — so on an OAuth error we render a
 * self-hosted page for them rather than 302-ing to a dead port. Hosted HTTPS
 * callbacks (claude.ai, Copilot Studio) and custom-scheme app callbacks
 * (`vscode:`, `cursor:`) are live and expect the spec error redirect, so they keep
 * getting it.
 */
function isLoopbackHttpRedirect(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  const host = url.hostname.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

/**
 * Render a self-hosted OAuth error page for `/oauth/callback`. Surfaces the IdP's
 * error to the human (loopback MCP clients usually can't — they close their
 * listener on failure) with an actionable hint for the most common case,
 * `invalid_scope` (authenticated but no granted scopes → an admin must assign a
 * role collection under the user's login IdP).
 */
function renderOAuthErrorPage(error: string, errorDescription: string, clientReturnUrl: string): string {
  const hint =
    error === 'invalid_scope'
      ? 'You are signed in, but your user is not granted any scopes. An administrator must assign you a role collection under the identity provider you sign in with — see the authorization docs.'
      : 'Retry the sign-in from your MCP client. If it keeps failing, share this error with your administrator.';
  const descBlock = errorDescription ? `<p><code>${escapeHtml(errorDescription)}</code></p>` : '';
  return `<!doctype html><html><head><meta charset="utf-8"><title>Sign-in failed</title></head><body style="font-family:sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;line-height:1.5"><h1>Sign-in failed</h1><p><strong>Error:</strong> <code>${escapeHtml(error)}</code></p>${descBlock}<p>${escapeHtml(hint)}</p><p><a href="${escapeHtml(clientReturnUrl)}">Return to your application</a></p></body></html>`;
}

/**
 * Build the Express handler for `/oauth/callback` (the issue-#214 callback proxy
 * second half). `clientStore` enables the redirect_uri binding check; omit it only
 * for legacy round-trip tests.
 */
export function createOAuthCallbackHandler(
  stateCodec: OAuthStateCodec,
  clientStore?: StatelessDcrClientStore,
  options: { logger?: Logger } = {},
): RequestHandler {
  const logger = options.logger ?? noopLogger;

  return async (req, res): Promise<void> => {
    const stateToken = typeof req.query.state === 'string' ? req.query.state : '';
    const decoded = stateCodec.decode(stateToken);
    if (decoded.kind !== 'ok') {
      logger.warn('OAuth callback: invalid state token', { reason: decoded.reason });
      // We cannot safely redirect anywhere — the client redirect_uri lives inside
      // the (unverified) token. Return a terminal error page.
      res
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><body style="font-family:sans-serif;padding:2rem">' +
            '<h1>Authentication failed</h1>' +
            '<p>The OAuth state token was invalid or expired. Please retry the sign-in from your MCP client.</p>' +
            '</body></html>',
        );
      return;
    }

    // ── Client-binding validation (authorization-code interception defense) ──
    // Verify the recovered redirect_uri is an allowed target for the client_id
    // that minted this state, BEFORE the success or error branches below — so
    // neither a code nor an error response is ever steered to an unverified URI.
    // Fails CLOSED on any lookup error.
    if (clientStore && decoded.clientId) {
      let verdict: 'ok' | 'unknown_client' | 'unregistered';
      try {
        verdict = await clientStore.checkRedirectUri(decoded.clientId, decoded.clientRedirectUri);
      } catch (err) {
        logger.warn('OAuth callback: redirect_uri check threw — failing closed', {
          clientId: decoded.clientId,
          error: err instanceof Error ? err.message : String(err),
        });
        verdict = 'unknown_client';
      }
      if (verdict === 'unknown_client') {
        logger.warn('OAuth callback: state references unknown client_id', { clientId: decoded.clientId });
        res
          .status(400)
          .type('html')
          .send(
            '<!doctype html><html><body style="font-family:sans-serif;padding:2rem">' +
              '<h1>Authentication failed</h1>' +
              '<p>The OAuth client referenced in the state token is no longer valid. Please retry the sign-in.</p>' +
              '</body></html>',
          );
        return;
      }
      if (verdict === 'unregistered') {
        logger.warn('OAuth callback: redirect_uri not allowed for client', {
          clientId: decoded.clientId,
          redirectUri: decoded.clientRedirectUri,
        });
        res
          .status(400)
          .type('html')
          .send(
            '<!doctype html><html><body style="font-family:sans-serif;padding:2rem">' +
              '<h1>Authentication failed</h1>' +
              '<p>The redirect URI in the state token is not registered for this client. Please retry the sign-in.</p>' +
              '</body></html>',
          );
        return;
      }
    }

    let target: URL;
    try {
      target = new URL(decoded.clientRedirectUri);
    } catch {
      logger.warn('OAuth callback: stored redirect_uri is not a valid URL');
      res.status(400).type('html').send('<!doctype html><html><body>Invalid redirect target.</body></html>');
      return;
    }

    // On error there is no auth code. Forward the error to the client per the
    // OAuth spec — EXCEPT for loopback HTTP callbacks. Native MCP clients tear
    // down their ephemeral localhost listener the instant the flow fails, so a
    // 302 there lands on a dead port. For those we render a self-hosted page that
    // surfaces the real reason, with a best-effort link back.
    const error = typeof req.query.error === 'string' ? req.query.error : undefined;
    if (error) {
      const errorDescription = typeof req.query.error_description === 'string' ? req.query.error_description : '';
      if (decoded.clientState !== undefined) target.searchParams.set('state', decoded.clientState);
      target.searchParams.set('error', error);
      if (errorDescription) target.searchParams.set('error_description', errorDescription);
      const loopback = isLoopbackHttpRedirect(target);
      logger.warn('OAuth callback: identity provider returned an error', {
        error,
        errorDescriptionPreview: errorDescription.slice(0, 200),
        clientRedirectUriHost: target.host,
        loopback,
      });
      if (loopback) {
        res
          .status(400)
          .type('html')
          .send(renderOAuthErrorPage(error, errorDescription, target.toString()));
      } else {
        res.redirect(302, target.toString());
      }
      return;
    }

    // Success: forward the authorization code, re-attaching the client's ORIGINAL
    // state. URLSearchParams serialization encodes `+` as `%2B`, which is exactly
    // what fixes the round-trip (issue #214).
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    target.searchParams.set('code', code);
    if (decoded.clientState !== undefined) {
      target.searchParams.set('state', decoded.clientState);
    }

    logger.debug('OAuth callback: redirecting to client', {
      clientRedirectUriHost: target.host,
      hasState: decoded.clientState !== undefined,
    });
    res.redirect(302, target.toString());
  };
}

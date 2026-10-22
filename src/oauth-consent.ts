import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import type { OAuthClientInformationFull } from './internal/sdk.js';
import { renderConsentErrorPage, renderConsentPage } from './oauth-consent-page.js';

const FLOW_SECONDS = 600;

export interface BrowserBinding {
  cookieName: string;
  digest: string;
}

export interface AuthorizationParams {
  state?: string;
  scopes?: string[];
  codeChallenge: string;
  redirectUri: string;
  resource?: URL;
}

function sameValue(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readNonce(req: Request, name: string): string | undefined {
  const values = (req.headers.cookie ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`))
    .map((part) => part.slice(name.length + 1));
  // Reject duplicate cookies, including path/domain shadowing, and malformed values.
  return values.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(values[0] ?? '') ? values[0] : undefined;
}

function cookieOptions(name: string) {
  return { httpOnly: true, secure: name.startsWith('__Host-'), sameSite: 'lax' as const, path: '/' };
}

export function isBrowserBinding(value: unknown): value is BrowserBinding {
  if (!value || typeof value !== 'object') return false;
  const binding = value as BrowserBinding;
  return (
    typeof binding.cookieName === 'string' &&
    /^(?:__Host-)?mcp-oauth-state-[a-f0-9]{16}-[a-f0-9]{16}$/.test(binding.cookieName) &&
    typeof binding.digest === 'string' &&
    /^[A-Za-z0-9_-]{43}$/.test(binding.digest)
  );
}

/** A signed state is insufficient: it must return in the browser that approved it. */
export function consumeBrowserBinding(req: Request, res: Response, binding: BrowserBinding | undefined): boolean {
  if (!isBrowserBinding(binding)) return false;
  const nonce = readNonce(req, binding.cookieName);
  if (!nonce || !sameValue(createHash('sha256').update(nonce).digest('base64url'), binding.digest)) return false;
  res.clearCookie(binding.cookieName, cookieOptions(binding.cookieName));
  return true;
}

/**
 * Per-request consent, with no remembered approvals or process-local sessions.
 * The form proof binds every authorization parameter to a browser-only nonce.
 * A separate callback cookie is minted ONLY after approval, so transferring an
 * attacker-approved upstream URL to a victim cannot bypass the consent screen.
 */
export class OAuthConsent {
  private readonly key: Buffer;
  private readonly authorizationUrl: string;
  private readonly origin: string;
  private readonly consentCookie: string;
  private readonly stateCookie: string;

  constructor(signingSecret: string, authorizationUrl: string, callbackUrl: string) {
    const authorize = new URL(authorizationUrl);
    const callback = new URL(callbackUrl);
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(authorize.hostname);
    if (
      (authorize.protocol !== 'https:' && !(authorize.protocol === 'http:' && loopback)) ||
      authorize.origin !== callback.origin ||
      authorize.username ||
      authorize.password ||
      authorize.search ||
      authorize.hash ||
      callback.username ||
      callback.password ||
      callback.search ||
      callback.hash
    ) {
      throw new Error(
        'OAuth authorization and callback URLs must share a secure public origin (HTTP loopback is allowed).',
      );
    }
    this.authorizationUrl = authorize.href;
    this.origin = authorize.origin;
    this.key = createHmac('sha256', signingSecret).update('mcp-oauth-consent/v1').digest();
    const prefix = authorize.protocol === 'https:' ? '__Host-' : '';
    const suffix = createHash('sha256').update(authorize.href).digest('hex').slice(0, 16);
    this.consentCookie = `${prefix}mcp-oauth-consent-${suffix}`;
    this.stateCookie = `${prefix}mcp-oauth-state-${suffix}`;
  }

  approve(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): BrowserBinding | undefined {
    res.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
      // A no-referrer consent document makes browsers send Origin: null on
      // ordinary form POSTs. Send only the origin, never OAuth query values.
      'Referrer-Policy': 'origin',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy':
        // form-action 'self' also blocks the subsequent XSUAA/IdP redirects in
        // Chromium/WebKit. The form target is fixed, and its input is escaped.
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; style-src 'unsafe-inline'",
      'X-Content-Type-Options': 'nosniff',
    });
    const fields: Record<string, string> = {
      client_id: client.client_id,
      redirect_uri: params.redirectUri,
      response_type: 'code',
      code_challenge: params.codeChallenge,
      code_challenge_method: 'S256',
    };
    if (params.state !== undefined) fields.state = params.state;
    if (params.scopes?.length) fields.scope = params.scopes.join(' ');
    if (params.resource) fields.resource = params.resource.href;

    const req = res.req;
    const body = req.body as Record<string, unknown> | undefined;
    const submitted =
      req.method === 'POST' && (body?.consent_action !== undefined || body?.consent_proof !== undefined);
    if (submitted) {
      const id = typeof body?.consent_id === 'string' && /^[a-f0-9]{16}$/.test(body.consent_id) ? body.consent_id : '';
      const consentCookie = `${this.consentCookie}-${id}`;
      const stateCookie = `${this.stateCookie}-${id}`;
      fields.consent_id = id;
      const nonce = id ? readNonce(req, consentCookie) : undefined;
      const proof = typeof body?.consent_proof === 'string' ? body.consent_proof : '';
      const match = /^(\d{10})\.([A-Za-z0-9_-]{43})$/.exec(proof);
      const expires = Number(match?.[1]);
      const now = Math.floor(Date.now() / 1000);
      if (
        req.headers.origin !== this.origin ||
        !nonce ||
        !match ||
        expires <= now ||
        expires > now + FLOW_SECONDS ||
        !sameValue(match[2] ?? '', this.sign(nonce, expires, fields)) ||
        (body?.consent_action !== 'approve' && body?.consent_action !== 'deny')
      ) {
        res.status(403).type('html').send(renderConsentErrorPage(this.origin));
        return;
      }
      res.clearCookie(consentCookie, cookieOptions(consentCookie));
      res.set('Referrer-Policy', 'no-referrer');
      if (body.consent_action === 'deny') {
        const target = new URL(params.redirectUri);
        target.searchParams.set('error', 'access_denied');
        if (params.state !== undefined) target.searchParams.set('state', params.state);
        res.redirect(303, target.href);
        return;
      }
      const callbackNonce = randomBytes(32).toString('base64url');
      res.cookie(stateCookie, callbackNonce, { ...cookieOptions(stateCookie), maxAge: FLOW_SECONDS * 1000 });
      return { cookieName: stateCookie, digest: createHash('sha256').update(callbackNonce).digest('base64url') };
    }

    const nonce = randomBytes(32).toString('base64url');
    const expires = Math.floor(Date.now() / 1000) + FLOW_SECONDS;
    fields.consent_id = randomBytes(8).toString('hex');
    const consentCookie = `${this.consentCookie}-${fields.consent_id}`;
    res.cookie(consentCookie, nonce, { ...cookieOptions(consentCookie), maxAge: FLOW_SECONDS * 1000 });
    fields.consent_proof = `${expires}.${this.sign(nonce, expires, fields)}`;
    res
      .status(200)
      .type('html')
      .send(
        renderConsentPage({
          authorizationUrl: this.authorizationUrl,
          clientName: client.client_name,
          redirectUri: params.redirectUri,
          scopes: params.scopes,
          expiresInSeconds: FLOW_SECONDS,
          fields,
        }),
      );
  }

  private sign(nonce: string, expires: number, fields: Record<string, string>): string {
    return createHmac('sha256', this.key)
      .update(JSON.stringify([this.authorizationUrl, nonce, expires, fields]))
      .digest('base64url');
  }
}

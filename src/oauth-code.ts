import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const PREFIX = 'mcp-code-';
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

/**
 * Only the browser-validated callback can issue a local authorization code.
 * Binding it to the local client also prevents redeeming a static-client code
 * through a newly registered public client. XSUAA still enforces PKCE and code
 * single-use; this wrapper keeps that upstream grant behind our consent gate.
 */
export class OAuthCodeCodec {
  private readonly key: Buffer;

  constructor(signingSecret: string, label: string) {
    this.key = createHmac('sha256', signingSecret).update(`${label}/authorization-code/v1`).digest();
  }

  encode(code: string, clientId: string, redirectUri: string): string {
    const payload = Buffer.from(
      JSON.stringify({
        code,
        client: hash(clientId),
        redirect: hash(redirectUri),
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ).toString('base64url');
    return `${PREFIX}${payload}.${this.sign(payload).toString('base64url')}`;
  }

  decode(wrapped: string, clientId: string, redirectUri?: string): string | undefined {
    if (!wrapped.startsWith(PREFIX) || wrapped.length > 32_768) return undefined;
    const parts = wrapped.slice(PREFIX.length).split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1] || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return undefined;
    const expected = this.sign(parts[0]);
    const actual = Buffer.from(parts[1], 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return undefined;
    try {
      const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>;
      const now = Math.floor(Date.now() / 1000);
      if (
        typeof payload.code !== 'string' ||
        !payload.code ||
        payload.client !== hash(clientId) ||
        typeof payload.redirect !== 'string' ||
        (redirectUri !== undefined && payload.redirect !== hash(redirectUri)) ||
        typeof payload.exp !== 'number' ||
        !Number.isSafeInteger(payload.exp) ||
        payload.exp <= now ||
        payload.exp > now + 600
      )
        return undefined;
      return payload.code;
    } catch {
      return undefined;
    }
  }

  private sign(payload: string): Buffer {
    return createHmac('sha256', this.key).update(payload).digest();
  }
}

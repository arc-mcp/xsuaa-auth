import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const PREFIX = 'mcp-refresh-';
const MAX_LENGTH = 32_768;
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

/**
 * Stateless local-client binding for an upstream refresh grant. The envelope
 * authenticates, but does not encrypt, the upstream bearer token. Every refresh
 * exchange must require it: accepting an extracted/raw token would bypass it.
 * XSUAA remains responsible for expiry, rotation and revocation.
 */
export class OAuthRefreshTokenCodec {
  private readonly key: Buffer;

  constructor(secret: string, issuer: string, xsuaaClientId: string, callbackUrl: string) {
    this.key = createHmac('sha256', secret)
      .update(JSON.stringify(['mcp-oauth-refresh/v1', issuer, xsuaaClientId, callbackUrl]))
      .digest();
  }

  /** Namespace detection only; decode must authenticate before use. */
  isWrapped(token: string): boolean {
    return token.startsWith(PREFIX);
  }

  encode(token: string, clientId: string): string {
    if (typeof token !== 'string' || !token || token.length > MAX_LENGTH) {
      throw new Error('Invalid upstream refresh token');
    }
    const payload = Buffer.from(JSON.stringify({ token, client: hash(clientId) })).toString('base64url');
    const wrapped = `${PREFIX}${payload}.${this.sign(payload).toString('base64url')}`;
    // Never issue a token our decoder cannot accept.
    if (wrapped.length > MAX_LENGTH) throw new Error('Upstream refresh token exceeds local envelope limit');
    return wrapped;
  }

  decode(wrapped: string, clientId: string): string | undefined {
    if (!this.isWrapped(wrapped) || wrapped.length > MAX_LENGTH) return undefined;
    const parts = wrapped.slice(PREFIX.length).split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return undefined;
    if (!/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) return undefined;
    const expected = this.sign(parts[0]);
    const actual = Buffer.from(parts[1], 'base64url');
    if (actual.toString('base64url') !== parts[1] || !timingSafeEqual(actual, expected)) return undefined;
    try {
      const bytes = Buffer.from(parts[0], 'base64url');
      if (bytes.toString('base64url') !== parts[0]) return undefined;
      const payload = JSON.parse(bytes.toString('utf8')) as Record<string, unknown> | null;
      if (!payload || typeof payload.token !== 'string' || !payload.token || payload.client !== hash(clientId)) {
        return undefined;
      }
      return payload.token;
    } catch {
      return undefined;
    }
  }

  private sign(payload: string): Buffer {
    return createHmac('sha256', this.key).update(payload).digest();
  }
}

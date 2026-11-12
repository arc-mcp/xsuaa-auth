import { afterEach, describe, expect, it, vi } from 'vitest';
import { OAuthCodeCodec } from '../src/oauth-code.js';
import { OAuthRefreshTokenCodec } from '../src/oauth-refresh-token.js';

const secret = 'synthetic-refresh-token-test-secret';
const issuer = 'https://identity.example';
const xsuaaClient = 'sb-test!t1';
const callback = 'https://proxy.example/oauth/callback';
const codec = () => new OAuthRefreshTokenCodec(secret, issuer, xsuaaClient, callback);

afterEach(() => vi.useRealTimers());

describe('local refresh token envelope', () => {
  it('binds to the local client, key and deployment while surviving restarts', () => {
    const token = codec().encode('raw-refresh', 'client-one');
    expect(codec().decode(token, 'client-one')).toBe('raw-refresh');
    expect(codec().decode(token, 'client-two')).toBeUndefined();
    for (const changed of [
      new OAuthRefreshTokenCodec('other-secret', issuer, xsuaaClient, callback),
      new OAuthRefreshTokenCodec(secret, 'https://other-identity.example', xsuaaClient, callback),
      new OAuthRefreshTokenCodec(secret, issuer, 'sb-other!t1', callback),
      new OAuthRefreshTokenCodec(secret, issuer, xsuaaClient, 'https://other-proxy.example/oauth/callback'),
    ])
      expect(changed.decode(token, 'client-one')).toBeUndefined();
  });

  it('rejects raw tokens, code tokens, changed payloads/signatures, truncation and oversized inputs', () => {
    const token = codec().encode('raw-refresh', 'client-one');
    const [payload, signature] = token.slice('mcp-refresh-'.length).split('.');
    const changedPayload = Buffer.from(JSON.stringify({ token: 'other-refresh', client: 'client-one' })).toString(
      'base64url',
    );
    for (const invalid of [
      'raw-refresh',
      new OAuthCodeCodec(secret, 'mcp-oauth-state/v1').encode('raw-refresh', 'client-one', callback),
      `mcp-refresh-${changedPayload}.${signature}`,
      `mcp-refresh-${payload}.${'A'.repeat(43)}`,
      `mcp-refresh-${payload}.${signature}=`,
      'mcp-refresh-',
      `mcp-refresh-%%%.${signature}`,
      token.slice(0, -3),
      `${token}.extra`,
      `mcp-refresh-${'a'.repeat(33_000)}`,
    ])
      expect(codec().decode(invalid, 'client-one')).toBeUndefined();
  });

  it('does not impose the authorization-code lifetime on a refresh grant', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const token = codec().encode('raw-refresh', 'client-one');
    vi.setSystemTime(Date.now() + 31 * 24 * 60 * 60 * 1000);
    expect(codec().decode(token, 'client-one')).toBe('raw-refresh');
  });

  it('never issues an empty or oversized envelope that the decoder would refuse', () => {
    for (const raw of ['', 'a'.repeat(33_000), '€'.repeat(10_000)]) {
      expect(() => codec().encode(raw, 'client-one')).toThrow();
    }
    const raw = 'a'.repeat(20_000);
    expect(codec().decode(codec().encode(raw, 'client-one'), 'client-one')).toBe(raw);
  });
});

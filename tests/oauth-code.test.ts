import { afterEach, describe, expect, it, vi } from 'vitest';
import { OAuthCodeCodec } from '../src/oauth-code.js';

const secret = 'synthetic-test-secret-for-code-binding';
const label = 'test-oauth-state/v1';
const redirect = 'https://client.example/callback';

afterEach(() => vi.useRealTimers());

describe('local authorization code binding', () => {
  it('survives instance changes but not client, redirect, secret or namespace changes', () => {
    const code = new OAuthCodeCodec(secret, label).encode('upstream-code', 'client-one', redirect);
    const otherInstance = new OAuthCodeCodec(secret, label);
    expect(otherInstance.decode(code, 'client-one', redirect)).toBe('upstream-code');
    // OAuth permits omission when redirect_uri was not sent by the client.
    expect(otherInstance.decode(code, 'client-one')).toBe('upstream-code');
    expect(otherInstance.decode(code, 'client-two', redirect)).toBeUndefined();
    expect(otherInstance.decode(code, 'client-one', `${redirect}/other`)).toBeUndefined();
    expect(new OAuthCodeCodec('different-secret', label).decode(code, 'client-one', redirect)).toBeUndefined();
    expect(new OAuthCodeCodec(secret, 'other/v1').decode(code, 'client-one', redirect)).toBeUndefined();
  });

  it('rejects raw, tampered, truncated, extended and oversized codes', () => {
    const codec = new OAuthCodeCodec(secret, label);
    const code = codec.encode('upstream-code', 'client-one', redirect);
    for (const invalid of [
      'upstream-code',
      code.replace('mcp-code-e', 'mcp-code-f'),
      code.slice(0, -3),
      `${code}.extra`,
      `mcp-code-${'a'.repeat(33_000)}`,
    ]) {
      expect(codec.decode(invalid, 'client-one', redirect)).toBeUndefined();
    }
  });

  it('expires after ten minutes and rejects tokens from the future', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const now = Date.now();
    const codec = new OAuthCodeCodec(secret, label);
    const code = codec.encode('upstream-code', 'client-one', redirect);
    vi.setSystemTime(now + 600_000);
    expect(codec.decode(code, 'client-one', redirect)).toBeUndefined();
    vi.setSystemTime(now - 1_000);
    expect(codec.decode(code, 'client-one', redirect)).toBeUndefined();
  });
});

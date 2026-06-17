/**
 * Redirect-URI validation + allowlist matching (SPEC §6, fail-closed normative).
 *
 * Ported from arc-1 `stateless-client-store.test.ts` (the `matchesXsuaaRedirectPattern`
 * / `validateRedirectUri` describe blocks), renamed to the package's public exports
 * `matchesRedirectPattern` / `validateRedirectUri` and the shipped default patterns
 * (which already include the azure-apim / MS Copilot pattern).
 */

import { describe, expect, it } from 'vitest';
import {
  XSUAA_DEFAULT_REDIRECT_URIS,
  XSUAA_DEFAULT_REDIRECT_URI_PATTERNS,
  matchesRedirectPattern,
  validateRedirectUri,
} from '../src/index.js';

describe('matchesRedirectPattern (redirect-uri allowlist for the shared XSUAA client)', () => {
  it('accepts URIs covered by the shipped default patterns', () => {
    const allowed = [
      'http://localhost:6274/oauth/callback', // http://localhost:*/**
      'http://localhost:3000/oauth/callback',
      'https://abc.hana.ondemand.com/login/callback', // https://*.hana.ondemand.com/**
      'https://dev-xyz.applicationstudio.cloud.sap/cb', // https://*.applicationstudio.cloud.sap/**
      'https://claude.ai/api/mcp/auth_callback', // exact
      'https://callback.mistral.ai/v1/integrations_auth/oauth2_callback', // exact
      'cursor://anysphere.cursor-retrieval/oauth/callback', // cursor://anysphere.cursor-retrieval/**
      'cursor://anysphere.cursor-mcp/cb',
      'vscode://vscode.microsoft-authentication/callback',
      'https://global.consent.azure-apim.net/redirect/contoso', // MS Copilot (Manual mode)
    ];
    for (const uri of allowed) {
      expect(matchesRedirectPattern(uri), uri).toBe(true);
    }
  });

  it('matches the azure-apim (MS Copilot) + claude.ai patterns specifically', () => {
    expect(matchesRedirectPattern('https://global.consent.azure-apim.net/redirect/anything')).toBe(true);
    expect(matchesRedirectPattern('https://global.consent.azure-apim.net/redirect/a/b/c')).toBe(true);
    expect(matchesRedirectPattern('https://claude.ai/api/mcp/auth_callback')).toBe(true);
  });

  it('rejects attacker-controlled and out-of-allowlist URIs', () => {
    const rejected = [
      'https://attacker.example/cb',
      'https://claude.ai.attacker.com/api/mcp/auth_callback', // suffix-graft on an exact host
      'https://attacker.com/claude.ai/api/mcp/auth_callback', // path can't impersonate host
      'https://hana.ondemand.com.attacker.com/cb', // subdomain-suffix trick must NOT match *.hana.ondemand.com
      'http://evil.com/cb', // non-loopback http not in allowlist
      'https://global.consent.azure-apim.net.evil.com/redirect/x', // host-suffix graft
      'javascript:alert(1)',
    ];
    for (const uri of rejected) {
      expect(matchesRedirectPattern(uri), uri).toBe(false);
    }
  });

  it("a host-label '*' does not cross a path separator (so it cannot reach a foreign host)", () => {
    expect(matchesRedirectPattern('https://x.hana.ondemand.com.evil.com/cb')).toBe(false);
    expect(matchesRedirectPattern('https://a.b.hana.ondemand.com/cb')).toBe(true); // extra SAP subdomain is fine
  });

  it('rejects URL userinfo smuggling — the string matches the glob but parses to a foreign host', () => {
    expect(new URL('http://localhost:x@evil.com/cb').host).toBe('evil.com'); // documents the parse
    expect(matchesRedirectPattern('http://localhost:x@evil.com/cb')).toBe(false);
    expect(matchesRedirectPattern('http://localhost:@evil.com/x')).toBe(false);
    expect(matchesRedirectPattern('http://localhost:1234@evil.com/cb')).toBe(false);
    expect(matchesRedirectPattern('https://user:pass@claude.ai/api/mcp/auth_callback')).toBe(false);
    // a credential-free loopback redirect (the legitimate use of the localhost pattern) still passes
    expect(matchesRedirectPattern('http://localhost:6274/oauth/callback')).toBe(true);
  });

  it('returns false on parse failure (not a parseable URL)', () => {
    expect(matchesRedirectPattern('not a url')).toBe(false);
    expect(matchesRedirectPattern('http://')).toBe(false);
    expect(matchesRedirectPattern('')).toBe(false);
  });

  it('rejects authority-relocation smuggling (\\, #, ? that move the real host) — matches the CANONICAL parse, not the raw string', () => {
    // The WHATWG URL parser treats `\` as `/`, and `#`/`?` start the fragment/query,
    // so all three of these parse to host `evil.com` while the raw string still
    // contains `.hana.ondemand.com`. Matching the raw string would have let them
    // through `https://*.hana.ondemand.com/**`; canonical matching rejects them.
    expect(new URL('https://evil.com\\@x.hana.ondemand.com/cb').host).toBe('evil.com'); // documents the parse
    expect(matchesRedirectPattern('https://evil.com\\@x.hana.ondemand.com/cb')).toBe(false);
    expect(matchesRedirectPattern('https://evil.com#@x.hana.ondemand.com/cb')).toBe(false);
    expect(matchesRedirectPattern('https://evil.com?@x.hana.ondemand.com/cb')).toBe(false);
    // A legitimate subdomain redirect under the same pattern is still ACCEPTED.
    expect(matchesRedirectPattern('https://sub.hana.ondemand.com/cb')).toBe(true);
  });

  it('honors a custom patterns argument (overriding the shipped defaults)', () => {
    const custom = ['https://only.example.com/**'];
    expect(matchesRedirectPattern('https://only.example.com/cb', custom)).toBe(true);
    // A default-allowlisted URI is NOT allowed under the custom list.
    expect(matchesRedirectPattern('https://claude.ai/api/mcp/auth_callback', custom)).toBe(false);
  });
});

describe('validateRedirectUri (fail-closed scheme/host policy)', () => {
  it('throws on dangerous schemes', () => {
    expect(() => validateRedirectUri('javascript:alert(1)')).toThrow();
    expect(() => validateRedirectUri('data:text/html,foo')).toThrow();
    expect(() => validateRedirectUri('file:///etc/passwd')).toThrow();
    expect(() => validateRedirectUri('ftp://x/y')).toThrow();
  });

  it('throws on http:// to a non-loopback host', () => {
    expect(() => validateRedirectUri('http://evil.com/cb')).toThrow(/localhost\/127\.0\.0\.1/);
  });

  it('accepts https, loopback http, and the known MCP-client custom schemes', () => {
    expect(() => validateRedirectUri('https://example.com/cb')).not.toThrow();
    expect(() => validateRedirectUri('http://localhost/cb')).not.toThrow();
    expect(() => validateRedirectUri('http://127.0.0.1:6274/oauth/callback')).not.toThrow();
    expect(() => validateRedirectUri('http://[::1]:6274/cb')).not.toThrow();
    expect(() => validateRedirectUri('cursor://anysphere/cb')).not.toThrow();
    expect(() => validateRedirectUri('vscode://x/cb')).not.toThrow();
    expect(() => validateRedirectUri('vscode-insiders://x/cb')).not.toThrow();
    expect(() => validateRedirectUri('claude://x/cb')).not.toThrow();
  });

  it('rejects an unknown/custom scheme that is NOT allowlisted by patterns (fail-closed)', () => {
    // Previously this returned (allowed) for any scheme that merely parsed.
    expect(() => validateRedirectUri('myapp://callback')).toThrow(/not allowed|not a parseable/);
    expect(() => validateRedirectUri('weird-scheme://x/cb')).toThrow(/not allowed|not a parseable/);
    // Default patterns do not cover these schemes, so even with the default list they are rejected.
    expect(() => validateRedirectUri('myapp://callback', XSUAA_DEFAULT_REDIRECT_URI_PATTERNS)).toThrow();
  });

  it('accepts an unknown/custom scheme ONLY when an allowlisted pattern matches it', () => {
    const patterns = ['myapp://oauth/**'];
    expect(() => validateRedirectUri('myapp://oauth/callback', patterns)).not.toThrow();
    // A different custom scheme not covered by the pattern is still rejected.
    expect(() => validateRedirectUri('other://oauth/callback', patterns)).toThrow();
  });
});

describe('shipped default constants', () => {
  it('XSUAA_DEFAULT_REDIRECT_URI_PATTERNS includes the azure-apim (MS Copilot) pattern', () => {
    expect(XSUAA_DEFAULT_REDIRECT_URI_PATTERNS).toContain('https://global.consent.azure-apim.net/redirect/**');
  });

  it('XSUAA_DEFAULT_REDIRECT_URIS includes Claude Desktop, Cursor, and VS Code callbacks', () => {
    expect(XSUAA_DEFAULT_REDIRECT_URIS).toContain('https://claude.ai/api/mcp/auth_callback');
    expect(XSUAA_DEFAULT_REDIRECT_URIS).toContain('cursor://anysphere.cursor-retrieval/oauth/callback');
    expect(XSUAA_DEFAULT_REDIRECT_URIS).toContain('vscode://vscode.microsoft-authentication/callback');
  });
});

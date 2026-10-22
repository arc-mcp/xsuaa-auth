import { describe, expect, it } from 'vitest';
import { renderConsentErrorPage, renderConsentPage } from '../src/oauth-consent-page.js';
import { consentFields } from './helpers/oauth-consent.js';

const options = {
  authorizationUrl: 'https://server.example/mcp-proxy/authorize',
  clientName: 'Example desktop client',
  redirectUri: 'https://client.example/callback?workspace=example&mode=connect',
  expiresInSeconds: 600,
  fields: { client_id: 'synthetic-client', state: 'example+state/with=padding', consent_proof: 'synthetic-proof' },
};

describe('OAuth consent page presentation', () => {
  it('separates the configured server identity from the self-declared application and full return address', () => {
    const html = renderConsentPage(options);
    expect(html).toContain('<p class="address" dir="ltr">https://server.example</p>');
    expect(html).toContain('Application name · unverified');
    expect(html).toContain('<bdi>Example desktop client</bdi>');
    expect(html).toContain('client.example/callback?workspace=example&amp;mode=connect');
    expect(html).toContain('Only approve a connection you started');
    expect(html).not.toMatch(/<(?:script|img|iframe|link|a)\b/i);
  });

  it('keeps the complete form payload and prefixed authorization endpoint unchanged', () => {
    const html = renderConsentPage(options);
    expect(consentFields(html)).toEqual(options.fields);
    expect(html).toContain('<form method="post" action="https://server.example/mcp-proxy/authorize">');
    expect(html.indexOf('value="deny"')).toBeLessThan(html.indexOf('value="approve"'));
    expect(html).not.toMatch(/autofocus|tabindex|onclick|onload/i);
  });

  it('explains unspecified permissions without implying read-only access', () => {
    for (const scopes of [undefined, [], ['']]) {
      const html = renderConsentPage({ ...options, scopes });
      expect(html).toContain('All permissions assigned to your account for this server');
      expect(html).toContain('did not request a narrower set');
      expect(html).not.toContain('read-only');
    }
  });

  it('shows custom scope identifiers without inventing application-specific semantics', () => {
    const html = renderConsentPage({ ...options, scopes: ['inventory.inspect', 'orders.submit'] });
    expect(html).toContain('<code dir="ltr">inventory.inspect</code>');
    expect(html).toContain('<code dir="ltr">orders.submit</code>');
    expect(html).toContain('permission names are defined by this server');
    expect(html).not.toContain('All permissions assigned');
  });

  it.each(['http://localhost:6274/cb', 'http://127.0.0.1:6274/cb', 'http://[::1]:6274/cb'])(
    'explains local return addresses without treating them as verified: %s',
    (redirectUri) => {
      const html = renderConsentPage({ ...options, redirectUri });
      expect(html).toContain(redirectUri);
      expect(html).toContain('A local address does not verify which application is listening.');
    },
  );

  it.each(['vscode://vscode.microsoft-authentication/cb', 'cursor://anysphere.cursor-mcp/cb'])(
    'explains application URI schemes: %s',
    (redirectUri) => {
      const html = renderConsentPage({ ...options, redirectUri });
      expect(html).toContain(redirectUri);
      expect(html).toContain('does not verify which application handles it');
      expect(html).toContain(`<p class="address" dir="ltr">${new URL(redirectUri).protocol}</p>`);
    },
  );

  it('bounds long names by Unicode code points while keeping the complete return address', () => {
    const clientName = '🌍'.repeat(110);
    const redirectUri = `https://client.example/${'workspace-'.repeat(100)}/callback`;
    const html = renderConsentPage({ ...options, clientName, redirectUri });
    expect(html).toContain(`<bdi>${'🌍'.repeat(100)}…</bdi>`);
    expect(html).toContain('Name shortened for display.');
    expect(html).not.toContain(clientName);
    expect(html).toContain(redirectUri);
  });

  it('escapes and isolates multilingual names without changing short names', () => {
    const html = renderConsentPage({ ...options, clientName: 'Example & "Team" <Workspace> — فريق' });
    expect(html).toContain('<bdi>Example &amp; &quot;Team&quot; &lt;Workspace&gt; — فريق</bdi>');
    expect(html).not.toContain('Name shortened for display.');
    expect(html).not.toContain('<Workspace>');
  });

  it('shows the browser-normalized destination without changing the signed redirect value', () => {
    const redirectUri = 'https://bücher.example/über?workspace=example&mode=connect';
    const html = renderConsentPage({
      ...options,
      redirectUri,
      fields: { ...options.fields, redirect_uri: redirectUri },
    });
    expect(html).toContain('<code>https://xn--bcher-kva.example/%C3%BCber?workspace=example&amp;mode=connect</code>');
    expect(consentFields(html).redirect_uri).toBe(redirectUri);
  });

  it('provides an unnamed-client fallback and a complete accessible document', () => {
    const html = renderConsentPage({ ...options, clientName: '   ' });
    expect(html).toContain('Unnamed MCP client');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('<main>');
    expect(html.match(/<h1>/g)).toHaveLength(1);
    expect(html).toContain('name="viewport" content="width=device-width,initial-scale=1"');
  });

  it('gives expired/invalid requests a separate restart page without a retry form or request details', () => {
    const html = renderConsentErrorPage('https://server.example');
    expect(html).toContain('<title>Approval expired or invalid</title>');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('No access was approved by this attempt.');
    expect(html).toContain('start a new connection');
    expect(html).toContain('same browser');
    expect(html).not.toMatch(/<(?:form|input|button|script|a)\b/i);
    expect(html).not.toContain(options.fields.consent_proof);
  });
});

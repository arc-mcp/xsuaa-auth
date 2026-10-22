/** Presentation only: OAuth validation, cookies and response headers stay in OAuthConsent. */
interface ConsentPageOptions {
  authorizationUrl: string;
  clientName?: string;
  redirectUri: string;
  scopes?: readonly string[];
  expiresInSeconds: number;
  fields: Readonly<Record<string, string>>;
}

function escapeHtml(value: string): string {
  const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return value.replace(/[&<>"']/g, (character) => entities[character] ?? character);
}

const styles = `
:root { color-scheme: light dark; --page:#f3f5f9; --surface:#fff; --text:#182330; --muted:#475569;
  --line:#cbd5e1; --panel:#f1f5f9; --accent:#1658c7; --on-accent:#fff; --focus:#0b5ecf; }
* { box-sizing:border-box; }
body { margin:0; background:var(--page); color:var(--text); font:1rem/1.5 system-ui,sans-serif; }
main { max-width:44rem; margin:2rem auto; padding:0 1rem; }
.card { padding:2rem; border:1px solid var(--line); border-radius:1rem; background:var(--surface); }
.server { padding-bottom:1.25rem; border-bottom:1px solid var(--line); }
.eyebrow { margin:0 0 .25rem; color:var(--muted); font-size:.8rem; font-weight:700; letter-spacing:.08em; }
.address, code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
.address { margin:0; font-weight:600; }
h1 { margin:1.5rem 0 .5rem; font-size:1.75rem; line-height:1.2; }
h2 { margin:0 0 .5rem; font-size:1rem; }
p { margin:.5rem 0; }
section { margin-top:1.25rem; }
.client { padding:1rem; border:1px solid var(--line); border-radius:.5rem; background:var(--panel); }
.client-name { margin:.5rem 0; font-size:1.25rem; font-weight:650; overflow-wrap:anywhere; }
.hint { color:var(--muted); font-size:.9375rem; }
.value { overflow-wrap:anywhere; }
.permissions { margin:.5rem 0; padding-left:1.25rem; }
.return-url { padding:.75rem; border:1px solid var(--line); border-radius:.375rem; background:var(--panel); }
.actions { display:flex; gap:.75rem; flex-wrap:wrap; margin-top:1.5rem; }
button { min-height:2.75rem; padding:.7rem 1.2rem; border:1px solid var(--muted); border-radius:.5rem;
  background:var(--surface); color:var(--text); font:inherit; font-weight:600; cursor:pointer; }
button.primary { background:var(--accent); border-color:var(--accent); color:var(--on-accent); }
button:hover { text-decoration:underline; }
button:focus-visible { outline:3px solid var(--focus); outline-offset:3px; }
.footer { margin:1rem 0 0; color:var(--muted); font-size:.875rem; }
@media (max-width:30rem) {
  main { margin:1rem auto; padding:0 .75rem; }
  .card { padding:1.25rem; }
  .actions { flex-direction:column; }
  button { width:100%; }
}
@media (prefers-color-scheme:dark) {
  :root { --page:#101722; --surface:#182330; --text:#f1f5f9; --muted:#cbd5e1; --line:#65758b;
    --panel:#202e40; --accent:#a8caff; --on-accent:#10264b; --focus:#a8caff; }
}
@media (forced-colors:active) {
  button:focus-visible { outline-color:Highlight; }
}
`;

function document(title: string, origin: string, content: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>${styles}</style></head>
<body><main><div class="card">
<header class="server"><p class="eyebrow">MCP SERVER</p><p class="address" dir="ltr">${escapeHtml(origin)}</p></header>
${content}
</div></main></body></html>`;
}

function returnAddressHint(target: URL): string {
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return 'This address opens an application on your device. The address alone does not verify which application handles it.';
  }
  if (['localhost', '127.0.0.1', '[::1]'].includes(target.hostname)) {
    return 'This address returns to an application on your device. A local address does not verify which application is listening.';
  }
  return 'After sign-in, or if you deny, your browser returns to this address. Check that it belongs to the application you intended to connect.';
}

export function renderConsentPage(options: ConsentPageOptions): string {
  const target = new URL(options.redirectUri);
  const returnLabel = ['https:', 'http:'].includes(target.protocol) ? target.host : target.protocol;
  const name = [...(options.clientName?.trim() || 'Unnamed MCP client')];
  const shortName = name.length > 100;
  const clientName = name.slice(0, 100).join('') + (shortName ? '…' : '');
  const scopes = options.scopes?.filter(Boolean);
  const permissions = scopes?.length
    ? `<ul class="permissions">${scopes.map((scope) => `<li class="value"><code dir="ltr">${escapeHtml(scope)}</code></li>`).join('')}</ul>
<p class="hint">These permission names are defined by this server. Your account permissions still apply.</p>`
    : `<p>All permissions assigned to your account for this server</p>
<p class="hint">The application did not request a narrower set of permissions.</p>`;
  const inputs = Object.entries(options.fields)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('');
  return document(
    'Approve client access',
    new URL(options.authorizationUrl).origin,
    `<h1>Approve client access</h1>
<p>An application wants to connect to this server using your account.</p>
<section class="client" aria-labelledby="application-heading">
<h2 id="application-heading">Application name · unverified</h2>
<p class="client-name"><bdi>${escapeHtml(clientName)}</bdi></p>
<p class="hint">This name has not been verified. Check the application where you started this connection.${shortName ? ' Name shortened for display.' : ''}</p>
</section>
<section aria-labelledby="permissions-heading"><h2 id="permissions-heading">Requested permissions</h2>${permissions}</section>
<section aria-labelledby="return-heading"><h2 id="return-heading">Return address</h2>
<p class="address" dir="ltr">${escapeHtml(returnLabel)}</p>
<p class="return-url" dir="ltr"><code>${escapeHtml(target.href)}</code></p>
<p class="hint">${returnAddressHint(target)}</p></section>
<p><strong>Only approve a connection you started in an application you trust.</strong> Otherwise, choose Deny.</p>
<form method="post" action="${escapeHtml(options.authorizationUrl)}">${inputs}
<div class="actions"><button type="submit" name="consent_action" value="deny">Deny</button>
<button class="primary" type="submit" name="consent_action" value="approve">Approve and continue</button></div></form>
<p class="footer">Next, continue to your organization’s sign-in service. An existing sign-in session may skip the login prompt.</p>
<p class="footer">This request expires after ${options.expiresInSeconds / 60} minutes. If it expires, restart the connection from your MCP client.</p>`,
  );
}

export function renderConsentErrorPage(origin: string): string {
  return document(
    'Approval expired or invalid',
    origin,
    `<h1>Approval expired or invalid</h1>
<p>This sign-in request could not be approved. No access was approved by this attempt.</p>
<p>Return to your MCP client and start a new connection. Complete approval and sign-in in the same browser.</p>
<p class="hint">If this keeps happening, ask your server administrator to check the public URL and browser cookie settings.</p>`,
  );
}

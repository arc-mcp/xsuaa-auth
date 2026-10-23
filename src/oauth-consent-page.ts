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
.eyebrow { margin:0 0 .25rem; color:var(--muted); font-size:.8rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
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
<header class="server"><p class="eyebrow">MCP server</p><p class="address" dir="ltr">${escapeHtml(origin)}</p></header>
${content}
</div></main></body></html>`;
}

export function renderConsentPage(options: ConsentPageOptions): string {
  const target = new URL(options.redirectUri);
  const name = [...(options.clientName?.trim() || 'Unnamed MCP client')];
  const shortName = name.length > 100;
  const clientName = name.slice(0, 100).join('') + (shortName ? '…' : '');
  const scopes = options.scopes?.filter(Boolean);
  const permissions = scopes?.length
    ? `<ul class="permissions">${scopes.map((scope) => `<li class="value"><code dir="ltr">${escapeHtml(scope)}</code></li>`).join('')}</ul>`
    : '<p>All your permissions on this server</p>';
  const inputs = Object.entries(options.fields)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('');
  return document(
    'Approve client access',
    new URL(options.authorizationUrl).origin,
    `<h1>Approve client access</h1>
<section class="client" aria-labelledby="application-heading">
<h2 id="application-heading">Application name (unverified)</h2>
<p class="client-name"><bdi>${escapeHtml(clientName)}</bdi></p>
${shortName ? '<p class="hint">Name shortened for display.</p>' : ''}
</section>
<section aria-labelledby="permissions-heading"><h2 id="permissions-heading">Requested permissions</h2>${permissions}</section>
<section aria-labelledby="return-heading"><h2 id="return-heading">Return address</h2>
<p class="return-url" dir="ltr"><code>${escapeHtml(target.href)}</code></p>
</section>
<p><strong>Only approve if you started this connection and trust the app.</strong></p>
<form method="post" action="${escapeHtml(options.authorizationUrl)}">${inputs}
<div class="actions"><button type="submit" name="consent_action" value="deny">Deny</button>
<button class="primary" type="submit" name="consent_action" value="approve">Approve and continue</button></div></form>
<p class="footer">Request expires after ${options.expiresInSeconds / 60} minutes.</p>`,
  );
}

export function renderConsentErrorPage(origin: string): string {
  return document(
    'Approval expired or invalid',
    origin,
    `<h1>Approval expired or invalid</h1>
<p>No access was approved by this attempt.</p>
<p>Return to your MCP client and start a new connection in the same browser.</p>`,
  );
}

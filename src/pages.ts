export const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

export const BASE_CSS = `
:root{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#6b6b66;--line:#e2e2dd;--accent:#2f5bd3;--accent-text:#fff;--warn:#9a5b00;--warn-bg:#fff4e0;--danger:#b42318;--ok:#18794e;--code:#f0f0ec}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--text:#ececea;--muted:#9b9b95;--line:#33332f;--accent:#7c9bf0;--accent-text:#0b1020;--warn:#f0b54a;--warn-bg:#2b2213;--danger:#f97066;--ok:#4ac88a;--code:#262623}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}
a{color:var(--accent)}
code,pre,textarea.code{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
button{font:inherit;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:6px;padding:6px 12px;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-text)}
button.danger{color:var(--danger)}
button:disabled{opacity:.5;cursor:default}
input,textarea,select{font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;width:100%}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px}
.narrow{max-width:460px;margin:12vh auto;padding:0 16px}
.muted{color:var(--muted)}
.warn{background:var(--warn-bg);color:var(--warn);border-radius:6px;padding:8px 10px}
`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)}</title><style>${BASE_CSS}</style></head><body>${body}</body></html>`;
}

export function html(body: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Content-Security-Policy', "frame-ancestors 'none'");
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Cache-Control', 'no-store');
  return new Response(body, { ...init, headers });
}

export function loginPage(proxyName: string, next: string, error?: string): string {
  return page(
    `Sign in · ${proxyName}`,
    `<div class="narrow"><form class="card" method="post" action="/admin/login">
<h2 style="margin-top:0">${escape(proxyName)}</h2>
<p class="muted">Enter the admin password.</p>
${error ? `<p class="warn">${escape(error)}</p>` : ''}
<input type="hidden" name="next" value="${escape(next)}">
<p><input type="password" name="password" autocomplete="current-password" autofocus required></p>
<button class="primary" type="submit">Sign in</button>
</form></div>`,
  );
}

export interface ConsentDetails {
  clientName: string;
  fingerprint: string;
  redirectHost: string;
  redirectIsLoopback: boolean;
  scope: string[];
}

export function consentPage(proxyName: string, upstreamHost: string, details: ConsentDetails, consent: string): string {
  return page(
    `Authorize ${details.clientName}`,
    `<div class="narrow"><form class="card" method="post" action="/authorize">
<h2 style="margin-top:0">Allow ${escape(details.clientName)} to use ${escape(proxyName)}?</h2>
<p class="muted">This app registered itself, so its name is not verified. Client fingerprint: <code>${escape(details.fingerprint)}</code> (use it to revoke the app later).</p>
<p>It will be able to call the tools this proxy exposes from <strong>${escape(upstreamHost)}</strong>, using the proxy’s upstream login.</p>
<p>Access will be sent to <strong>${escape(details.redirectHost)}</strong>.</p>
${details.redirectIsLoopback ? '<p class="warn">This sends access to an app on your computer. Continue only if you just started connecting from it.</p>' : ''}
${details.scope.length ? `<p class="muted">Scopes: ${details.scope.map(escape).join(', ')}</p>` : ''}
<input type="hidden" name="consent" value="${escape(consent)}">
<p style="display:flex;gap:8px"><button class="primary" name="decision" value="approve">Allow</button><button name="decision" value="deny">Deny</button></p>
</form></div>`,
  );
}

/** Where the upstream sends the browser after sign-in. Any node can show it; the CLI holds the PKCE verifier. */
export function upstreamCallbackPage(proxyName: string, paste: string, error?: string): string {
  return page(
    `Sign-in code · ${proxyName}`,
    `<div class="narrow" style="max-width:620px"><div class="card">
<h2 style="margin-top:0">${error ? 'Upstream sign-in failed' : 'Almost done'}</h2>
${error ? `<p class="warn">${escape(error)}</p>` : ''}
<p>Copy this and paste it into the terminal running <code>mcp-proxy login</code>:</p>
<textarea class="code" readonly rows="4" onclick="this.select()" style="word-break:break-all">${escape(paste)}</textarea>
<p><button class="primary" onclick="navigator.clipboard.writeText(document.querySelector('textarea').value).then(()=>this.textContent='Copied')">Copy</button></p>
<p class="muted">It only works together with that terminal session, and expires within minutes.</p>
</div></div>`,
  );
}

export function messagePage(title: string, message: string, link?: { href: string; label: string }): string {
  return page(
    title,
    `<div class="narrow"><div class="card"><h2 style="margin-top:0">${escape(title)}</h2><p>${escape(message)}</p>
${link ? `<p><a href="${escape(link.href)}">${escape(link.label)}</a></p>` : ''}</div></div>`,
  );
}

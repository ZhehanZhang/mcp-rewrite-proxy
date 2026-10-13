// HTTP routes: agent-facing OAuth and /mcp, the admin editor, and the upstream sign-in landing page.

import { hostname } from 'node:os';
import adminHtml from './admin.html';
import { checkPassword, clearSessionCookie, clientIp, isAdmin, isSameOrigin, loginBlocked, readCookie, recordLoginFailure, sameOriginPath, sessionCookie } from './auth';
import { parseConfig } from './config-file';
import { fingerprint, randomId } from './crypto';
import type { Env } from './env';
import {
  AuthorizeError,
  type AuthRequest,
  approve,
  authorizationServerMetadata,
  deny,
  openConsent,
  parseAuthorize,
  protectedResourceMetadata,
  register,
  resourceUrl,
  revoke,
  sealConsent,
  token,
  verifyBearer,
} from './oauth-server';
import { BASE_CSS, consentPage, escape, html, loginPage, messagePage, upstreamCallbackPage } from './pages';
import { cachedSnapshot, fetchSnapshot, proxyMcp } from './proxy';
import { ConfigError, type ProxyConfig, Rewriter } from './rewrite';
import { clientMetadata } from './upstream-oauth';

const CONSENT_COOKIE = '__Host-proxy-consent';
const APPROVALS_COOKIE = '__Host-proxy-approvals';
const APPROVAL_SECONDS = 30 * 24 * 60 * 60;
const NODE = hostname();

const redirect = (location: string, headers: HeadersInit = {}) => {
  const h = new Headers(headers);
  h.set('Location', location);
  h.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers: h });
};
const jsonError = (status: number, error: string) => Response.json({ error }, { status });


// Agents may run in a browser (e.g. MCP Inspector). These endpoints use bearer tokens, not cookies.
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id, WWW-Authenticate',
  'Access-Control-Max-Age': '86400',
};
function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

// ---------------------------------------------------------------- remembered approvals

interface Approval {
  f: string; // client fingerprint
  r: string; // redirect URI
  x: number; // expires (s)
}

function readApprovals(request: Request, env: Env): Approval[] {
  const sealed = readCookie(request, APPROVALS_COOKIE);
  const list = sealed ? env.sealer.open<Approval[]>('approvals', sealed) : null;
  const now = Date.now() / 1000;
  return Array.isArray(list) ? list.filter((a) => a.x > now) : [];
}

function approvalsCookie(env: Env, approvals: Approval[]): string {
  const value = env.sealer.seal('approvals', approvals.slice(-20));
  return `${APPROVALS_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${APPROVAL_SECONDS}`;
}

// ---------------------------------------------------------------- agent authorization (admin-only consent)

async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  // Only the admin may let an agent use the proxy's upstream login.
  if (!isAdmin(request, env)) {
    if (request.method !== 'GET') return jsonError(401, 'Sign in first');
    return redirect(`/admin/login?next=${encodeURIComponent(url.pathname + url.search)}`);
  }
  try {
    if (request.method === 'GET') {
      const { request: authRequest, client } = parseAuthorize(url.searchParams, env.oauth);
      const fp = fingerprint(authRequest.clientId);
      if (readApprovals(request, env).some((a) => a.f === fp && a.r === authRequest.redirectUri)) {
        console.log(`oauth: approved "${client.n}" (${fp}) from remembered consent`);
        return redirect(approve(authRequest, env.oauth));
      }
      const nonce = randomId();
      const target = new URL(authRequest.redirectUri);
      const page = consentPage(
        env.settings.proxyName,
        new URL(env.settings.upstreamUrl).host,
        {
          clientName: client.n,
          fingerprint: fp,
          redirectHost: target.host || authRequest.redirectUri,
          redirectIsLoopback: ['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname),
          scope: authRequest.scope,
        },
        sealConsent(authRequest, nonce, env.oauth),
      );
      // The nonce cookie ties the form to this browser, so a form lifted elsewhere can't be replayed.
      return html(page, { headers: { 'Set-Cookie': `${CONSENT_COOKIE}=${nonce}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` } });
    }
    if (request.method === 'POST') {
      if (!isSameOrigin(request)) return jsonError(403, 'Cross-site request refused');
      const form = await request.formData();
      const authRequest: AuthRequest | null = openConsent(String(form.get('consent') ?? ''), readCookie(request, CONSENT_COOKIE), env.oauth);
      if (!authRequest) return html(messagePage('Authorization expired', 'This page expired or was opened in another browser. Start connecting from the app again.'), { status: 400 });
      const headers = new Headers({ 'Set-Cookie': `${CONSENT_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0` });
      if (form.get('decision') !== 'approve') return redirect(deny(authRequest, env.oauth), headers);
      const fp = fingerprint(authRequest.clientId);
      const approvals = readApprovals(request, env).filter((a) => !(a.f === fp && a.r === authRequest.redirectUri));
      approvals.push({ f: fp, r: authRequest.redirectUri, x: Math.floor(Date.now() / 1000) + APPROVAL_SECONDS });
      headers.append('Set-Cookie', approvalsCookie(env, approvals));
      console.log(`oauth: admin approved client ${fp}`);
      return redirect(approve(authRequest, env.oauth), headers);
    }
    return new Response('Method not allowed', { status: 405 });
  } catch (error) {
    if (error instanceof AuthorizeError) {
      if (error.redirect) return redirect(error.redirect);
      return html(messagePage('Authorization failed', error.message), { status: 400 });
    }
    throw error;
  }
}

// ---------------------------------------------------------------- admin editor

async function handleAdmin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const name = env.settings.proxyName;

  if (path === '/admin/login') {
    const next = (request.method === 'POST' ? String((await request.clone().formData()).get('next') ?? '') : url.searchParams.get('next')) || '/admin';
    const safeNext = sameOriginPath(next, env.settings.publicUrl);
    if (request.method === 'POST') {
      if (!isSameOrigin(request)) return jsonError(403, 'Cross-site request refused');
      const ip = clientIp(request);
      if (loginBlocked(ip)) return html(loginPage(name, safeNext, 'Too many attempts. Try again in 15 minutes.'), { status: 429 });
      const form = await request.formData();
      if (checkPassword(env, String(form.get('password') ?? ''))) return redirect(safeNext, { 'Set-Cookie': sessionCookie(env) });
      recordLoginFailure(ip);
      return html(loginPage(name, safeNext, 'Wrong password.'), { status: 401 });
    }
    return html(loginPage(name, safeNext));
  }

  if (!isAdmin(request, env)) {
    if (path.startsWith('/admin/api/')) return jsonError(401, 'Sign in again');
    return redirect(`/admin/login?next=${encodeURIComponent(path)}`);
  }
  if (request.method !== 'GET' && !isSameOrigin(request)) return jsonError(403, 'Cross-site request refused');

  switch (`${request.method} ${path}`) {
    case 'GET /admin':
      return html(adminHtml.replace('/*BASE_CSS*/', BASE_CSS).replace('<title>MCP Proxy Admin</title>', `<title>${escape(name)}</title>`));

    case 'POST /admin/logout':
      return redirect('/admin/login', { 'Set-Cookie': clearSessionCookie() });

    case 'GET /admin/api/state': {
      let snapshot = cachedSnapshot();
      let snapshotError: string | undefined;
      if (!snapshot && env.login.isConnected()) {
        try {
          snapshot = await fetchSnapshot(env);
        } catch (error) {
          snapshotError = (error as Error).message;
        }
      }
      return Response.json({
        proxyName: name,
        node: NODE,
        mcpUrl: resourceUrl(env.settings),
        configPath: env.settings.configPath,
        configError: env.config.error ?? null,
        config: env.config.get().config,
        status: env.login.status(),
        snapshot: snapshot ?? null,
        snapshotError: snapshotError ?? null,
      });
    }

    case 'POST /admin/api/preview': {
      const { config, tool } = (await request.json()) as { config: ProxyConfig; tool: string };
      const original = cachedSnapshot()?.tools.find((t) => typeof t === 'object' && t !== null && !Array.isArray(t) && t.name === tool);
      if (!original) return jsonError(404, 'Tool not in the last fetched list');
      try {
        const [rewritten] = new Rewriter(config).rewriteTools([original]);
        return Response.json({ hidden: rewritten === undefined, tool: rewritten ?? null });
      } catch (error) {
        return jsonError(error instanceof ConfigError ? 400 : 500, (error as Error).message);
      }
    }

    case 'POST /admin/api/validate':
      try {
        parseConfig(await request.text());
        return Response.json({ ok: true });
      } catch (error) {
        return jsonError(400, (error as Error).message);
      }

    case 'POST /admin/api/refresh':
      try {
        return Response.json({ snapshot: await fetchSnapshot(env) });
      } catch (error) {
        return jsonError(502, (error as Error).message);
      }
  }
  return new Response('Not found', { status: 404 });
}

// ---------------------------------------------------------------- routing

export type Handler = (request: Request) => Promise<Response>;

export function createApp(env: Env): Handler {
  return async (request) => {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const isPublicApi = path.startsWith('/.well-known/') || path === '/register' || path === '/token' || path === '/revoke' || path === '/mcp' || path.startsWith('/mcp/');
    if (method === 'OPTIONS' && isPublicApi) return new Response(null, { status: 204, headers: CORS });

    if (isPublicApi) {
      return withCors(await (async () => {
        if (path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp') return Response.json(protectedResourceMetadata(env.oauth));
        if (path === '/.well-known/oauth-authorization-server') return Response.json(authorizationServerMetadata(env.oauth));
        if (path === '/register' && method === 'POST') return register(request, env.oauth);
        if (path === '/token' && method === 'POST') return token(request, env.oauth);
        if (path === '/revoke' && method === 'POST') return revoke(request, env.oauth);
        if (path === '/mcp') {
          const agent = verifyBearer(request, env.oauth);
          if (agent instanceof Response) return agent;
          return proxyMcp(request, env);
        }
        return new Response('Not found', { status: 404 });
      })());
    }

    if (path === '/') return redirect('/admin');
    if (path === '/authorize') return handleAuthorize(request, env);
    if (path === '/admin' || path.startsWith('/admin/')) return handleAdmin(request, env);
    if (path === '/upstream-callback') {
      return html(upstreamCallbackPage(env.settings.proxyName, url.search.slice(1), url.searchParams.get('error_description') ?? url.searchParams.get('error') ?? undefined));
    }
    if (path === '/oauth/upstream-client.json') {
      return Response.json(clientMetadata({ redirectUri: `${env.settings.publicUrl}/upstream-callback`, metadataUrl: `${env.settings.publicUrl}${path}`, clientName: env.settings.proxyName }));
    }
    return new Response('Not found', { status: 404 });
  };
}

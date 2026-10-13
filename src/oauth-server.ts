// A stateless OAuth 2.1 authorization server for agents (MCP authorization profile):
// RFC 9728 resource metadata, RFC 8414 server metadata, RFC 7591 dynamic registration,
// authorization code + PKCE (S256 only), refresh tokens, RFC 8707 resource binding, RFC 9207 `iss`.
//
// Nothing is stored. A client ID is the client's sealed registration; codes and tokens are sealed
// claims; a confidential client's secret is a MAC of its ID. Any node holding PROXY_SECRET can
// verify all of them. The trade-off: a single token can't be revoked before it expires. Revoke a
// client by fingerprint, or everything issued before a time, in the config file instead.

import type { LoadedConfig } from './config-file';
import { type Sealer, fingerprint, randomId, sha256base64url } from './crypto';
import type { Settings } from './env';

export const ACCESS_TOKEN_SECONDS = 60 * 60;
export const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60; // sliding: each refresh extends it
export const GRANT_MAX_SECONDS = 90 * 24 * 60 * 60; // absolute: then the agent must be approved again
const CODE_SECONDS = 60;
const CONSENT_SECONDS = 10 * 60;

type AuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

/** The sealed registration that *is* the client ID. Short keys keep IDs compact. */
interface ClientClaims {
  n: string; // client_name
  r: string[]; // redirect_uris
  m: AuthMethod;
  t: number; // issued at (s)
}

export interface AuthRequest {
  clientId: string;
  redirectUri: string;
  state?: string;
  scope: string[];
  codeChallenge: string;
  resource: string;
}

interface CodeClaims {
  c: string; // client fingerprint
  r: string; // redirect_uri
  p: string; // PKCE challenge
  s: string[];
  x: number; // expires (s)
  j: string; // id, for best-effort replay detection
}

interface TokenClaims {
  c: string; // client fingerprint
  s: string[];
  g: number; // grant issued at (s): when the admin approved this agent
  x: number; // expires (s)
}

export interface OAuthContext {
  settings: Settings;
  sealer: Sealer;
  policy: () => LoadedConfig;
}

export interface Agent {
  via: 'oauth' | 'api-key';
  client?: string;
}

const now = () => Math.floor(Date.now() / 1000);
const MCP_PATH = '/mcp';

export function resourceUrl(settings: Settings): string {
  return `${settings.publicUrl}${MCP_PATH}`;
}

export function resourceMetadataUrl(settings: Settings): string {
  return `${settings.publicUrl}/.well-known/oauth-protected-resource${MCP_PATH}`;
}

// ---------------------------------------------------------------- metadata

export function protectedResourceMetadata(ctx: OAuthContext) {
  return {
    resource: resourceUrl(ctx.settings),
    authorization_servers: [ctx.settings.publicUrl],
    bearer_methods_supported: ['header'],
    resource_name: ctx.settings.proxyName,
  };
}

export function authorizationServerMetadata(ctx: OAuthContext) {
  const base = ctx.settings.publicUrl;
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    revocation_endpoint: `${base}/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: false,
  };
}

/** The 401 challenge that sends an agent to the resource metadata. */
export function challenge(ctx: OAuthContext, error?: string): string {
  return `Bearer resource_metadata="${resourceMetadataUrl(ctx.settings)}"${error ? `, error="${error}"` : ''}`;
}

// ---------------------------------------------------------------- errors

function oauthError(status: number, error: string, description: string, headers: Record<string, string> = {}): Response {
  return Response.json({ error, error_description: description }, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

/** A validation failure. `redirect` is set only once the client and redirect URI are trusted. */
export class AuthorizeError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly redirect?: string,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------- redirect URIs

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const FORBIDDEN_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:']);

function checkRedirectUri(uri: string): string | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return `not a URL: ${uri}`;
  }
  if (url.hash) return `redirect URIs may not have a fragment: ${uri}`;
  if (url.protocol === 'https:') return null;
  if (url.protocol === 'http:') return LOOPBACK.has(url.hostname) ? null : `http redirect URIs must be loopback: ${uri}`;
  if (FORBIDDEN_SCHEMES.has(url.protocol)) return `scheme not allowed: ${uri}`;
  return null; // private-use scheme for native apps (RFC 8252 §7.1), e.g. cursor://
}

/** Exact match, except a loopback redirect may use any port (RFC 8252 §7.3). */
function redirectMatches(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  try {
    const a = new URL(registered);
    const b = new URL(presented);
    return a.protocol === 'http:' && b.protocol === 'http:' && LOOPBACK.has(a.hostname) && a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- clients

function openClient(ctx: OAuthContext, clientId: string | null): ClientClaims | null {
  if (!clientId) return null;
  const claims = ctx.sealer.open<ClientClaims>('client', clientId);
  if (!claims || !Array.isArray(claims.r)) return null;
  return claims;
}

function clientSecret(ctx: OAuthContext, clientId: string): string {
  return ctx.sealer.mac(`client-secret:${clientId}`).toString('base64url');
}

export async function register(request: Request, ctx: OAuthContext): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return oauthError(400, 'invalid_client_metadata', 'Body must be JSON client metadata');
  }
  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 10 || !redirectUris.every((u) => typeof u === 'string')) {
    return oauthError(400, 'invalid_redirect_uri', 'redirect_uris must be a list of 1 to 10 URIs');
  }
  for (const uri of redirectUris) {
    const problem = checkRedirectUri(uri);
    if (problem) return oauthError(400, 'invalid_redirect_uri', problem);
  }
  const method = (body.token_endpoint_auth_method ?? 'client_secret_basic') as AuthMethod;
  if (!['none', 'client_secret_basic', 'client_secret_post'].includes(method)) {
    return oauthError(400, 'invalid_client_metadata', `Unsupported token_endpoint_auth_method ${String(method)}`);
  }
  const grantTypes = (body.grant_types as string[] | undefined) ?? ['authorization_code', 'refresh_token'];
  if (!Array.isArray(grantTypes) || grantTypes.some((g) => g !== 'authorization_code' && g !== 'refresh_token')) {
    return oauthError(400, 'invalid_client_metadata', 'Only authorization_code and refresh_token grants are supported');
  }
  const name = typeof body.client_name === 'string' ? body.client_name.slice(0, 100) : 'Unnamed client';
  const claims: ClientClaims = { n: name, r: redirectUris as string[], m: method, t: now() };
  const clientId = ctx.sealer.seal('client', claims);
  const response: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: claims.t,
    client_name: name,
    redirect_uris: claims.r,
    grant_types: grantTypes,
    response_types: ['code'],
    token_endpoint_auth_method: method,
  };
  if (method !== 'none') {
    response.client_secret = clientSecret(ctx, clientId);
    response.client_secret_expires_at = 0;
  }
  console.log(`oauth: registered client "${name}" (${fingerprint(clientId)})`);
  return Response.json(response, { status: 201, headers: { 'Cache-Control': 'no-store' } });
}

// ---------------------------------------------------------------- authorize

/** Validates an authorization request (RFC 6749 §4.1.2.1 order: client and redirect URI first). */
export function parseAuthorize(params: URLSearchParams, ctx: OAuthContext): { request: AuthRequest; client: ClientClaims } {
  const clientId = params.get('client_id');
  const client = openClient(ctx, clientId);
  if (!client || !clientId) throw new AuthorizeError('invalid_client', 'Unknown client. Remove and re-add this MCP server in your agent.');
  const redirectUri = params.get('redirect_uri') ?? (client.r.length === 1 ? client.r[0] : null);
  if (!redirectUri || !client.r.some((r) => redirectMatches(r, redirectUri))) {
    throw new AuthorizeError('invalid_request', 'The redirect URI is not registered for this client.');
  }
  // From here on, errors go back to the client.
  const fail = (code: string, message: string): never => {
    throw new AuthorizeError(code, message, errorRedirect(ctx, redirectUri, params.get('state') ?? undefined, code, message));
  };
  if (ctx.policy().revoked.has(fingerprint(clientId))) fail('access_denied', 'This client has been revoked');
  if (params.get('response_type') !== 'code') fail('unsupported_response_type', 'Only response_type=code is supported');
  const challenge = params.get('code_challenge');
  if (!challenge || params.get('code_challenge_method') !== 'S256') fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
  const resources = params.getAll('resource');
  if (resources.length > 1 || (resources[0] && resources[0].replace(/\/$/, '') !== resourceUrl(ctx.settings))) {
    fail('invalid_target', `The only resource here is ${resourceUrl(ctx.settings)}`);
  }
  return {
    client,
    request: {
      clientId,
      redirectUri,
      state: params.get('state') ?? undefined,
      scope: (params.get('scope') ?? '').split(' ').filter(Boolean),
      codeChallenge: challenge!,
      resource: resourceUrl(ctx.settings),
    },
  };
}

function errorRedirect(ctx: OAuthContext, redirectUri: string, state: string | undefined, error: string, description: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  if (state) url.searchParams.set('state', state);
  url.searchParams.set('iss', ctx.settings.publicUrl);
  return url.toString();
}

/** The approved request's redirect, carrying a fresh authorization code. */
export function approve(request: AuthRequest, ctx: OAuthContext): string {
  const code = ctx.sealer.seal('code', {
    c: fingerprint(request.clientId),
    r: request.redirectUri,
    p: request.codeChallenge,
    s: request.scope,
    x: now() + CODE_SECONDS,
    j: randomId(),
  } satisfies CodeClaims);
  const url = new URL(request.redirectUri);
  url.searchParams.set('code', code);
  if (request.state) url.searchParams.set('state', request.state);
  url.searchParams.set('iss', ctx.settings.publicUrl);
  return url.toString();
}

export function deny(request: AuthRequest, ctx: OAuthContext): string {
  return errorRedirect(ctx, request.redirectUri, request.state, 'access_denied', 'The administrator declined');
}

/** The consent form's hidden field: the validated request, sealed and tied to one browser nonce. */
export function sealConsent(request: AuthRequest, nonce: string, ctx: OAuthContext): string {
  return ctx.sealer.seal('consent', { q: request, n: nonce, x: now() + CONSENT_SECONDS });
}

export function openConsent(sealed: string, nonce: string | undefined, ctx: OAuthContext): AuthRequest | null {
  const consent = ctx.sealer.open<{ q: AuthRequest; n: string; x: number }>('consent', sealed);
  if (!consent || !nonce || consent.x < now() || !ctx.sealer.equal(consent.n, nonce)) return null;
  return consent.q;
}

// ---------------------------------------------------------------- token

/** Codes seen on this node, until they expire. Cross-node replay inside 60 s still needs the PKCE verifier. */
const usedCodes = new Map<string, number>();

function authenticateClient(request: Request, form: URLSearchParams, ctx: OAuthContext): { clientId: string; client: ClientClaims } | Response {
  let clientId = form.get('client_id');
  let secret = form.get('client_secret');
  let basic = false;
  const header = request.headers.get('authorization');
  if (header?.toLowerCase().startsWith('basic ')) {
    const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    if (i < 0) return oauthError(401, 'invalid_client', 'Malformed Basic credentials', { 'WWW-Authenticate': 'Basic realm="OAuth"' });
    const id = decodeURIComponent(decoded.slice(0, i));
    if (clientId && clientId !== id) return oauthError(400, 'invalid_request', 'Conflicting client_id');
    clientId = id;
    secret = decodeURIComponent(decoded.slice(i + 1));
    basic = true;
  }
  const client = openClient(ctx, clientId);
  const unauthorized = () => oauthError(401, 'invalid_client', 'Client authentication failed', basic ? { 'WWW-Authenticate': 'Basic realm="OAuth"' } : {});
  if (!client || !clientId) return unauthorized();
  if (client.m !== 'none') {
    if (!secret || !ctx.sealer.verifyMac(`client-secret:${clientId}`, Buffer.from(secret, 'base64url'))) return unauthorized();
  }
  if (ctx.policy().revoked.has(fingerprint(clientId))) return oauthError(400, 'invalid_grant', 'This client has been revoked');
  return { clientId, client };
}

function issueTokens(ctx: OAuthContext, clientFp: string, scope: string[], grantIssuedAt: number): Response {
  const t = now();
  const accessToken = ctx.sealer.seal('access', { c: clientFp, s: scope, g: grantIssuedAt, x: t + ACCESS_TOKEN_SECONDS } satisfies TokenClaims);
  const refreshExpires = Math.min(t + REFRESH_TOKEN_SECONDS, grantIssuedAt + GRANT_MAX_SECONDS);
  const body: Record<string, unknown> = { access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS };
  if (refreshExpires > t + 60) body.refresh_token = ctx.sealer.seal('refresh', { c: clientFp, s: scope, g: grantIssuedAt, x: refreshExpires } satisfies TokenClaims);
  if (scope.length) body.scope = scope.join(' ');
  return Response.json(body, { headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' } });
}

export async function token(request: Request, ctx: OAuthContext): Promise<Response> {
  if (!(request.headers.get('content-type') ?? '').includes('application/x-www-form-urlencoded')) {
    return oauthError(400, 'invalid_request', 'Use application/x-www-form-urlencoded');
  }
  const form = new URLSearchParams(await request.text());
  const auth = authenticateClient(request, form, ctx);
  if (auth instanceof Response) return auth;
  const clientFp = fingerprint(auth.clientId);
  const resource = form.get('resource');
  if (resource && resource.replace(/\/$/, '') !== resourceUrl(ctx.settings)) return oauthError(400, 'invalid_target', `The only resource here is ${resourceUrl(ctx.settings)}`);

  switch (form.get('grant_type')) {
    case 'authorization_code': {
      const code = ctx.sealer.open<CodeClaims>('code', form.get('code') ?? '');
      const t = now();
      if (!code || code.x < t || code.c !== clientFp) return oauthError(400, 'invalid_grant', 'Invalid or expired authorization code');
      if (usedCodes.has(code.j)) return oauthError(400, 'invalid_grant', 'Authorization code already used');
      const redirectUri = form.get('redirect_uri');
      if (redirectUri !== null && redirectUri !== code.r) return oauthError(400, 'invalid_grant', 'redirect_uri does not match the authorization request');
      const verifier = form.get('code_verifier');
      if (!verifier || !/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier) || sha256base64url(verifier) !== code.p) {
        return oauthError(400, 'invalid_grant', 'PKCE verification failed');
      }
      usedCodes.set(code.j, code.x);
      for (const [id, expires] of usedCodes) if (expires < t) usedCodes.delete(id);
      return issueTokens(ctx, clientFp, code.s, t);
    }
    case 'refresh_token': {
      const refresh = ctx.sealer.open<TokenClaims>('refresh', form.get('refresh_token') ?? '');
      if (!refresh || refresh.x < now() || refresh.c !== clientFp || refresh.g < ctx.policy().notBefore) {
        return oauthError(400, 'invalid_grant', 'Invalid, expired or revoked refresh token');
      }
      const requested = (form.get('scope') ?? '').split(' ').filter(Boolean);
      if (requested.some((s) => !refresh.s.includes(s))) return oauthError(400, 'invalid_scope', 'Cannot widen scope on refresh');
      return issueTokens(ctx, clientFp, requested.length ? requested : refresh.s, refresh.g);
    }
    default:
      return oauthError(400, 'unsupported_grant_type', 'Supported: authorization_code, refresh_token');
  }
}

/** RFC 7009. Stateless tokens can't be revoked individually; the client discards them. */
export async function revoke(request: Request, ctx: OAuthContext): Promise<Response> {
  const form = new URLSearchParams(await request.text());
  const auth = authenticateClient(request, form, ctx);
  if (auth instanceof Response) return auth;
  return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } });
}

// ---------------------------------------------------------------- bearer check for /mcp

export function verifyBearer(request: Request, ctx: OAuthContext): Agent | Response {
  const match = /^Bearer[\t ]+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  if (!match) return unauthorized(ctx);
  const presented = match[1];
  const claims = ctx.sealer.open<TokenClaims>('access', presented);
  if (claims) {
    const policy = ctx.policy();
    if (claims.x < now() || policy.revoked.has(claims.c) || claims.g < policy.notBefore) return unauthorized(ctx, 'invalid_token');
    return { via: 'oauth', client: claims.c };
  }
  // Static keys for headless agents (outside the MCP OAuth profile, so opt-in via API_KEYS).
  if (ctx.settings.apiKeys.some((key) => key.length >= 16 && ctx.sealer.equal(presented, key))) return { via: 'api-key' };
  return unauthorized(ctx, 'invalid_token');
}

function unauthorized(ctx: OAuthContext, error?: string): Response {
  return Response.json(
    error ? { error, error_description: 'Invalid or expired access token' } : { error: 'unauthorized', error_description: 'Authorization required' },
    { status: 401, headers: { 'WWW-Authenticate': challenge(ctx, error), 'Cache-Control': 'no-store' } },
  );
}

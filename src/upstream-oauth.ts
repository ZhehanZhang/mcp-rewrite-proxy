// OAuth client for the upstream MCP server, following MCP authorization discovery:
// protected resource metadata (RFC 9728) → authorization server metadata (RFC 8414 / OIDC),
// then a pre-registered client, a Client ID Metadata Document, or dynamic registration (RFC 7591),
// with PKCE (S256) and resource indicators (RFC 8707).

export interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
  client_id_metadata_document_supported?: boolean;
  authorization_response_iss_parameter_supported?: boolean;
}

export interface Discovery {
  authServer: AuthServerMetadata;
  /** Scopes from the protected resource metadata or the 401 challenge. */
  resourceScopes?: string[];
  /** RFC 8707 resource indicator for the upstream server. */
  resource: string;
  /** False for pre-2025-06 servers without protected resource metadata. */
  hasResourceMetadata: boolean;
}

export type ClientAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export interface UpstreamClient {
  client_id: string;
  client_secret?: string;
  auth_method: ClientAuthMethod;
  /** How this client came to be, for the admin page. */
  source: 'configured' | 'metadata-document' | 'dynamic-registration';
}

export interface UpstreamTokens {
  access_token: string;
  token_type: string;
  refresh_token?: string;
  /** Epoch milliseconds. */
  expires_at?: number;
  scope?: string;
}

export class UpstreamOAuthError extends Error {
  constructor(
    message: string,
    readonly code?: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

const JSON_HEADERS = { Accept: 'application/json' };

async function getJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, { headers: JSON_HEADERS });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

function wellKnown(base: string, suffix: string): string[] {
  const url = new URL(base);
  const path = url.pathname.replace(/\/$/, '');
  const urls = [];
  if (path) urls.push(`${url.origin}/.well-known/${suffix}${path}`);
  urls.push(`${url.origin}/.well-known/${suffix}`);
  return urls;
}

/** Parses `Bearer resource_metadata="…", scope="…"` into its parameters. */
export function parseChallenge(header: string | null): Record<string, string> {
  const params: Record<string, string> = {};
  if (!header) return params;
  for (const match of header.matchAll(/([a-zA-Z_]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g)) {
    params[match[1].toLowerCase()] = (match[2] ?? match[3]).replace(/\\(.)/g, '$1');
  }
  return params;
}

async function probeChallenge(mcpUrl: string): Promise<Record<string, string>> {
  try {
    const res = await fetch(mcpUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'ping' }),
    });
    await res.body?.cancel();
    return res.status === 401 ? parseChallenge(res.headers.get('WWW-Authenticate')) : {};
  } catch {
    return {};
  }
}

interface ResourceMetadata {
  resource?: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
}

export async function discover(mcpUrl: string, overrides: Partial<AuthServerMetadata> = {}): Promise<Discovery> {
  // The 401 challenge is authoritative; well-known locations are the fallback.
  const challenge = await probeChallenge(mcpUrl);
  let prm: ResourceMetadata | null = null;
  if (challenge.resource_metadata) prm = await getJson<ResourceMetadata>(challenge.resource_metadata);
  for (const url of prm ? [] : wellKnown(mcpUrl, 'oauth-protected-resource')) {
    prm = await getJson<ResourceMetadata>(url);
    if (prm) break;
  }

  const issuer = prm?.authorization_servers?.[0] ?? new URL(mcpUrl).origin;
  let authServer: AuthServerMetadata | null = null;
  const candidates = [...wellKnown(issuer, 'oauth-authorization-server'), ...wellKnown(issuer, 'openid-configuration')];
  if (new URL(issuer).pathname.replace(/\/$/, '')) candidates.push(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  for (const url of candidates) {
    authServer = await getJson<AuthServerMetadata>(url);
    if (authServer?.authorization_endpoint && authServer.token_endpoint) break;
    authServer = null;
  }
  if (!authServer && !prm) {
    // 2025-03-26 servers: the MCP origin is the authorization server, with default paths.
    const origin = new URL(mcpUrl).origin;
    authServer = {
      issuer: origin,
      authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`,
      registration_endpoint: `${origin}/register`,
    };
  }
  authServer = { ...authServer, ...overrides } as AuthServerMetadata;
  if (!authServer.authorization_endpoint || !authServer.token_endpoint) {
    throw new UpstreamOAuthError(`Could not find authorization server metadata for ${issuer}`);
  }
  const scopes = challenge.scope ? challenge.scope.split(' ') : prm?.scopes_supported;
  return {
    authServer,
    resourceScopes: scopes?.length ? scopes : undefined,
    resource: prm?.resource ?? mcpUrl,
    hasResourceMetadata: !!prm,
  };
}

export interface ClientIdentity {
  redirectUri: string;
  /** URL of this proxy's Client ID Metadata Document. */
  metadataUrl: string;
  clientName: string;
  configuredId?: string;
  configuredSecret?: string;
}

export function clientMetadata(identity: Pick<ClientIdentity, 'redirectUri' | 'metadataUrl' | 'clientName'>) {
  return {
    client_id: identity.metadataUrl,
    client_name: identity.clientName,
    redirect_uris: [identity.redirectUri],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };
}

function pickAuthMethod(authServer: AuthServerMetadata, hasSecret: boolean): ClientAuthMethod {
  if (!hasSecret) return 'none';
  const supported = authServer.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  return supported.includes('client_secret_basic') ? 'client_secret_basic' : 'client_secret_post';
}

export async function obtainClient(authServer: AuthServerMetadata, identity: ClientIdentity): Promise<UpstreamClient> {
  if (identity.configuredId) {
    return {
      client_id: identity.configuredId,
      client_secret: identity.configuredSecret,
      auth_method: pickAuthMethod(authServer, !!identity.configuredSecret),
      source: 'configured',
    };
  }
  if (authServer.client_id_metadata_document_supported && identity.metadataUrl.startsWith('https://')) {
    return { client_id: identity.metadataUrl, auth_method: 'none', source: 'metadata-document' };
  }
  if (!authServer.registration_endpoint) {
    throw new UpstreamOAuthError(
      'The upstream authorization server supports neither dynamic client registration nor client ID metadata documents. ' +
        'Register an OAuth app there and set the UPSTREAM_CLIENT_ID (and UPSTREAM_CLIENT_SECRET) secrets.',
    );
  }
  const { client_id: _, ...metadata } = clientMetadata(identity);
  const res = await fetch(authServer.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...JSON_HEADERS },
    body: JSON.stringify(metadata),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, string>;
  if (!res.ok || !body.client_id) {
    throw new UpstreamOAuthError(`Dynamic client registration failed (${res.status}): ${body.error_description ?? body.error ?? 'no client_id'}`);
  }
  const method = body.token_endpoint_auth_method as ClientAuthMethod | undefined;
  return {
    client_id: body.client_id,
    client_secret: body.client_secret,
    auth_method: method && ['none', 'client_secret_basic', 'client_secret_post'].includes(method) ? method : pickAuthMethod(authServer, !!body.client_secret),
    source: 'dynamic-registration',
  };
}

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  return base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
}

export function chooseScopes(discovery: Discovery, configured?: string[]): string[] | undefined {
  const scopes = configured?.length ? [...configured] : discovery.resourceScopes ? [...discovery.resourceScopes] : undefined;
  // Ask for a refresh token where the server models that as a scope.
  if (scopes && discovery.authServer.scopes_supported?.includes('offline_access') && !scopes.includes('offline_access')) {
    scopes.push('offline_access');
  }
  return scopes;
}

export async function authorizationUrl(options: {
  discovery: Discovery;
  client: UpstreamClient;
  redirectUri: string;
  state: string;
  verifier: string;
  scopes?: string[];
  sendResource: boolean;
}): Promise<string> {
  const url = new URL(options.discovery.authServer.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', options.client.client_id);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', await pkceChallenge(options.verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  if (options.scopes?.length) url.searchParams.set('scope', options.scopes.join(' '));
  if (options.sendResource) url.searchParams.set('resource', options.discovery.resource);
  return url.toString();
}

export async function tokenRequest(
  authServer: AuthServerMetadata,
  client: UpstreamClient,
  params: Record<string, string>,
): Promise<UpstreamTokens> {
  const body = new URLSearchParams(params);
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', ...JSON_HEADERS };
  if (client.auth_method === 'client_secret_basic' && client.client_secret) {
    headers.Authorization = `Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`)}`;
  } else {
    body.set('client_id', client.client_id);
    if (client.auth_method === 'client_secret_post' && client.client_secret) body.set('client_secret', client.client_secret);
  }
  let res: Response;
  try {
    res = await fetch(authServer.token_endpoint, { method: 'POST', headers, body });
  } catch (error) {
    throw new UpstreamOAuthError(`Token endpoint unreachable: ${(error as Error).message}`, 'temporarily_unavailable');
  }
  const text = await res.text();
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(text);
  } catch {
    data = Object.fromEntries(new URLSearchParams(text)); // some providers answer form-encoded
  }
  if (!res.ok || typeof data.access_token !== 'string') {
    const code = typeof data.error === 'string' ? data.error : res.status >= 500 ? 'temporarily_unavailable' : 'invalid_grant';
    throw new UpstreamOAuthError(`Token request failed (${res.status}): ${data.error_description ?? data.error ?? text.slice(0, 200)}`, code, res.status);
  }
  const expiresIn = Number(data.expires_in);
  return {
    access_token: data.access_token,
    token_type: typeof data.token_type === 'string' ? data.token_type : 'Bearer',
    refresh_token: typeof data.refresh_token === 'string' ? data.refresh_token : undefined,
    expires_at: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : undefined,
    scope: typeof data.scope === 'string' ? data.scope : undefined,
  };
}

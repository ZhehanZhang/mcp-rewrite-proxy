import { readFileSync } from 'node:fs';
import type { ConfigFile } from './config-file';
import type { Sealer } from './crypto';
import type { OAuthContext } from './oauth-server';
import type { UpstreamLogin } from './upstream-login';
import type { AuthServerMetadata } from './upstream-oauth';

export interface Settings {
  /** Public origin agents and browsers use, e.g. https://mcp-proxy.example.com (the tunnel hostname). */
  publicUrl: string;
  port: number;
  /** The transferable config file (tool edits, agent revocations). Same on every node. */
  configPath: string;
  /** This node's own data (its upstream login). A per-node volume. */
  dataDir: string;
  proxyName: string;

  upstreamUrl: string;
  upstreamScopes?: string[];
  upstreamClientId?: string;
  upstreamClientSecret?: string;
  upstreamSendResource: boolean;
  upstreamAuthServerOverrides: Partial<AuthServerMetadata>;

  adminPassword: string;
  proxySecret: string;
  /** Older secrets still accepted while agents' tokens roll over to a new PROXY_SECRET. */
  proxySecretPrevious: string[];
  apiKeys: string[];
  /** cloudflared connector token; when set, the container runs its own tunnel connector. */
  tunnelToken?: string;
}

/** Everything request handlers need. */
export interface Env {
  settings: Settings;
  sealer: Sealer;
  config: ConfigFile;
  login: UpstreamLogin;
  oauth: OAuthContext;
}

/** Reads NAME, or the file named by NAME_FILE (Docker/Compose secrets). */
function read(name: string): string | undefined {
  const file = process.env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  const value = process.env[name];
  return value === undefined || value === '' ? undefined : value;
}

function required(name: string): string {
  const value = read(name);
  if (!value) throw new Error(`${name} (or ${name}_FILE) must be set`);
  return value;
}

function parseUrl(name: string): URL {
  const value = required(name);
  try {
    return new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL: ${value}`);
  }
}

export function loadSettings(): Settings {
  const publicUrl = parseUrl('PUBLIC_URL');
  if (publicUrl.pathname !== '/' || publicUrl.search) throw new Error('PUBLIC_URL must be an origin, like https://mcp-proxy.example.com');
  const proxySecret = required('PROXY_SECRET');
  if (proxySecret.length < 32) throw new Error('PROXY_SECRET must be at least 32 characters');
  const overrides = read('UPSTREAM_AUTH_SERVER_OVERRIDES');
  return {
    publicUrl: publicUrl.origin,
    port: Number(read('PORT') ?? 8080),
    configPath: read('CONFIG_PATH') ?? '/config/proxy.config.json',
    dataDir: read('DATA_DIR') ?? '/data',
    proxyName: read('PROXY_NAME') ?? 'MCP Rewrite Proxy',
    upstreamUrl: parseUrl('UPSTREAM_URL').toString(),
    upstreamScopes: read('UPSTREAM_SCOPES')?.split(/\s+/).filter(Boolean),
    upstreamClientId: read('UPSTREAM_CLIENT_ID'),
    upstreamClientSecret: read('UPSTREAM_CLIENT_SECRET'),
    upstreamSendResource: read('UPSTREAM_SEND_RESOURCE') !== 'false',
    upstreamAuthServerOverrides: overrides ? JSON.parse(overrides) : {},
    adminPassword: required('ADMIN_PASSWORD'),
    proxySecret,
    proxySecretPrevious: (read('PROXY_SECRET_PREVIOUS') ?? '').split(',').map((k) => k.trim()).filter(Boolean),
    apiKeys: (read('API_KEYS') ?? '').split(',').map((k) => k.trim()).filter(Boolean),
    tunnelToken: read('TUNNEL_TOKEN'),
  };
}

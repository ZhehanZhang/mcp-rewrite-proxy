// This node's own upstream login, kept in a file on the node's volume. Each node signs in
// separately (`mcp-proxy login`), so a rotating refresh token is only ever used by one node and
// nodes never need to coordinate.

import { chmodSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Settings } from './env';
import {
  type Discovery,
  type UpstreamClient,
  type UpstreamTokens,
  UpstreamOAuthError,
  authorizationUrl,
  chooseScopes,
  discover,
  obtainClient,
  randomToken,
  tokenRequest,
} from './upstream-oauth';

/** How long before expiry a token is refreshed. */
export const REFRESH_MARGIN_MS = 60 * 1000;

interface Stored {
  discovery?: Discovery;
  client?: UpstreamClient;
  redirectUri?: string;
  tokens?: UpstreamTokens;
  /** Identifies one sign-in; a refresh never overwrites a newer sign-in. */
  connectedAt?: number;
  lastError?: string;
}

export interface Status {
  upstreamUrl: string;
  connected: boolean;
  issuer?: string;
  clientSource?: UpstreamClient['source'];
  scope?: string;
  expiresAt?: number;
  hasRefreshToken: boolean;
  connectedAt?: number;
  lastError?: string;
}

export interface PendingLogin {
  url: string;
  state: string;
  verifier: string;
  redirectUri: string;
  discovery: Discovery;
  client: UpstreamClient;
}

export class UpstreamLogin {
  private stored: Stored = {};
  private signature = '';
  private refreshing?: Promise<UpstreamTokens>;
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly file: string,
    private readonly settings: Settings,
  ) {
    this.load();
  }

  /** Re-reads the file if another process (the login command) changed it. */
  load(): void {
    let signature: string;
    try {
      const stat = statSync(this.file);
      signature = `${stat.mtimeMs}:${stat.size}:${stat.ino}`;
    } catch {
      this.stored = {};
      this.signature = '';
      return;
    }
    if (signature === this.signature) return;
    try {
      this.stored = JSON.parse(readFileSync(this.file, 'utf8')) as Stored;
      this.signature = signature;
    } catch (error) {
      console.error(`upstream login: unreadable ${this.file}: ${(error as Error).message}`);
    }
  }

  watch(intervalMs = 2_000): void {
    this.timer = setInterval(() => this.load(), intervalMs);
    this.timer.unref();
  }

  stop(): void {
    clearInterval(this.timer);
  }

  private save(next: Stored): void {
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(next, null, 2), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.file); // atomic: readers see the old or the new file, never half of one
    this.stored = next;
    const stat = statSync(this.file);
    this.signature = `${stat.mtimeMs}:${stat.size}:${stat.ino}`;
  }

  /** True when this node holds a login it can use (or try to refresh). */
  isConnected(): boolean {
    this.load();
    return !!this.stored.tokens;
  }

  status(): Status {
    this.load();
    const { tokens, discovery, client, connectedAt, lastError } = this.stored;
    return {
      upstreamUrl: this.settings.upstreamUrl,
      connected: !!tokens,
      issuer: discovery?.authServer.issuer,
      clientSource: client?.source,
      scope: tokens?.scope,
      expiresAt: tokens?.expires_at,
      hasRefreshToken: !!tokens?.refresh_token,
      connectedAt,
      lastError,
    };
  }

  // ---------------------------------------------------------------- sign-in (used by the CLI)

  async begin(): Promise<PendingLogin> {
    this.load();
    const redirectUri = `${this.settings.publicUrl}/upstream-callback`;
    const discovery = await discover(this.settings.upstreamUrl, this.settings.upstreamAuthServerOverrides);
    const saved = this.stored;
    // Reuse this node's dynamically registered client instead of registering again on every login.
    const client =
      saved.client && !this.settings.upstreamClientId && saved.client.source === 'dynamic-registration' && saved.redirectUri === redirectUri && saved.discovery?.authServer.issuer === discovery.authServer.issuer
        ? saved.client
        : await obtainClient(discovery.authServer, {
            redirectUri,
            metadataUrl: `${this.settings.publicUrl}/oauth/upstream-client.json`,
            clientName: this.settings.proxyName,
            configuredId: this.settings.upstreamClientId,
            configuredSecret: this.settings.upstreamClientSecret,
          });
    const state = randomToken();
    const verifier = randomToken(48);
    const url = await authorizationUrl({
      discovery,
      client,
      redirectUri,
      state,
      verifier,
      scopes: chooseScopes(discovery, this.settings.upstreamScopes),
      sendResource: this.settings.upstreamSendResource,
    });
    return { url, state, verifier, redirectUri, discovery, client };
  }

  async complete(pending: PendingLogin, callback: URLSearchParams): Promise<void> {
    const error = callback.get('error');
    if (error) throw new UpstreamOAuthError(`The upstream refused: ${error}${callback.get('error_description') ? ` (${callback.get('error_description')})` : ''}`);
    if (callback.get('state') !== pending.state) throw new UpstreamOAuthError('That code belongs to a different sign-in attempt. Run the login command again.');
    const iss = callback.get('iss');
    if (iss && iss !== pending.discovery.authServer.issuer) throw new UpstreamOAuthError(`Unexpected issuer ${iss}`); // RFC 9207
    const code = callback.get('code');
    if (!code) throw new UpstreamOAuthError('No authorization code in what was pasted.');
    const params: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: pending.redirectUri, code_verifier: pending.verifier };
    if (this.settings.upstreamSendResource) params.resource = pending.discovery.resource;
    const tokens = await tokenRequest(pending.discovery.authServer, pending.client, params);
    this.save({ discovery: pending.discovery, client: pending.client, redirectUri: pending.redirectUri, tokens, connectedAt: Date.now() });
  }

  logout(): void {
    this.load();
    const { discovery, client, redirectUri } = this.stored;
    this.save({ discovery, client, redirectUri });
  }

  // ---------------------------------------------------------------- tokens (used by the server)

  /**
   * A usable access token. Pass the token the upstream just rejected to force a refresh;
   * concurrent callers on this node share one refresh.
   */
  async accessToken(rejected?: string): Promise<{ token: string; expiresAt?: number }> {
    this.load();
    const tokens = this.stored.tokens;
    if (!tokens) throw new UpstreamOAuthError(this.stored.lastError ?? 'This node is not signed in to the upstream. Run `mcp-proxy login` on it.');
    const stale = rejected ? rejected === tokens.access_token : !!tokens.expires_at && tokens.expires_at - REFRESH_MARGIN_MS < Date.now();
    if (!stale) return { token: tokens.access_token, expiresAt: tokens.expires_at };
    if (!tokens.refresh_token) {
      if (!rejected) return { token: tokens.access_token, expiresAt: tokens.expires_at };
      this.fail('The upstream rejected this node’s login and issued no refresh token. Run `mcp-proxy login` on it again.');
    }
    this.refreshing ??= this.refresh().finally(() => (this.refreshing = undefined));
    const next = await this.refreshing;
    return { token: next.access_token, expiresAt: next.expires_at };
  }

  private async refresh(): Promise<UpstreamTokens> {
    const { tokens, discovery, client, connectedAt } = this.stored;
    if (!tokens?.refresh_token || !discovery || !client) throw new UpstreamOAuthError('This node is not signed in to the upstream.');
    const params: Record<string, string> = { grant_type: 'refresh_token', refresh_token: tokens.refresh_token };
    if (this.settings.upstreamSendResource) params.resource = discovery.resource;
    try {
      const next = await tokenRequest(discovery.authServer, client, params);
      next.refresh_token ??= tokens.refresh_token; // providers that don't rotate keep the old one
      next.scope ??= tokens.scope;
      this.load();
      if (this.stored.connectedAt !== connectedAt) return this.stored.tokens!; // a new login landed meanwhile; keep it
      this.save({ ...this.stored, tokens: next, lastError: undefined });
      return next;
    } catch (error) {
      if (error instanceof UpstreamOAuthError && (error.code === 'invalid_grant' || error.code === 'invalid_client')) {
        this.fail(`The upstream login expired or was revoked (${error.message}). Run \`mcp-proxy login\` on this node again.`);
      }
      this.save({ ...this.stored, lastError: (error as Error).message });
      throw error;
    }
  }

  private fail(message: string): never {
    this.load();
    const { tokens: _, ...rest } = this.stored;
    this.save({ ...rest, lastError: message });
    console.error(`upstream login: ${message}`);
    throw new UpstreamOAuthError(message);
  }
}

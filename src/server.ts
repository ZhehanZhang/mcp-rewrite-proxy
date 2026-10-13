// Node entry point. Nodes share nothing at runtime: each serves HTTP from the shared config file
// and its own upstream login, keeps its own cloudflared connector up only while it can serve,
// and drains cleanly on SIGTERM.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { createApp } from './app';
import { ConfigFile } from './config-file';
import { Sealer } from './crypto';
import { type Env, loadSettings } from './env';
import { REFRESH_MARGIN_MS, UpstreamLogin } from './upstream-login';
import { Tunnel } from './tunnel';

const settings = loadSettings();
const sealer = new Sealer(settings.proxySecret, settings.proxySecretPrevious);
const config = new ConfigFile(settings.configPath);
const login = new UpstreamLogin(join(settings.dataDir, 'upstream-login.json'), settings);
const env: Env = { settings, sealer, config, login, oauth: { settings, sealer, policy: () => config.get() } };
const app = createApp(env);

const HEALTH_INTERVAL_MS = 5_000;
const DRAIN_TIMEOUT_MS = Number(process.env.DRAIN_TIMEOUT_MS ?? 30_000);

let draining = false;
/** Ready = this node can serve agents: it holds a working upstream login and isn't shutting down. */
const ready = () => !draining && login.isConnected();

// ---------------------------------------------------------------- HTTP adapter

function toRequest(req: IncomingMessage, signal: AbortSignal): Request {
  // Behind the tunnel the container only sees plain HTTP on an internal address. Every URL the app
  // builds (OAuth metadata, redirects, the resource identifier) must use the public origin instead.
  const url = new URL(req.url ?? '/', settings.publicUrl);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined || name.startsWith(':')) continue;
    for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
  }
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  return new Request(url, {
    method: req.method,
    headers,
    body: hasBody ? (Readable.toWeb(req) as ReadableStream) : undefined,
    signal,
    // @ts-expect-error Node's fetch requires duplex for streaming request bodies.
    duplex: hasBody ? 'half' : undefined,
  });
}

async function writeResponse(response: Response, res: ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => {
    if (name !== 'set-cookie') headers[name] = value;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers['set-cookie'] = cookies;
  res.writeHead(response.status, headers);
  if (!response.body) return void res.end();
  res.flushHeaders(); // start SSE streams immediately

  const reader = response.body.getReader();
  res.on('close', () => void reader.cancel().catch(() => {}));
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(value)) await new Promise((resolve) => res.once('drain', resolve));
    }
    res.end();
  } catch {
    res.destroy(); // client went away or the upstream stream failed
  }
}

const server = createServer(async (req, res) => {
  if (req.url === '/healthz') return void res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  if (req.url === '/readyz') return void res.writeHead(ready() ? 200 : 503, { 'content-type': 'text/plain' }).end(ready() ? 'ready' : 'not ready');

  const abort = new AbortController();
  res.on('close', () => abort.abort());
  try {
    const response = await app(toRequest(req, abort.signal));
    await writeResponse(response, res);
  } catch (error) {
    if (abort.signal.aborted) return;
    console.error(`${req.method} ${req.url?.split('?')[0]} failed:`, error);
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' }).end('Internal error');
    else res.destroy();
  }
});
server.keepAliveTimeout = 65_000; // longer than cloudflared's idle timeout, so it never reuses a closed socket
server.headersTimeout = 66_000;

// ---------------------------------------------------------------- lifecycle

const tunnel = settings.tunnelToken ? new Tunnel(settings.tunnelToken) : undefined;

let checking = false;

async function checkHealth(): Promise<void> {
  if (checking) return;
  checking = true;
  try {
    // Refresh ahead of expiry, so a revoked or expired login takes this node out of rotation
    // before an agent's request finds out the hard way.
    const status = login.status();
    if (status.connected && status.expiresAt && status.expiresAt - REFRESH_MARGIN_MS < Date.now()) {
      await login.accessToken().catch((error) => console.error('upstream refresh failed:', error.message));
    }
  } finally {
    checking = false;
  }
  // Only advertise this node to Cloudflare while it can actually serve requests.
  if (tunnel && !draining) {
    if (ready()) tunnel.start();
    else await tunnel.stop();
  }
}

config.watch();
login.watch();
if (!login.isConnected()) console.warn('upstream: this node is not signed in yet; run `mcp-proxy login` in this container');
await checkHealth();
const healthTimer = setInterval(checkHealth, HEALTH_INTERVAL_MS);

server.listen(settings.port, () => {
  console.log(`${settings.proxyName} listening on :${settings.port} as ${settings.publicUrl} → ${settings.upstreamUrl}${tunnel ? ' (with tunnel connector)' : ''}`);
});

async function shutdown(signal: string): Promise<void> {
  if (draining) return;
  draining = true;
  console.log(`${signal}: draining`);
  clearInterval(healthTimer);
  // 1. Leave the tunnel first: Cloudflare stops sending new requests here and routes them to the
  //    other nodes, while cloudflared lets requests already in flight finish.
  await tunnel?.stop();
  // 2. Stop accepting connections and wait for the remaining requests (long SSE streams included).
  server.close();
  server.closeIdleConnections();
  const forced = setTimeout(() => server.closeAllConnections(), DRAIN_TIMEOUT_MS);
  await new Promise((resolve) => server.once('close', resolve));
  clearTimeout(forced);
  config.stop();
  login.stop();
  console.log('stopped');
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

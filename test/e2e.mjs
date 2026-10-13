// Multi-node end-to-end test against docker-compose.test.yml: two proxy nodes that share only a
// config directory and PROXY_SECRET, a mock OAuth-protected upstream, and a stand-in cloudflared
// on node B. Every flow hops between nodes to prove nothing needs to be shared at runtime.
//   node test/e2e.mjs          (KEEP=1 leaves the cluster running afterwards)

import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const PUBLIC = 'http://localhost:8080'; // the origin the app believes it serves (the tunnel hostname)
const A = 'http://localhost:8081';
const B = 'http://localhost:8082';
const MOCK_INTERNAL = 'http://mock-upstream:8788';
const MOCK = 'http://localhost:8788';
const ADMIN_PASSWORD = 'dev-password-123';
const API_KEY = 'dev-api-key-0123456789abcdef';
const CONFIG_DIR = 'test/tmp/config';

const composeArgs = ['compose', '-f', 'docker-compose.test.yml'];
const compose = (...args) => execFileSync('docker', [...composeArgs, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const logs = (service) => compose('logs', '--no-log-prefix', service);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fingerprint = (clientId) => createHash('sha256').update(clientId).digest('hex').slice(0, 16);
/** Routes a URL as the app or mock wrote it to a host-reachable address on the chosen node. */
const via = (url, node) => url.replace(PUBLIC, node).replace(MOCK_INTERNAL, MOCK);
const step = (name) => console.log(`✓ ${name}`);
const ready = async (node) => (await fetch(`${node}/readyz`)).status === 200;

async function until(what, check, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      if (await check()) return;
    } catch {}
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
    await sleep(200);
  }
}

/** Replaces the shared config file the way a deploy would: write a temp file, then rename. */
function writeConfig(config) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(`${CONFIG_DIR}/.tmp`, typeof config === 'string' ? config : JSON.stringify(config, null, 2));
  renameSync(`${CONFIG_DIR}/.tmp`, `${CONFIG_DIR}/proxy.config.json`);
}

class Browser {
  jar = new Map(); // one browser: cookies are for the public host, whichever node answers
  async fetch(url, init = {}, node = A) {
    const headers = new Headers(init.headers);
    if (url.startsWith(PUBLIC) && this.jar.size) headers.set('cookie', [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '));
    const res = await fetch(via(url, node), { ...init, headers, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      if (/max-age=0/i.test(c) || pair.slice(i + 1) === '') this.jar.delete(pair.slice(0, i));
      else this.jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return res;
  }
  form(url, fields, node = A) {
    return this.fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: PUBLIC }, body: new URLSearchParams(fields) }, node);
  }
}

const rpc = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, params });
async function mcp(node, token, body) {
  const res = await fetch(`${node}/mcp`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body,
  });
  const text = await res.text();
  const payload = res.headers.get('content-type')?.includes('text/event-stream') ? text.split('\n').find((l) => l.startsWith('data: '))?.slice(6) : text;
  return { res, body: payload ? JSON.parse(payload) : null, raw: text };
}
const ping = (node, token, id) => mcp(node, token, rpc(id, 'tools/call', { name: 'ping', arguments: {} }));
const mockState = async () => (await fetch(`${MOCK}/__state`)).json();

/** Runs `mcp-proxy login` in a node like a person would: open the link, copy the code from the landing page (served by `landingNode`), paste it back. */
async function cliLogin(service, landingNode) {
  const child = spawn('docker', [...composeArgs, 'exec', '-T', service, 'mcp-proxy', 'login'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  const exited = new Promise((resolve) => child.on('exit', resolve));
  await until('the login link', () => /https?:\/\/\S+\/authorize\?\S+/.test(out), 20_000);
  const link = out.match(/https?:\/\/\S+\/authorize\?\S+/)[0];
  const res = await fetch(via(link, A), { redirect: 'manual' });
  const landing = res.headers.get('location');
  assert.ok(landing?.startsWith(`${PUBLIC}/upstream-callback?`), `upstream refused: ${await res.text()}`);
  const page = await (await fetch(via(landing, landingNode))).text();
  const code = page.match(/<textarea[^>]*>([^<]*)<\/textarea>/)[1].replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
  child.stdin.end(`${code}\n`);
  const status = await exited;
  assert.equal(status, 0, out);
  assert.match(out, /Signed in\./);
}

// ------------------------------------------------------------------ run

console.log('starting cluster (mock upstream, node-a, node-b)…');
writeConfig({});
compose('down', '-v', '--remove-orphans');
compose('up', '-d', '--build', '--wait');

try {
  // --- fresh nodes have no upstream login, so they stay out of rotation
  assert.equal(await ready(A), false);
  assert.equal(await ready(B), false);
  assert.doesNotMatch(logs('node-b'), /fake-cloudflared connected/);
  step('fresh nodes: not signed in upstream → not ready, no tunnel connector');

  await cliLogin('node-a', B);
  await until('node A ready', () => ready(A), 10_000);
  await cliLogin('node-b', A);
  await until('node B ready', () => ready(B), 10_000);
  await until('node B tunnel connector', () => /fake-cloudflared connected args=tunnel --no-autoupdate --grace-period 2s run/.test(logs('node-b')), 10_000);
  assert.equal((await mockState()).grants, 2, 'two independent upstream grants');
  step('`mcp-proxy login` on each node (landing page served by the other node) → two separate upstream logins; nodes join');

  // --- admin editor works across nodes
  const admin = new Browser();
  let res = await admin.form(`${PUBLIC}/admin/login`, { password: ADMIN_PASSWORD, next: '/admin' }, A);
  assert.equal(res.status, 302);
  const state = await (await admin.fetch(`${PUBLIC}/admin/api/state`, {}, B)).json();
  assert.equal(state.status.connected, true);
  assert.equal(state.snapshot.tools.length, 3);
  assert.equal(state.configPath, '/config/proxy.config.json');
  res = await admin.fetch(`${PUBLIC}/admin`, {}, A);
  assert.ok((await res.text()).includes('Download config'));
  step(`admin session from node A accepted by node B (${state.node}); tool list fetched with B's own login`);

  // --- agent OAuth, hopping nodes at every step; nothing is stored anywhere
  res = await fetch(`${A}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: rpc(1, 'ping') });
  assert.equal(res.status, 401);
  const prmUrl = res.headers.get('www-authenticate').match(/resource_metadata="([^"]+)"/)[1];
  const prm = await (await fetch(via(prmUrl, B))).json();
  assert.equal(prm.resource, `${PUBLIC}/mcp`);
  const asMeta = await (await fetch(via(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`, A))).json();
  const reg = await (await fetch(via(asMeta.registration_endpoint, B), {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Test Agent', redirect_uris: ['http://127.0.0.1:33418/callback'], token_endpoint_auth_method: 'none' }),
  })).json();
  assert.ok(reg.client_id);
  const verifier = b64url(randomBytes(32));
  const authUrl = new URL(asMeta.authorization_endpoint);
  Object.entries({
    response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://127.0.0.1:44555/callback', state: 'xyz', // loopback: any port
    code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256', resource: prm.resource,
  }).forEach(([k, v]) => authUrl.searchParams.set(k, v));
  res = await admin.fetch(authUrl.toString(), {}, A);
  assert.equal(res.status, 200, 'consent page');
  const page = await res.text();
  assert.ok(page.includes(fingerprint(reg.client_id)), 'consent page shows the fingerprint');
  const consent = page.match(/name="consent" value="([^"]+)"/)[1];
  assert.equal((await new Browser().form(`${PUBLIC}/authorize`, { consent, decision: 'approve' }, B)).status, 401, 'consent needs the admin');
  res = await admin.form(`${PUBLIC}/authorize`, { consent, decision: 'approve' }, B);
  assert.equal(res.status, 302, await res.text());
  const back = new URL(res.headers.get('location'));
  assert.equal(back.searchParams.get('state'), 'xyz');
  assert.equal(back.searchParams.get('iss'), PUBLIC);
  const tokenAt = (node, fields) => fetch(via(asMeta.token_endpoint, node), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: reg.client_id, ...fields }) });
  let tokens = await (await tokenAt(A, { grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: 'http://127.0.0.1:44555/callback', code_verifier: verifier, resource: prm.resource })).json();
  assert.ok(tokens.access_token && tokens.refresh_token, JSON.stringify(tokens));
  const replay = await tokenAt(A, { grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: 'http://127.0.0.1:44555/callback', code_verifier: verifier });
  assert.equal(replay.status, 400, 'code replay refused');
  tokens = await (await tokenAt(B, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).json();
  const token = tokens.access_token;
  assert.ok((await ping(A, token, 2)).body.result, 'token refreshed on B works on A');
  step('agent OAuth: metadata on A/B, register on B, consent on A, approve on B, code on A, refresh on B, call on A');

  // --- config file: deploy an edit, both nodes pick it up
  let r = await mcp(B, token, rpc(3, 'tools/list', {}));
  assert.deepEqual(r.body.result.tools.map((t) => t.name), ['search', 'delete_doc', 'ping']);
  const config = {
    server: { instructions: 'Use find_docs. {{original}}' },
    tools: {
      overrides: {
        search: { name: 'find_docs', description: 'Find team documents. {{original}}', params: { q: { name: 'query' }, workspace: { value: 'team-a' }, limit: { default: 5 } } },
        delete_doc: { hidden: true },
      },
    },
    agents: { revoked: [] },
  };
  const deployedAt = Date.now();
  writeConfig(config);
  for (const node of [A, B]) {
    await until(`node ${node} to load the config`, async () => (await mcp(node, token, rpc(4, 'tools/list', {}))).body.result.tools[0].name === 'find_docs', 10_000);
  }
  step(`config file replaced → both nodes reloaded it in ${((Date.now() - deployedAt) / 1000).toFixed(1)} s`);

  r = await mcp(A, token, rpc(5, 'tools/list', {}));
  assert.deepEqual(r.body.result.tools.map((t) => t.name), ['find_docs', 'ping']);
  assert.ok(r.raw.startsWith(': hello'), 'SSE framing preserved');
  await mcp(B, token, rpc(6, 'tools/call', { name: 'find_docs', arguments: { query: 'roadmap', workspace: 'evil' } }));
  assert.deepEqual((await mockState()).lastCall, { name: 'search', arguments: { q: 'roadmap', workspace: 'team-a', limit: 5 } });
  await fetch(`${MOCK}/__reset`);
  r = await mcp(A, token, rpc(7, 'tools/call', { name: 'delete_doc', arguments: { id: '1' } }));
  assert.equal(r.body.error.code, -32602);
  assert.equal((await mockState()).lastCall, null);
  step('rewritten tools/list (SSE) and tools/call on both nodes; hidden tool refused locally');

  writeConfig('{ "tools": { "overrides": { "a": { "name": "x" }, "b": { "name": "x" } } } }');
  await until('node A to report the bad file', async () => (await (await admin.fetch(`${PUBLIC}/admin/api/state`, {}, A)).json()).configError?.includes('both exposed as "x"'), 10_000);
  r = await mcp(A, token, rpc(8, 'tools/list', {}));
  assert.equal(r.body.result.tools[0].name, 'find_docs', 'previous config kept');
  step('broken config file rejected: nodes keep serving the last good one and the admin page says why');

  // --- revoke the agent in the config file, then restore it
  writeConfig({ ...config, agents: { revoked: [fingerprint(reg.client_id)] } });
  await until('revocation on both nodes', async () => (await ping(A, token, 9)).res.status === 401 && (await ping(B, token, 10)).res.status === 401, 10_000);
  assert.equal((await tokenAt(A, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status, 400);
  writeConfig(config);
  await until('un-revoked', async () => !!(await ping(B, token, 11)).body?.result, 10_000);
  step('agent revoked by fingerprint in the config file → refused on both nodes (tokens and refresh); restored likewise');

  // --- upstream access tokens expire: each node refreshes its own login, once
  await fetch(`${MOCK}/__expire`);
  const calls = await Promise.all([A, B, A, B, A].map((node, i) => ping(node, token, 20 + i)));
  for (const call of calls) assert.ok(call.body.result, JSON.stringify(call.body));
  assert.deepEqual((await mockState()).refreshByGrant, { 1: 1, 2: 1 });
  step('upstream tokens expired → each node refreshed its own grant exactly once; all concurrent calls succeeded');

  // --- the upstream revokes node B's login: B leaves rotation, A keeps serving
  await fetch(`${MOCK}/__revoke?grant=2`);
  r = await ping(B, token, 30);
  assert.equal(r.res.status, 503);
  await until('node B out of rotation', async () => !(await ready(B)) && /fake-cloudflared draining/.test(logs('node-b')), 15_000);
  assert.ok((await ping(A, token, 31)).body.result);
  step('upstream revoked node B’s login → B answers 503, drops out of /readyz and disconnects its connector; A unaffected');

  await cliLogin('node-b', A);
  await until('node B back', async () => (await ready(B)) && (logs('node-b').match(/fake-cloudflared connected/g) ?? []).length >= 2, 15_000);
  assert.ok((await ping(B, token, 32)).body.result);
  step('`mcp-proxy login` on node B again → back in rotation');

  assert.ok((await ping(A, API_KEY, 33)).body.result);
  step('static API key works');

  // --- graceful shutdown of node B while node A keeps serving
  const stopStarted = Date.now();
  compose('stop', 'node-b');
  const stopSeconds = (Date.now() - stopStarted) / 1000;
  const bLogs = logs('node-b');
  const order = ['SIGTERM: draining', 'tunnel: disconnecting', 'fake-cloudflared draining', 'stopped'].map((line) => bLogs.lastIndexOf(line));
  assert.ok(order.every((i, n) => i >= 0 && (n === 0 || i > order[n - 1])), `shutdown order wrong:\n${bLogs.slice(-1500)}`);
  assert.ok((await ping(A, token, 34)).body.result);
  step(`node B drained in ${stopSeconds.toFixed(1)} s: tunnel connector first, then HTTP, then exit; node A unaffected`);

  console.log('\nAll multi-node checks passed.');
} catch (error) {
  console.error('\nFAILED:', error);
  for (const service of ['node-a', 'node-b']) console.error(`\n--- ${service} logs ---\n${logs(service).slice(-3000)}`);
  process.exitCode = 1;
} finally {
  if (!process.env.KEEP) compose('down', '-v', '--remove-orphans');
}

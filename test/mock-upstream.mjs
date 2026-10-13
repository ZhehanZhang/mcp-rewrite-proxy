// A mock MCP server protected by OAuth 2.1 (protected resource metadata, AS metadata, DCR, PKCE,
// rotating refresh tokens). Used by e2e.mjs; run it directly for a manual demo:
//   node test/mock-upstream.mjs

import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

export const UP = process.env.MOCK_BASE ?? 'http://localhost:8788';

export const up = { clients: new Map(), codes: new Map(), access: new Map(), refresh: new Map(), grants: 0, refreshCount: 0, refreshByGrant: {}, lastCall: null, n: 0 };
const TOOLS = [
  {
    name: 'search',
    description: 'Search documents.',
    annotations: { readOnlyHint: true },
    inputSchema: {
      type: 'object',
      properties: { q: { type: 'string', description: 'Query' }, workspace: { type: 'string' }, limit: { type: 'integer' } },
      required: ['q', 'workspace'],
    },
  },
  { name: 'delete_doc', description: 'Delete a document.', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
  { name: 'ping', description: 'Ping.', inputSchema: { type: 'object' } },
];
export const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const readBody = (req) => new Promise((resolve) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => resolve(d)); });
const json = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(body)); };

// Each authorization is a grant; refresh tokens rotate within it (single use), like most providers.
function issueTokens(grant) {
  const access = `at-${++up.n}`;
  const refresh = `rt-${up.n}`;
  up.access.set(access, grant);
  up.refresh.set(refresh, grant);
  return { access_token: access, token_type: 'bearer', refresh_token: refresh, expires_in: 3600, scope: 'docs:read' };
}

export const upstream = createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (error) {
    // A failed check answers 400 with the reason instead of crashing the mock.
    if (!res.headersSent) json(res, 400, { error: 'mock_check_failed', error_description: error.message });
  }
});

async function handle(req, res) {
  const url = new URL(req.url, UP);
  const body = await readBody(req);
  if (url.pathname === '/__state') return json(res, 200, { grants: up.grants, refreshCount: up.refreshCount, refreshByGrant: up.refreshByGrant, lastCall: up.lastCall });
  if (url.pathname === '/__revoke') {
    // The user revokes one grant at the provider: its tokens stop working.
    const grant = Number(url.searchParams.get('grant'));
    for (const map of [up.access, up.refresh]) for (const [token, g] of map) if (g === grant) map.delete(token);
    return json(res, 200, {});
  }
  if (url.pathname === '/__reset') {
    up.lastCall = null;
    return json(res, 200, {});
  }
  if (url.pathname === '/.well-known/oauth-protected-resource/mcp') {
    return json(res, 200, { resource: `${UP}/mcp`, authorization_servers: [UP], scopes_supported: ['docs:read'] });
  }
  if (url.pathname === '/.well-known/oauth-authorization-server') {
    return json(res, 200, {
      issuer: UP,
      authorization_endpoint: `${UP}/authorize`,
      token_endpoint: `${UP}/token`,
      registration_endpoint: `${UP}/register`,
      scopes_supported: ['docs:read', 'offline_access'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      authorization_response_iss_parameter_supported: true,
    });
  }
  if (url.pathname === '/register' && req.method === 'POST') {
    const meta = JSON.parse(body);
    const client_id = `client-${up.clients.size + 1}`;
    up.clients.set(client_id, meta);
    return json(res, 201, { client_id, ...meta });
  }
  if (url.pathname === '/authorize') {
    const p = url.searchParams;
    const client = up.clients.get(p.get('client_id'));
    assert.ok(client, 'upstream: unknown client');
    assert.ok(client.redirect_uris.includes(p.get('redirect_uri')), 'upstream: redirect_uri not registered');
    assert.equal(p.get('code_challenge_method'), 'S256');
    assert.equal(p.get('resource'), `${UP}/mcp`, 'upstream: RFC 8707 resource missing');
    assert.deepEqual(p.get('scope').split(' ').sort(), ['docs:read', 'offline_access']);
    const code = b64url(randomBytes(12));
    up.codes.set(code, { challenge: p.get('code_challenge'), redirect: p.get('redirect_uri'), client: p.get('client_id') });
    const back = new URL(p.get('redirect_uri'));
    back.searchParams.set('code', code);
    back.searchParams.set('state', p.get('state'));
    back.searchParams.set('iss', UP);
    res.writeHead(302, { location: back.toString() });
    return res.end();
  }
  if (url.pathname === '/token' && req.method === 'POST') {
    const p = new URLSearchParams(body);
    if (p.get('grant_type') === 'authorization_code') {
      const code = up.codes.get(p.get('code'));
      up.codes.delete(p.get('code'));
      if (!code || code.redirect !== p.get('redirect_uri') || code.client !== p.get('client_id')) return json(res, 400, { error: 'invalid_grant' });
      if (b64url(createHash('sha256').update(p.get('code_verifier')).digest()) !== code.challenge) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE' });
      return json(res, 200, issueTokens(++up.grants));
    }
    if (p.get('grant_type') === 'refresh_token') {
      const grant = up.refresh.get(p.get('refresh_token'));
      if (grant === undefined) return json(res, 400, { error: 'invalid_grant' });
      up.refresh.delete(p.get('refresh_token')); // rotation: single use
      up.refreshCount++;
      up.refreshByGrant[grant] = (up.refreshByGrant[grant] ?? 0) + 1;
      return json(res, 200, issueTokens(grant));
    }
    return json(res, 400, { error: 'unsupported_grant_type' });
  }
  if (url.pathname === '/__expire') {
    up.access.clear(); // every access token expires; refresh tokens still work
    return json(res, 200, {});
  }
  if (url.pathname === '/mcp') {
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    if (!up.access.has(token)) {
      res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${UP}/.well-known/oauth-protected-resource/mcp", scope="docs:read"` });
      return res.end();
    }
    if (req.method === 'DELETE') { res.writeHead(200); return res.end(); }
    const msg = JSON.parse(body);
    if (!('id' in msg)) { res.writeHead(202); return res.end(); }
    if (msg.method === 'initialize') {
      return json(res, 200, {
        jsonrpc: '2.0', id: msg.id,
        result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'mock-upstream', version: '1.0.0' }, instructions: 'Upstream instructions.' },
      }, { 'mcp-session-id': 'sess-1' });
    }
    if (msg.method === 'tools/list') {
      // SSE response, to exercise the stream rewriter.
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(': hello\n\n');
      res.write(`id: 1\nevent: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } })}\n\n`);
      return res.end();
    }
    if (msg.method === 'tools/call') {
      up.lastCall = msg.params;
      return json(res, 200, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: JSON.stringify(msg.params) }] } });
    }
    return json(res, 200, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'not found' } });
  }
  res.writeHead(404);
  res.end();
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  upstream.listen(8788, '0.0.0.0', () => console.log(`mock upstream MCP server on ${UP}/mcp`));
}

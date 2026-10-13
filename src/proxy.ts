// Forwards an agent's MCP request (Streamable HTTP) to the upstream with the proxy's own
// upstream token, rewriting tool calls on the way up and tool lists on the way down.

import type { Env } from './env';
import { rewriteEventStream, rewriteRequest, rewriteResponse } from './messages';
import type { Json } from './rewrite';

export interface Snapshot {
  fetchedAt: number;
  tools: Json[];
  serverInfo?: Json;
  instructions?: string;
  protocolVersion?: string;
}

const DROP_REQUEST_HEADERS = new Set([
  'host',
  'authorization',
  'cookie',
  'content-length',
  'accept-encoding',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'x-real-ip',
  'true-client-ip',
]);
const DROP_RESPONSE_HEADERS = new Set(['content-length', 'content-encoding', 'transfer-encoding', 'connection', 'set-cookie', 'www-authenticate']);

/** The node's upstream token, or why there isn't one. */
async function upstreamToken(env: Env, rejected?: string): Promise<{ token?: string; error?: string }> {
  try {
    return { token: (await env.login.accessToken(rejected)).token };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

function jsonRpcErrorResponse(status: number, message: string): Response {
  return Response.json({ jsonrpc: '2.0', id: null, error: { code: -32603, message } }, { status });
}

export async function proxyMcp(request: Request, env: Env): Promise<Response> {
  let upstream = await upstreamToken(env);
  if (!upstream.token) return jsonRpcErrorResponse(503, `Upstream unavailable: ${upstream.error}`);
  const rewriter = env.config.get().rewriter; // validated when the file was loaded

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!DROP_REQUEST_HEADERS.has(name) && !name.startsWith('cf-')) headers.set(name, value);
  }

  let body: string | undefined;
  if (request.method === 'POST') {
    const text = await request.text();
    body = text;
    if ((request.headers.get('content-type') ?? '').includes('application/json')) {
      let parsed: Json;
      try {
        parsed = JSON.parse(text);
      } catch {
        return Response.json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, { status: 400 });
      }
      const rewritten = rewriteRequest(parsed, rewriter);
      if (rewritten.body === null) {
        // Every message was refused (e.g. a call to a hidden tool): answer locally.
        return Response.json(Array.isArray(parsed) ? rewritten.errors : rewritten.errors[0]);
      }
      if (rewritten.errors.length && Array.isArray(parsed)) {
        // A batch mixing allowed and refused calls (batching left the spec in 2025-06-18): refuse it whole.
        const message = rewritten.errors.map((e) => (e.error as { message: string }).message).join('; ');
        return Response.json(
          parsed
            .filter((m) => typeof m === 'object' && m !== null && !Array.isArray(m) && 'id' in m)
            .map((m) => ({ jsonrpc: '2.0', id: (m as { id: Json }).id, error: { code: -32602, message } })),
        );
      }
      body = JSON.stringify(rewritten.body);
      // Newer protocol versions mirror the tool name in a header; keep it consistent with the body.
      if (rewritten.toolName && headers.has('mcp-name')) headers.set('mcp-name', rewritten.toolName);
    }
  }

  const send = (token: string) => {
    headers.set('authorization', `Bearer ${token}`);
    // request.signal aborts when the agent disconnects, which also closes the upstream stream.
    return fetch(env.settings.upstreamUrl + new URL(request.url).search, { method: request.method, headers, body, signal: request.signal });
  };

  let response = await send(upstream.token);
  if (response.status === 401) {
    await response.body?.cancel();
    upstream = await upstreamToken(env, upstream.token);
    if (!upstream.token) return jsonRpcErrorResponse(503, `Upstream unavailable: ${upstream.error}`);
    response = await send(upstream.token);
    if (response.status === 401) {
      await response.body?.cancel();
      return jsonRpcErrorResponse(503, 'The upstream rejected this node’s login. Run `mcp-proxy login` on it.');
    }
  }

  const outHeaders = new Headers();
  for (const [name, value] of response.headers) {
    if (!DROP_RESPONSE_HEADERS.has(name)) outHeaders.set(name, value);
  }
  const contentType = response.headers.get('content-type') ?? '';

  if (response.body && contentType.includes('text/event-stream')) {
    return new Response(rewriteEventStream(response.body, rewriter), { status: response.status, headers: outHeaders });
  }
  if (response.body && contentType.includes('application/json')) {
    const text = await response.text();
    let out = text;
    try {
      out = JSON.stringify(rewriteResponse(JSON.parse(text), rewriter));
    } catch {
      // Not JSON after all: forward unchanged.
    }
    return new Response(out, { status: response.status, headers: outHeaders });
  }
  return new Response(response.body, { status: response.status, headers: outHeaders });
}

/** Reads one JSON-RPC response with the given id from a JSON or SSE body. */
async function readResult(response: Response, id: number): Promise<Record<string, Json>> {
  const text = await response.text();
  const messages: Json[] = [];
  if ((response.headers.get('content-type') ?? '').includes('text/event-stream')) {
    for (const event of text.split(/\r?\n\r?\n/)) {
      const data = event
        .split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n');
      if (data) messages.push(JSON.parse(data));
    }
  } else if (text) {
    const parsed = JSON.parse(text);
    messages.push(...(Array.isArray(parsed) ? parsed : [parsed]));
  }
  const match = messages.find((m) => typeof m === 'object' && m !== null && !Array.isArray(m) && m.id === id) as Record<string, Json> | undefined;
  if (!match) throw new Error(`No response to request ${id} (HTTP ${response.status}): ${text.slice(0, 200)}`);
  if (match.error) throw new Error(`Upstream error: ${JSON.stringify(match.error)}`);
  return match.result as Record<string, Json>;
}

/** Fetches the upstream's unmodified server info and full tool list, for the admin editor. */
let snapshot: Snapshot | undefined;

/** The last tool list fetched on this node, if any. */
export function cachedSnapshot(): Snapshot | undefined {
  return snapshot;
}

export async function fetchSnapshot(env: Env): Promise<Snapshot> {
  let token = (await env.login.accessToken()).token;
  let sessionId: string | null = null;
  let protocolVersion = '2025-06-18';
  let id = 0;

  const call = async (method: string, params?: Json, notification = false) => {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': protocolVersion,
    };
    if (sessionId) headers['mcp-session-id'] = sessionId;
    const message: Record<string, Json> = { jsonrpc: '2.0', method };
    if (params !== undefined) message.params = params;
    if (!notification) message.id = ++id;
    const send = () => fetch(env.settings.upstreamUrl, { method: 'POST', headers: { ...headers, authorization: `Bearer ${token}` }, body: JSON.stringify(message) });
    let response = await send();
    if (response.status === 401) {
      await response.body?.cancel();
      token = (await env.login.accessToken(token)).token;
      response = await send();
    }
    sessionId = response.headers.get('mcp-session-id') ?? sessionId;
    if (notification) {
      await response.body?.cancel();
      return {};
    }
    return readResult(response, id);
  };

  const init = await call('initialize', {
    protocolVersion,
    capabilities: {},
    clientInfo: { name: 'mcp-rewrite-proxy', version: '1.0.0' },
  });
  if (typeof init.protocolVersion === 'string') protocolVersion = init.protocolVersion;
  await call('notifications/initialized', undefined, true);

  const tools: Json[] = [];
  let cursor: Json | undefined;
  for (let page = 0; page < 50; page++) {
    const result = await call('tools/list', cursor ? { cursor } : {});
    if (Array.isArray(result.tools)) tools.push(...result.tools);
    cursor = result.nextCursor;
    if (!cursor) break;
  }

  if (sessionId) {
    await fetch(env.settings.upstreamUrl, { method: 'DELETE', headers: { authorization: `Bearer ${token}`, 'mcp-session-id': sessionId } }).catch(() => {});
  }
  snapshot = {
    fetchedAt: Date.now(),
    tools,
    serverInfo: init.serverInfo,
    instructions: typeof init.instructions === 'string' ? init.instructions : undefined,
    protocolVersion,
  };
  return snapshot;
}

// JSON-RPC message rewriting in both directions, for plain JSON bodies and SSE streams.

import type { Json, Rewriter } from './rewrite';

type Message = { [key: string]: Json };

function isObject(value: unknown): value is Message {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface RequestRewrite {
  /** Body to forward upstream, or null when every message was refused locally. */
  body: Json | null;
  /** Error responses for refused messages, answered by the proxy. */
  errors: Message[];
  /** Upstream tool name when the body is a single tools/call (for the Mcp-Name header). */
  toolName?: string;
}

/** Maps agent → upstream: tool and parameter names in tools/call. */
export function rewriteRequest(body: Json, rewriter: Rewriter): RequestRewrite {
  const messages = Array.isArray(body) ? body : [body];
  const forward: Json[] = [];
  const errors: Message[] = [];
  let toolName: string | undefined;
  for (const message of messages) {
    if (!isObject(message) || message.method !== 'tools/call' || !isObject(message.params)) {
      forward.push(message);
      continue;
    }
    const params = message.params;
    const mapped = typeof params.name === 'string' ? rewriter.mapCall(params.name, params.arguments) : null;
    if (!mapped) {
      errors.push({
        jsonrpc: '2.0',
        id: message.id ?? null,
        error: { code: -32602, message: `Unknown tool: ${String(params.name)}` },
      });
      continue;
    }
    toolName = mapped.name;
    forward.push({ ...message, params: { ...params, name: mapped.name, arguments: mapped.arguments } });
  }
  const body2 = forward.length === 0 ? null : Array.isArray(body) ? forward : forward[0];
  return { body: body2, errors, toolName: messages.length === 1 ? toolName : undefined };
}

/** Maps upstream → agent: tools/list results and the initialize result. */
export function rewriteResponse(body: Json, rewriter: Rewriter): Json {
  if (Array.isArray(body)) return body.map((message) => rewriteMessage(message, rewriter));
  return rewriteMessage(body, rewriter);
}

function rewriteMessage(message: Json, rewriter: Rewriter): Json {
  if (!isObject(message) || !isObject(message.result)) return message;
  const result = message.result;
  // Recognized by shape rather than request id, so replayed SSE events (Last-Event-ID) are covered too.
  if (Array.isArray(result.tools) && result.tools.every((t) => isObject(t) && 'inputSchema' in t)) {
    return { ...message, result: { ...result, tools: rewriter.rewriteTools(result.tools) } };
  }
  if (typeof result.protocolVersion === 'string' && isObject(result.serverInfo)) {
    return { ...message, result: rewriter.rewriteInitialize(result) };
  }
  return message;
}

/**
 * Rewrites each `data:` payload of a text/event-stream as it flows through.
 * Comments, ids, event names and retry fields pass through unchanged.
 */
export function rewriteEventStream(stream: ReadableStream<Uint8Array>, rewriter: Rewriter): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = '';

  const flushEvent = (block: string): string => {
    const lines = block.split(/\r\n|\r|\n/);
    const data: string[] = [];
    const other: string[] = [];
    for (const line of lines) {
      if (line.startsWith('data:')) data.push(line.slice(line.startsWith('data: ') ? 6 : 5));
      else other.push(line);
    }
    if (data.length === 0) return block + '\n\n';
    let payload = data.join('\n');
    try {
      payload = JSON.stringify(rewriteResponse(JSON.parse(payload), rewriter));
    } catch {
      // Not JSON: forward as-is.
    }
    const dataLines = payload.split('\n').map((line) => `data: ${line}`);
    return [...other.filter((line) => line !== ''), ...dataLines].join('\n') + '\n\n';
  };

  return stream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        buffer += decoder.decode(chunk, { stream: true });
        // Events end with a blank line.
        let match: RegExpExecArray | null;
        const boundary = /\r\n\r\n|\n\n|\r\r/g;
        let start = 0;
        let out = '';
        while ((match = boundary.exec(buffer))) {
          out += flushEvent(buffer.slice(start, match.index));
          start = match.index + match[0].length;
        }
        buffer = buffer.slice(start);
        if (out) controller.enqueue(encoder.encode(out));
      },
      flush(controller) {
        buffer += decoder.decode();
        if (buffer.trim()) controller.enqueue(encoder.encode(flushEvent(buffer)));
      },
    }),
  );
}

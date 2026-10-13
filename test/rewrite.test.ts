import { describe, expect, it } from 'vitest';
import { rewriteEventStream, rewriteRequest, rewriteResponse } from '../src/messages';
import { ConfigError, type ProxyConfig, Rewriter, mergePatch } from '../src/rewrite';

const searchTool = {
  name: 'search',
  title: 'Search',
  description: 'Search documents.',
  annotations: { readOnlyHint: true, openWorldHint: true },
  inputSchema: {
    type: 'object',
    properties: {
      q: { type: 'string', description: 'Query' },
      limit: { type: 'integer', description: 'Max results' },
      workspace: { type: 'string' },
      debug: { type: 'boolean' },
    },
    required: ['q', 'workspace'],
  },
  outputSchema: { type: 'object', properties: { hits: { type: 'array' } } },
};
const deleteTool = { name: 'delete_doc', description: 'Delete', inputSchema: { type: 'object', properties: { id: { type: 'string' } } } };
const otherTool = { name: 'ping', inputSchema: { type: 'object' } };

const config: ProxyConfig = {
  server: { instructions: 'Proxy. {{original}}', serverInfo: { name: 'renamed-server', version: null } },
  tools: {
    overrides: {
      search: {
        name: 'find_docs',
        title: null,
        description: 'Find documents. {{original}}',
        annotations: { openWorldHint: false, destructiveHint: false },
        params: {
          q: { name: 'query', description: 'What to look for ({{original}})' },
          limit: { default: 5, schema: { maximum: 20 } },
          workspace: { value: 'team-a' },
          debug: { hidden: true },
        },
        inputSchema: { additionalProperties: false },
        outputSchema: null,
        patch: { _meta: { 'example.com/tag': 'x' } },
      },
      delete_doc: { hidden: true },
    },
  },
};

describe('mergePatch', () => {
  it('follows RFC 7396', () => {
    expect(mergePatch({ a: 1, b: { c: 2, d: 3 } }, { a: null, b: { c: 9 }, e: [1] })).toEqual({ b: { c: 9, d: 3 }, e: [1] });
    expect(mergePatch({ a: 1 }, [1, 2])).toEqual([1, 2]);
  });
});

describe('Rewriter.rewriteTools', () => {
  const rewriter = new Rewriter(config);
  const [find, ping, ...rest] = rewriter.rewriteTools([searchTool, deleteTool, otherTool]) as any[];

  it('hides tools and passes through unlisted ones', () => {
    expect(rest).toHaveLength(0);
    expect(ping).toEqual(otherTool);
  });

  it('rewrites every tool-level field', () => {
    expect(find.name).toBe('find_docs');
    expect(find).not.toHaveProperty('title');
    expect(find.description).toBe('Find documents. Search documents.');
    expect(find.annotations).toEqual({ readOnlyHint: true, openWorldHint: false, destructiveHint: false });
    expect(find).not.toHaveProperty('outputSchema');
    expect(find._meta).toEqual({ 'example.com/tag': 'x' });
  });

  it('rewrites parameters', () => {
    expect(find.inputSchema).toEqual({
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'What to look for (Query)' },
        limit: { type: 'integer', description: 'Max results', default: 5, maximum: 20 },
      },
      required: ['query'],
    });
  });

  it('does not mutate the upstream definition', () => {
    expect(searchTool.inputSchema.properties.q.description).toBe('Query');
  });
});

describe('Rewriter.mapCall', () => {
  const rewriter = new Rewriter(config);

  it('maps names back, injects fixed and default values, drops hidden params', () => {
    expect(rewriter.mapCall('find_docs', { query: 'cats', debug: true, workspace: 'evil' })).toEqual({
      name: 'search',
      arguments: { q: 'cats', workspace: 'team-a', limit: 5 },
    });
    expect(rewriter.mapCall('find_docs', { query: 'x', limit: 9 })?.arguments.limit).toBe(9);
  });

  it('refuses hidden tools and the old name of renamed tools', () => {
    expect(rewriter.mapCall('delete_doc', { id: '1' })).toBeNull();
    expect(rewriter.mapCall('search', { q: 'x' })).toBeNull();
    expect(rewriter.mapCall('ping', {})).toEqual({ name: 'ping', arguments: {} });
  });

  it('respects allowlist mode', () => {
    const allow = new Rewriter({ tools: { hideUnlisted: true, overrides: { ping: { hidden: false } } } });
    expect(allow.rewriteTools([searchTool, otherTool]).map((t: any) => t.name)).toEqual(['ping']);
    expect(allow.mapCall('search', {})).toBeNull();
  });
});

describe('validateConfig', () => {
  it('rejects name collisions', () => {
    expect(() => new Rewriter({ tools: { overrides: { a: { name: 'x' }, b: { name: 'x' } } } })).toThrow(ConfigError);
    expect(() => new Rewriter({ tools: { overrides: { a: { params: { p: { name: 'q' }, q: {} } } } } })).toThrow(ConfigError);
  });
});

describe('JSON-RPC messages', () => {
  const rewriter = new Rewriter(config);

  it('rewrites tools/call requests and refuses hidden tools', () => {
    const ok = rewriteRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'find_docs', arguments: { query: 'a' } } }, rewriter);
    expect(ok.body).toEqual({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search', arguments: { q: 'a', workspace: 'team-a', limit: 5 } } });
    expect(ok.toolName).toBe('search');

    const refused = rewriteRequest({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'delete_doc', arguments: {} } }, rewriter);
    expect(refused.body).toBeNull();
    expect(refused.errors[0]).toMatchObject({ id: 2, error: { code: -32602 } });
  });

  it('rewrites initialize and tools/list results', () => {
    const init = rewriteResponse(
      { jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'up', version: '1' }, instructions: 'Hi.' } },
      rewriter,
    ) as any;
    expect(init.result.instructions).toBe('Proxy. Hi.');
    expect(init.result.serverInfo).toEqual({ name: 'renamed-server' });

    const list = rewriteResponse({ jsonrpc: '2.0', id: 2, result: { tools: [searchTool, deleteTool] } }, rewriter) as any;
    expect(list.result.tools.map((t: any) => t.name)).toEqual(['find_docs']);
  });

  it('rewrites SSE streams split across arbitrary chunks', async () => {
    const message = JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: [searchTool, deleteTool] } });
    const raw = `: keepalive\n\nid: 7\nevent: message\ndata: ${message}\n\n`;
    const bytes = new TextEncoder().encode(raw);
    const input = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < bytes.length; i += 13) controller.enqueue(bytes.slice(i, i + 13));
        controller.close();
      },
    });
    const text = await new Response(rewriteEventStream(input, rewriter)).text();
    expect(text).toContain(': keepalive\n\n');
    expect(text).toContain('id: 7\nevent: message\ndata: ');
    const data = JSON.parse(text.split('data: ')[1]);
    expect(data.result.tools.map((t: any) => t.name)).toEqual(['find_docs']);
  });
});

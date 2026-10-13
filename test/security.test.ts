// Regressions for issues found in review: the tool rules must hold whatever Content-Type an agent
// claims, and the post-login redirect must stay on this origin.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { sameOriginPath } from '../src/auth';
import type { Env } from '../src/env';
import { proxyMcp } from '../src/proxy';
import { Rewriter } from '../src/rewrite';

const rewriter = new Rewriter({ tools: { overrides: { delete_doc: { hidden: true }, search: { params: { workspace: { value: 'team-a' } } } } } });
const env = {
  settings: { upstreamUrl: 'https://upstream.example/mcp' },
  login: { accessToken: async () => ({ token: 'upstream-token' }) },
  config: { get: () => ({ rewriter }) },
} as unknown as Env;

function post(body: string, contentType?: string) {
  const headers: Record<string, string> = { accept: 'application/json, text/event-stream' };
  if (contentType) headers['content-type'] = contentType;
  return new Request('https://proxy.example/mcp', { method: 'POST', headers, body });
}

describe('tool rules cannot be bypassed through Content-Type', () => {
  afterEach(() => vi.unstubAllGlobals());
  const hiddenCall = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'delete_doc', arguments: { id: '1' } } });

  for (const contentType of ['APPLICATION/JSON', 'text/plain', 'application/json-patch', undefined]) {
    it(`refuses a hidden tool sent as ${contentType ?? 'no content type'}`, async () => {
      const upstream = vi.fn();
      vi.stubGlobal('fetch', upstream);
      const res = await proxyMcp(post(hiddenCall, contentType), env);
      expect(((await res.json()) as { error: { code: number } }).error.code).toBe(-32602);
      expect(upstream).not.toHaveBeenCalled();
    });
  }

  it('enforces fixed values and forwards canonical JSON, whatever the declared type', async () => {
    const upstream = vi.fn(async (_url: string, _init: RequestInit) => Response.json({ jsonrpc: "2.0", id: 2, result: {} }));
    vi.stubGlobal('fetch', upstream);
    await proxyMcp(post(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'search', arguments: { workspace: 'evil' } } }), 'Text/Plain'), env);
    const init = upstream.mock.calls[0][1];
    expect(JSON.parse(init.body as string).params.arguments).toEqual({ workspace: 'team-a' });
    expect(new Headers(init.headers).get('content-type')).toBe('application/json');
  });

  it('rejects a body it cannot parse instead of forwarding it', async () => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    const res = await proxyMcp(post('{"jsonrpc":"2.0", nope', 'text/plain'), env);
    expect(res.status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe('post-login redirect', () => {
  const origin = 'https://proxy.example';
  it('keeps same-origin paths', () => {
    expect(sameOriginPath('/authorize?client_id=x&state=y', origin)).toBe('/authorize?client_id=x&state=y');
    expect(sameOriginPath('/admin', origin)).toBe('/admin');
  });
  it('refuses anything that leaves the origin', () => {
    for (const next of ['//evil.example', '/\\evil.example', '\\\\evil.example', 'https://evil.example/', '/\t/evil.example', 'javascript:alert(1)', 'https://proxy.example.evil.example/']) {
      expect(sameOriginPath(next, origin)).toBe('/admin');
    }
  });
});

import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config-file';
import { Sealer, fingerprint } from '../src/crypto';
import type { Settings } from '../src/env';
import { AuthorizeError, type OAuthContext, approve, openConsent, parseAuthorize, register, sealConsent, token, verifyBearer } from '../src/oauth-server';

const SECRET = 'test-secret-test-secret-test-secret-0123';
const settings = { publicUrl: 'https://proxy.example', proxyName: 'Test', apiKeys: [] } as unknown as Settings;
const context = (secret = SECRET, previous: string[] = [], config = '{}'): OAuthContext => {
  const policy = parseConfig(config);
  return { settings, sealer: new Sealer(secret, previous), policy: () => policy };
};
const b64url = (buf: Buffer) => buf.toString('base64url');

describe('Sealer', () => {
  const sealer = new Sealer(SECRET);

  it('round-trips and binds the purpose', () => {
    const sealed = sealer.seal('access', { a: 1 });
    expect(sealer.open('access', sealed)).toEqual({ a: 1 });
    expect(sealer.open('refresh', sealed)).toBeNull(); // an access token is not a refresh token
  });

  it('rejects tampering and other secrets', () => {
    const sealed = sealer.seal('code', { a: 1 });
    const bytes = Buffer.from(sealed.slice(3), 'base64url');
    bytes[20] ^= 1;
    expect(sealer.open('code', `v1.${bytes.toString('base64url')}`)).toBeNull();
    expect(new Sealer('another-secret-another-secret-012345').open('code', sealed)).toBeNull();
    expect(sealer.open('code', 'garbage')).toBeNull();
  });

  it('opens values sealed under a previous secret during rotation', () => {
    const old = new Sealer('old-secret-old-secret-old-secret-0123');
    const sealed = old.seal('refresh', { a: 1 });
    expect(new Sealer(SECRET, ['old-secret-old-secret-old-secret-0123']).open('refresh', sealed)).toEqual({ a: 1 });
  });
});

async function registerClient(ctx: OAuthContext, metadata: object) {
  const res = await register(new Request('https://proxy.example/register', { method: 'POST', body: JSON.stringify(metadata) }), ctx);
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

function tokenRequest(fields: Record<string, string>, headers: Record<string, string> = {}) {
  return new Request('https://proxy.example/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(fields),
  });
}

describe('stateless OAuth server', () => {
  it('rejects unsafe redirect URIs at registration', async () => {
    const ctx = context();
    expect((await registerClient(ctx, { redirect_uris: ['http://evil.example/cb'] })).status).toBe(400);
    expect((await registerClient(ctx, { redirect_uris: ['javascript:alert(1)'] })).status).toBe(400);
    expect((await registerClient(ctx, { redirect_uris: ['cursor://anysphere.cursor-mcp/oauth/callback'] })).status).toBe(201);
  });

  it('runs the code flow with PKCE, and refuses a wrong verifier', async () => {
    const ctx = context();
    const { body: client } = await registerClient(ctx, { redirect_uris: ['https://app.example/cb'], token_endpoint_auth_method: 'none' });
    const verifier = b64url(randomBytes(32));
    const params = new URLSearchParams({
      client_id: client.client_id, redirect_uri: 'https://app.example/cb', response_type: 'code', state: 's',
      code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
    });
    const { request } = parseAuthorize(params, ctx);
    const code = new URL(approve(request, ctx)).searchParams.get('code')!;

    const wrong = await token(tokenRequest({ grant_type: 'authorization_code', client_id: client.client_id, code, code_verifier: b64url(randomBytes(32)) }), ctx);
    expect(wrong.status).toBe(400);
    const ok = await token(tokenRequest({ grant_type: 'authorization_code', client_id: client.client_id, code, code_verifier: verifier, redirect_uri: 'https://app.example/cb' }), ctx);
    expect(ok.status).toBe(200);
    const tokens = (await ok.json()) as Record<string, string>;
    const agent = verifyBearer(new Request('https://proxy.example/mcp', { headers: { authorization: `Bearer ${tokens.access_token}` } }), ctx);
    expect(agent).toEqual({ via: 'oauth', client: fingerprint(client.client_id) });
    // A refresh token is not accepted as an access token.
    expect(verifyBearer(new Request('https://proxy.example/mcp', { headers: { authorization: `Bearer ${tokens.refresh_token}` } }), ctx)).toBeInstanceOf(Response);
  });

  it('requires the derived secret from confidential clients', async () => {
    const ctx = context();
    const { body: client } = await registerClient(ctx, { redirect_uris: ['https://app.example/cb'], token_endpoint_auth_method: 'client_secret_basic' });
    expect(client.client_secret).toBeTruthy();
    const basic = (secret: string) => ({ authorization: `Basic ${Buffer.from(`${client.client_id}:${secret}`).toString('base64')}` });
    expect((await token(tokenRequest({ grant_type: 'refresh_token', refresh_token: 'x' }, basic('wrong')), ctx)).status).toBe(401);
    expect((await token(tokenRequest({ grant_type: 'refresh_token', refresh_token: 'x' }, basic(client.client_secret)), ctx)).status).toBe(400); // authenticated; bad refresh token
  });

  it('refuses unregistered redirect URIs without redirecting, but allows any loopback port', async () => {
    const ctx = context();
    const { body: client } = await registerClient(ctx, { redirect_uris: ['http://127.0.0.1:3000/cb'], token_endpoint_auth_method: 'none' });
    const base = { client_id: client.client_id, response_type: 'code', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' };
    expect(() => parseAuthorize(new URLSearchParams({ ...base, redirect_uri: 'https://evil.example/cb' }), ctx)).toThrow(AuthorizeError);
    try {
      parseAuthorize(new URLSearchParams({ ...base, redirect_uri: 'https://evil.example/cb' }), ctx);
    } catch (error) {
      expect((error as AuthorizeError).redirect).toBeUndefined();
    }
    expect(parseAuthorize(new URLSearchParams({ ...base, redirect_uri: 'http://127.0.0.1:51234/cb' }), ctx).request.redirectUri).toBe('http://127.0.0.1:51234/cb');
  });

  it('honors revocation from the config file', async () => {
    const plain = context();
    const { body: client } = await registerClient(plain, { redirect_uris: ['https://app.example/cb'], token_endpoint_auth_method: 'none' });
    const revoked = context(SECRET, [], JSON.stringify({ agents: { revoked: [fingerprint(client.client_id)] } }));
    const params = new URLSearchParams({ client_id: client.client_id, redirect_uri: 'https://app.example/cb', response_type: 'code', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' });
    expect(() => parseAuthorize(params, revoked)).toThrow(/revoked/);
  });

  it('binds the consent form to the browser nonce', () => {
    const ctx = context();
    const request = { clientId: 'c', redirectUri: 'https://app.example/cb', scope: [], codeChallenge: 'x', resource: 'https://proxy.example/mcp' };
    const sealed = sealConsent(request, 'nonce-1', ctx);
    expect(openConsent(sealed, 'nonce-1', ctx)).toEqual(request);
    expect(openConsent(sealed, 'nonce-2', ctx)).toBeNull();
    expect(openConsent(sealed, undefined, ctx)).toBeNull();
  });
});

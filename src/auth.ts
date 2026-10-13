// Admin sign-in: a password checked once, then a MAC-signed session cookie. Stateless, so a
// session started on one node is valid on every node that shares PROXY_SECRET.

import type { Env } from './env';

const COOKIE = '__Host-proxy-admin';
const SESSION_SECONDS = 12 * 60 * 60;

export function checkPassword(env: Env, password: string): boolean {
  return env.sealer.equal(password, env.settings.adminPassword);
}

export function sessionCookie(env: Env): string {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const signature = env.sealer.mac(`admin:${expires}`).toString('hex');
  // Lax so the session survives top-level navigations back from an agent's authorization redirect.
  return `${COOKIE}=${expires}.${signature}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${SESSION_SECONDS}`;
}

export function clearSessionCookie(): string {
  return `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export function isAdmin(request: Request, env: Env): boolean {
  const match = readCookie(request, COOKIE)?.match(/^(\d+)\.([0-9a-f]{64})$/);
  if (!match) return false;
  const [, expires, signature] = match;
  if (Number(expires) < Date.now() / 1000) return false;
  return env.sealer.verifyMac(`admin:${expires}`, Buffer.from(signature, 'hex'));
}

export function readCookie(request: Request, name: string): string | undefined {
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

/**
 * A redirect target on this proxy's own origin, or /admin. Resolving the URL (instead of checking
 * for a leading "/") also catches forms browsers treat as another host, like "/\\evil.example".
 */
export function sameOriginPath(next: string, origin: string): string {
  try {
    const url = new URL(next, origin);
    if (url.origin === origin && !/[\\\x00-\x1f]/.test(next)) return url.pathname + url.search;
  } catch {
    // fall through
  }
  return '/admin';
}

/** Rejects cross-site form posts and fetches to state-changing endpoints. */
export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin');
  if (origin) return origin === new URL(request.url).origin;
  return request.headers.get('sec-fetch-site') === 'same-origin';
}

// ---------------------------------------------------------------- login attempt limiting

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;
const failures = new Map<string, { count: number; resetAt: number }>();

/** The visitor's IP as Cloudflare reports it (the tunnel sets CF-Connecting-IP). */
export function clientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? request.headers.get('x-real-ip') ?? 'unknown';
}

/** Per node: with N nodes an attacker gets at most N × MAX_FAILURES guesses per window. */
export function loginBlocked(ip: string): boolean {
  const entry = failures.get(ip);
  return !!entry && entry.resetAt > Date.now() && entry.count >= MAX_FAILURES;
}

export function recordLoginFailure(ip: string): void {
  const now = Date.now();
  const entry = failures.get(ip);
  if (!entry || entry.resetAt <= now) failures.set(ip, { count: 1, resetAt: now + WINDOW_MS });
  else entry.count++;
  if (failures.size > 10_000) {
    for (const [key, value] of failures) if (value.resetAt <= now) failures.delete(key);
  }
}

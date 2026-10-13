// Sealed values: authenticated encryption (AES-256-GCM) under keys derived from PROXY_SECRET.
// Everything the agent-facing OAuth server issues (client IDs, codes, tokens, consent forms) is a
// sealed value, so any node holding the secret can verify it and no node has to remember it.

import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

/** What a sealed value is for. Bound into the ciphertext so one kind can't be replayed as another. */
export type Purpose = 'client' | 'code' | 'access' | 'refresh' | 'consent' | 'approvals';

const VERSION = 'v1';

export class Sealer {
  private readonly keys: Buffer[];
  private readonly macKeys: Buffer[];

  /** `previous` secrets still open values sealed before a rotation; only `secret` seals. */
  constructor(secret: string, previous: string[] = []) {
    this.keys = [secret, ...previous].map((s) => Buffer.from(hkdfSync('sha256', s, 'mcp-rewrite-proxy', 'seal-v1', 32)));
    this.macKeys = [secret, ...previous].map((s) => Buffer.from(hkdfSync('sha256', s, 'mcp-rewrite-proxy', 'mac-v1', 32)));
  }

  seal(purpose: Purpose, payload: object): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keys[0], iv);
    cipher.setAAD(Buffer.from(`${VERSION}:${purpose}`));
    const body = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    return `${VERSION}.${Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64url')}`;
  }

  /** The payload, or null when the value is malformed, tampered with, or sealed for another purpose. */
  open<T>(purpose: Purpose, sealed: string): T | null {
    if (typeof sealed !== 'string' || !sealed.startsWith(`${VERSION}.`)) return null;
    const raw = Buffer.from(sealed.slice(VERSION.length + 1), 'base64url');
    if (raw.length < 12 + 16 + 1) return null;
    for (const key of this.keys) {
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
        decipher.setAAD(Buffer.from(`${VERSION}:${purpose}`));
        decipher.setAuthTag(raw.subarray(raw.length - 16));
        const text = Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString('utf8');
        return JSON.parse(text) as T;
      } catch {
        // try the next key
      }
    }
    return null;
  }

  /** Keyed MAC for values that are derived rather than stored (client secrets, cookies). */
  mac(data: string, key = this.macKeys[0]): Buffer {
    return createHmac('sha256', key).update(data).digest();
  }

  /** Whether `presented` is the MAC of `data` under the current or a previous secret. */
  verifyMac(data: string, presented: Buffer): boolean {
    return this.macKeys.some((key) => {
      const expected = this.mac(data, key);
      return presented.length === expected.length && timingSafeEqual(presented, expected);
    });
  }

  /** Constant-time string comparison (via MACs, so lengths don't leak either). */
  equal(a: string, b: string): boolean {
    return timingSafeEqual(this.mac(`cmp:${a}`), this.mac(`cmp:${b}`));
  }
}

/** Short, stable, non-secret label for a client: shown on the consent page, in logs, and used to revoke. */
export function fingerprint(clientId: string): string {
  return createHash('sha256').update(clientId).digest('hex').slice(0, 16);
}

export function randomId(bytes = 16): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256base64url(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

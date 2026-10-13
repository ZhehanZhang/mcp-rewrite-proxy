// Runs this node's cloudflared connector. All nodes use the same tunnel token, so each one is a
// replica of the same tunnel: Cloudflare spreads requests across the connected replicas and stops
// sending to one as soon as its connector disconnects. Tying the connector's lifetime to this
// node's health is what removes a broken or draining node from rotation.

import { type ChildProcess, spawn } from 'node:child_process';

const BINARY = process.env.CLOUDFLARED_PATH ?? 'cloudflared';
/** cloudflared stops taking new requests on SIGTERM and lets in-flight ones finish for this long. */
const GRACE_SECONDS = Number(process.env.TUNNEL_GRACE_SECONDS ?? 25);

export class Tunnel {
  private child?: ChildProcess;
  private wanted = false;
  private restartTimer?: NodeJS.Timeout;
  private restartDelay = 1_000;

  constructor(private readonly token: string) {}

  /** Connects, if not already connected. */
  start(): void {
    this.wanted = true;
    if (this.child || this.restartTimer) return;
    console.log('tunnel: connecting');
    const child = spawn(BINARY, ['tunnel', '--no-autoupdate', '--grace-period', `${GRACE_SECONDS}s`, 'run'], {
      env: { ...process.env, TUNNEL_TOKEN: this.token },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    const log = (data: Buffer) => {
      for (const line of data.toString().split('\n')) if (line.trim()) console.log(`cloudflared: ${line}`);
    };
    child.stdout?.on('data', log);
    child.stderr?.on('data', log);
    const startedAt = Date.now();
    child.on('error', (error) => console.error('tunnel: failed to start cloudflared:', error.message));
    child.on('exit', (code, signal) => {
      if (this.child === child) this.child = undefined;
      if (!this.wanted) return;
      // Unexpected exit: reconnect with backoff (reset once a connection has lasted a minute).
      if (Date.now() - startedAt > 60_000) this.restartDelay = 1_000;
      console.error(`tunnel: cloudflared exited (${signal ?? code}); retrying in ${this.restartDelay / 1000}s`);
      this.restartTimer = setTimeout(() => {
        this.restartTimer = undefined;
        if (this.wanted) this.start();
      }, this.restartDelay);
      this.restartDelay = Math.min(this.restartDelay * 2, 30_000);
    });
  }

  /** Disconnects gracefully and resolves once cloudflared has exited. */
  async stop(): Promise<void> {
    this.wanted = false;
    clearTimeout(this.restartTimer);
    this.restartTimer = undefined;
    const child = this.child;
    if (!child) return;
    console.log('tunnel: disconnecting');
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    const killTimer = setTimeout(() => child.kill('SIGKILL'), (GRACE_SECONDS + 5) * 1000);
    await exited;
    clearTimeout(killTimer);
  }
}

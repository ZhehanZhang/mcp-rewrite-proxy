// The transferable config file: tool and server edits plus agent revocations. The same file goes
// on every node (copy it, bake it into the image, or mount it from git); nodes reload it on change.

import { readFileSync, statSync, watch } from 'node:fs';
import { type ProxyConfig, Rewriter } from './rewrite';

export interface AgentPolicy {
  /** Client fingerprints (shown on the consent page and in logs) whose tokens are refused. */
  revoked?: string[];
  /** ISO time: tokens issued before it are refused. Revokes every agent at once. */
  revokeIssuedBefore?: string;
}

export interface FileConfig extends ProxyConfig {
  agents?: AgentPolicy;
}

export interface LoadedConfig {
  config: FileConfig;
  rewriter: Rewriter;
  revoked: Set<string>;
  /** Epoch seconds; tokens issued earlier are refused. */
  notBefore: number;
  loadedAt: number;
}

function compile(config: FileConfig): LoadedConfig {
  if (typeof config !== 'object' || config === null || Array.isArray(config)) throw new Error('the config file must contain a JSON object');
  const agents = config.agents ?? {};
  if (agents.revoked !== undefined && !Array.isArray(agents.revoked)) throw new Error('agents.revoked must be an array of fingerprints');
  const notBefore = agents.revokeIssuedBefore ? Date.parse(agents.revokeIssuedBefore) : 0;
  if (Number.isNaN(notBefore)) throw new Error('agents.revokeIssuedBefore must be an ISO date');
  return {
    config,
    rewriter: new Rewriter(config), // validates names and collisions
    revoked: new Set(agents.revoked ?? []),
    notBefore: Math.floor(notBefore / 1000),
    loadedAt: Date.now(),
  };
}

/** Parses and validates config text without applying it (used by the admin editor too). */
export function parseConfig(text: string): LoadedConfig {
  return compile(JSON.parse(text) as FileConfig);
}

export class ConfigFile {
  private current: LoadedConfig;
  private signature = '';
  /** Why the file on disk isn't the one in use, if it isn't. */
  error?: string;
  private timer?: NodeJS.Timeout;

  constructor(readonly path: string) {
    this.current = compile({});
    this.reload(true);
  }

  get(): LoadedConfig {
    return this.current;
  }

  /** Re-reads the file if it changed. A broken file is reported and the last good config is kept. */
  reload(initial = false): void {
    let signature: string;
    try {
      const stat = statSync(this.path);
      signature = `${stat.mtimeMs}:${stat.size}:${stat.ino}`;
    } catch {
      if (initial) console.warn(`config: ${this.path} not found; serving the upstream unchanged until it exists`);
      this.signature = '';
      return;
    }
    if (signature === this.signature) return;
    this.signature = signature;
    try {
      this.current = parseConfig(readFileSync(this.path, 'utf8'));
      this.error = undefined;
      console.log(`config: loaded ${this.path} (${Object.keys(this.current.config.tools?.overrides ?? {}).length} tool overrides)`);
    } catch (error) {
      this.error = `${this.path}: ${(error as Error).message}`;
      console.error(`config: kept the previous config; ${this.error}`);
      if (initial) throw new Error(this.error);
    }
  }

  /** Polls as well as watching: change events don't reliably cross Docker bind mounts. */
  watch(intervalMs = 2_000): void {
    try {
      watch(this.path, () => this.reload()).on('error', () => {});
    } catch {
      // file may not exist yet; polling covers it
    }
    this.timer = setInterval(() => this.reload(), intervalMs);
    this.timer.unref();
  }

  stop(): void {
    clearInterval(this.timer);
  }
}

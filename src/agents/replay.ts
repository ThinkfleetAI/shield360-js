/**
 * The default replay store: passport ids remembered in memory until they
 * expire, with a size cap. One per process; use a shared ReplayStore (Redis,
 * a database) when a receiver runs on several instances.
 */

import { ReplayStore } from './types';

export type MemoryReplayStoreOptions = { maxEntries?: number; clock?: () => number };

export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();
  private readonly maxEntries: number;
  private readonly clock: () => number;

  constructor(options: MemoryReplayStoreOptions = {}) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 100_000);
    this.clock = options.clock ?? Date.now;
  }

  async seen(jti: string, expiresAtMs: number): Promise<boolean> {
    const now = this.clock();
    const until = this.entries.get(jti);
    if (until !== undefined && until > now) return true;
    if (until !== undefined) this.entries.delete(jti);
    if (this.entries.size >= this.maxEntries) this.evict(now);
    this.entries.set(jti, expiresAtMs);
    return false;
  }

  get size(): number {
    return this.entries.size;
  }

  /** Drops expired ids; if still full, the oldest-inserted ones. */
  private evict(now: number): void {
    for (const [k, until] of this.entries) if (until <= now) this.entries.delete(k);
    const over = this.entries.size - this.maxEntries + 1;
    if (over <= 0) return;
    let n = 0;
    for (const k of this.entries.keys()) {
      if (n++ >= over) break;
      this.entries.delete(k);
    }
  }
}

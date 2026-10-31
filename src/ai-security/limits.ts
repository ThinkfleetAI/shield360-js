/**
 * Per end-user and per-tenant rate and token limits (OWASP LLM10 unbounded
 * consumption): requests per minute, tokens per day and cost per day.
 *
 * Design: local approximate limits with periodic sync. Each process counts
 * locally and, every limits.syncSeconds (10 s by default) in the background,
 * sends what it counted since the last sync to the platform
 * (POST /api/ai-security/limits/sync), which adds it to shared counters (one
 * per tenant or user and window, in Redis) and answers with the totals
 * across every process. A check compares the last totals plus what this
 * process counted since with the limit. Nothing is fetched on the request
 * path, so a limit check costs a map lookup and the platform being slow or
 * down never slows or fails a call (it fails open: local counts still hold).
 *
 * Why not a lease per request or per batch of requests: a lease still puts
 * a platform round trip on the path of the request that needs the next one,
 * and a platform outage then stops every app at once. The cost of the chosen
 * design is precision: N processes can together overshoot a limit by at most
 * what they serve in one sync interval before they learn the total. Limits
 * are abuse controls, not billing, so that is the right trade.
 *
 * Windows are UTC: the current minute for requests, the current day for
 * tokens and cost. A tenant's and a user's limits both apply.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_limits.py
 * and src/client/src/lib/platform/ai-security/counters.ts
 */

import type { AiSecurityPolicy, LimitWindow } from './policy';

export type LimitScope = 'user' | 'tenant';
export type LimitKey = { scope: LimitScope; tenantId: string; userId?: string };
export type Usage = { requests: number; tokens: number; costMicros: number };

export type LimitVerdict = {
  allowed: boolean;
  /** The first limit that is reached: requests_per_minute, tokens_per_day or cost_per_day. */
  limit?: 'requests_per_minute' | 'tokens_per_day' | 'cost_per_day';
  scope?: LimitScope;
  used?: number;
  max?: number;
};

type Counter = {
  key: LimitKey;
  minute: number;
  day: number;
  /** Totals across processes at the last sync, for the current windows. */
  shared: Usage;
  /** Counted here since the last sync. */
  local: Usage;
  /** Counted here and being sent now. */
  inflight: Usage;
};

const zero = (): Usage => ({ requests: 0, tokens: 0, costMicros: 0 });
const MAX_KEYS = 50_000;

export type SyncEntry = LimitKey & { minute: number; day: number } & Usage;
export type SyncAnswer = { entries?: Array<LimitKey & { minute?: number; day?: number; requests?: number; tokens?: number; costMicros?: number }> };
export type SyncFn = (entries: SyncEntry[]) => Promise<SyncAnswer | null>;

const keyOf = (k: LimitKey) => `${k.scope}\u0000${k.tenantId}\u0000${k.userId || ''}`;

export class LimitEngine {
  private readonly counters = new Map<string, Counter>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private syncing = false;

  constructor(
    private policy: () => AiSecurityPolicy['limits'],
    private readonly sync: SyncFn | null,
    private readonly now: () => number = Date.now,
  ) {}

  start(): void {
    if (this.timer || !this.sync) return;
    const every = Math.max(2, this.policy().syncSeconds) * 1000;
    this.timer = setInterval(() => void this.syncNow(), every);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private windows() {
    const t = this.now();
    return { minute: Math.floor(t / 60_000), day: Math.floor(t / 86_400_000) };
  }

  private counter(key: LimitKey): Counter | null {
    const id = keyOf(key);
    const { minute, day } = this.windows();
    let c = this.counters.get(id);
    if (!c) {
      if (this.counters.size >= MAX_KEYS) this.evict(day);
      if (this.counters.size >= MAX_KEYS) return null;
      c = { key, minute, day, shared: zero(), local: zero(), inflight: zero() };
      this.counters.set(id, c);
    }
    if (c.day !== day) {
      c.day = day;
      c.minute = minute;
      c.shared = zero();
      c.local = zero();
    } else if (c.minute !== minute) {
      c.minute = minute;
      c.shared.requests = 0;
      c.local.requests = 0;
    }
    return c;
  }

  private evict(day: number) {
    this.counters.forEach((c, id) => {
      if (c.day !== day) this.counters.delete(id);
    });
  }

  /** The keys a request counts against: its tenant, and its user inside the tenant. */
  static keysFor(tenantId: string | null | undefined, userId: string | null | undefined): LimitKey[] {
    if (!tenantId) return [];
    const keys: LimitKey[] = [{ scope: 'tenant', tenantId }];
    if (userId) keys.push({ scope: 'user', tenantId, userId });
    return keys;
  }

  /** Whether one more request fits. Counts nothing; call record() for what was used. */
  check(keys: readonly LimitKey[]): LimitVerdict {
    const p = this.policy();
    if (p.mode === 'off') return { allowed: true };
    for (const key of keys) {
      const lim: LimitWindow = key.scope === 'user' ? p.perUser : p.perTenant;
      const c = this.counter(key);
      if (!c) continue;
      const used = (u: keyof Usage) => c.shared[u] + c.local[u] + c.inflight[u];
      if (lim.requestsPerMinute && used('requests') + 1 > lim.requestsPerMinute) {
        return { allowed: false, limit: 'requests_per_minute', scope: key.scope, used: used('requests'), max: lim.requestsPerMinute };
      }
      if (lim.tokensPerDay && used('tokens') >= lim.tokensPerDay) {
        return { allowed: false, limit: 'tokens_per_day', scope: key.scope, used: used('tokens'), max: lim.tokensPerDay };
      }
      if (lim.costPerDayUsd && used('costMicros') >= lim.costPerDayUsd * 1e6) {
        return { allowed: false, limit: 'cost_per_day', scope: key.scope, used: used('costMicros') / 1e6, max: lim.costPerDayUsd };
      }
    }
    return { allowed: true };
  }

  record(keys: readonly LimitKey[], usage: Partial<Usage>): void {
    if (this.policy().mode === 'off') return;
    for (const key of keys) {
      const c = this.counter(key);
      if (!c) continue;
      c.local.requests += Math.max(0, usage.requests || 0);
      c.local.tokens += Math.max(0, Math.round(usage.tokens || 0));
      c.local.costMicros += Math.max(0, Math.round(usage.costMicros || 0));
    }
  }

  /** Sends local counts and takes the shared totals. Never throws; a failed sync keeps the counts for the next. */
  async syncNow(): Promise<void> {
    if (!this.sync || this.syncing) return;
    this.syncing = true;
    const batch: Counter[] = [];
    try {
      this.counters.forEach((c) => {
        this.counter(c.key); // roll windows
        if (c.local.requests || c.local.tokens || c.local.costMicros || c.shared.requests || c.shared.tokens) {
          c.inflight = c.local;
          c.local = zero();
          batch.push(c);
        }
      });
      if (!batch.length) return;
      const answer = await this.sync(batch.slice(0, 5000).map((c) => ({ ...c.key, minute: c.minute, day: c.day, ...c.inflight })));
      if (!answer) throw new Error('no answer');
      const byKey = new Map(batch.map((c) => [keyOf(c.key), c]));
      for (const e of answer.entries || []) {
        const c = byKey.get(keyOf({ scope: e.scope, tenantId: e.tenantId, userId: e.userId }));
        if (!c) continue;
        if (e.day === c.day) {
          c.shared.tokens = Math.max(0, Number(e.tokens) || 0);
          c.shared.costMicros = Math.max(0, Number(e.costMicros) || 0);
        }
        if (e.minute === c.minute) c.shared.requests = Math.max(0, Number(e.requests) || 0);
      }
      for (const c of batch) c.inflight = zero();
    } catch {
      // Keep the counts: merge them back so the next sync sends them.
      for (const c of batch) {
        c.local.requests += c.inflight.requests;
        c.local.tokens += c.inflight.tokens;
        c.local.costMicros += c.inflight.costMicros;
        c.inflight = zero();
      }
    } finally {
      this.syncing = false;
    }
  }

  /** For tests and reports. */
  usage(key: LimitKey): Usage {
    const c = this.counter(key);
    if (!c) return zero();
    return {
      requests: c.shared.requests + c.local.requests + c.inflight.requests,
      tokens: c.shared.tokens + c.local.tokens + c.inflight.tokens,
      costMicros: c.shared.costMicros + c.local.costMicros + c.inflight.costMicros,
    };
  }
}

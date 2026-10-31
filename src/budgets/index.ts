/**
 * Budget check: ask Shield360 whether this app may spend on a model call.
 *
 *   Shield360.budgets.check({ model, estimatedCostUsd })
 *     -> { allowed, action: allow | warn | throttle | block, reason, ... }
 *
 * The answer comes from the platform's GET /api/budgets/decision, the one
 * spend decision every Shield360 enforcement point uses, asked with the
 * environment's API key and this app's service name. App budgets (Costs ->
 * Budgets, "App") and project budgets with enforcement rules apply.
 *
 * It does not call the platform on every request. Like the CLI's proxy and
 * hooks (cli/internal/spenddecision), a decision is reused for the
 * ttlSeconds the platform sets (60 s by default) while the estimated cost of
 * the calls checked with it fits in its headroomUsd, the spend left before
 * any limit turns stricter. Concurrent checks share one fetch.
 *
 * It never throws. When no decision can be read it fails open (allowed) by
 * default; closed when `failClosed` is set here or on the client, or when
 * the last decision read said failClosed (a budget with a block rule that
 * asks for it). A failed read is not retried for a few seconds.
 *
 * Must stay in sync with: sdk/python/src/shield360/budgets.py
 */

import Shield360Config from '../config';

export type BudgetAction = 'allow' | 'warn' | 'throttle' | 'block';

export type BudgetCheckOptions = {
  /** The app's service name; defaults to the applicationName given to init(). */
  app?: string;
  /** The model the call will use, for model budgets. */
  model?: string;
  /** What the call may cost in USD, when the caller can estimate it. Held against the decision's headroom. */
  estimatedCostUsd?: number;
  /** Refuse when no decision can be read. Overrides the client's setting for this check. */
  failClosed?: boolean;
};

export type BudgetCheckResult = {
  /** Whether the call may go ahead. */
  allowed: boolean;
  action: BudgetAction;
  /** budget_ok, budget_warn, budget_throttle, budget_block, budget_override or budget_unavailable. */
  code: string;
  /** What to show or log, from the platform. Empty when allowed with nothing to say. */
  reason: string;
  /** The limit that decided, when one did. */
  limit: { id: string; name: string; scope: string } | null;
  /** Spend left before a stricter action, from the decision; null when spending cannot make it stricter. */
  headroomUsd: number | null;
  /** Answered from a decision already fetched. */
  cached: boolean;
  /** No decision could be read; `allowed` is the fail mode's. */
  unavailable: boolean;
};

export type BudgetClientOptions = {
  /** Shield360 URL; defaults to init()'s shield360Url or SHIELD360_URL. */
  url?: string;
  /** Environment API key; defaults to init()'s shield360ApiKey or SHIELD360_API_KEY. */
  apiKey?: string;
  /** The app's service name; defaults to init()'s applicationName. */
  app?: string;
  /** Refuse when no decision can be read (default false; env SHIELD360_BUDGET_FAIL_CLOSED=1). */
  failClosed?: boolean;
  /** One fetch's timeout. Default 3000 ms. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
};

type Decision = {
  action?: string;
  code?: string;
  reason?: string;
  limit?: { id?: string; name?: string; scope?: string } | null;
  throttle?: { requestsPerMinute?: number } | null;
  failClosed?: boolean;
  ttlSeconds?: number;
  headroomUsd?: number | null;
};

type Entry = { decision: Decision; fetchedAt: number; ttlMs: number; spent: number };

const DEFAULT_TTL_MS = 60_000;
const MAX_TTL_MS = 600_000;
/** How long a failed read stands before the next check tries again. */
const UNAVAILABLE_BACKOFF_MS = 5_000;
const MAX_SUBJECT = 256;
const ACTIONS: readonly BudgetAction[] = ['allow', 'warn', 'throttle', 'block'];

export const UNAVAILABLE_REASON =
  'Shield360 could not check the budget for this AI call, and this app is set to wait until it can. Try again shortly. [budget_unavailable]';

function envFlag(name: string): boolean {
  const v = (typeof process !== 'undefined' ? process.env?.[name] : undefined)?.trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

const positive = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);

function clean(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const t = v.trim();
  return t && t.length <= MAX_SUBJECT ? t : undefined;
}

/** Thrown by the automatic pre-call check (init({ budgetCheck })) when a budget refuses the call. */
export class BudgetExceededError extends Error {
  readonly result: BudgetCheckResult;
  constructor(result: BudgetCheckResult) {
    super(result.reason || `Shield360 budget refused this AI call. [${result.code}]`);
    this.name = 'BudgetExceededError';
    this.result = result;
  }
}

export class BudgetClient {
  private readonly opts: BudgetClientOptions;
  private cache = new Map<string, Entry>();
  private inflight = new Map<string, Promise<Entry | null>>();
  private unavailableUntil = new Map<string, number>();
  private calls = new Map<string, number[]>();
  /** The last decision read asked to fail closed. */
  private failClosedHint = false;

  constructor(opts: BudgetClientOptions = {}) {
    this.opts = opts;
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private creds(): { url?: string; apiKey?: string } {
    const env = typeof process !== 'undefined' ? process.env : {};
    return {
      url: this.opts.url ?? Shield360Config.shield360Url ?? env.SHIELD360_URL,
      apiKey: this.opts.apiKey ?? Shield360Config.shield360ApiKey ?? env.SHIELD360_API_KEY,
    };
  }

  /** Forget cached decisions (after changing a budget, and in tests). */
  reset(): void {
    this.cache.clear();
    this.inflight.clear();
    this.unavailableUntil.clear();
    this.calls.clear();
    this.failClosedHint = false;
  }

  /** The decision for one call. Never throws. */
  async check(options: BudgetCheckOptions = {}): Promise<BudgetCheckResult> {
    try {
      return await this.checkUnsafe(options);
    } catch {
      return this.unavailable(options);
    }
  }

  private failClosed(options: BudgetCheckOptions): boolean {
    if (options.failClosed !== undefined) return options.failClosed;
    if (this.opts.failClosed !== undefined) return this.opts.failClosed || this.failClosedHint;
    return envFlag('SHIELD360_BUDGET_FAIL_CLOSED') || this.failClosedHint;
  }

  private unavailable(options: BudgetCheckOptions): BudgetCheckResult {
    const closed = this.failClosed(options);
    return {
      allowed: !closed,
      action: closed ? 'block' : 'allow',
      code: 'budget_unavailable',
      reason: closed ? UNAVAILABLE_REASON : '',
      limit: null,
      headroomUsd: null,
      cached: false,
      unavailable: true,
    };
  }

  private async checkUnsafe(options: BudgetCheckOptions): Promise<BudgetCheckResult> {
    const app = clean(options.app) ?? clean(this.opts.app) ?? clean(Shield360Config.applicationName);
    const model = clean(options.model);
    const cost = positive(options.estimatedCostUsd);
    const { url, apiKey } = this.creds();
    if (!app || !url || !apiKey) return this.unavailable(options);

    const key = `${app}\u0000${model ?? ''}`.toLowerCase();
    const now = this.now();
    const hit = this.cache.get(key);
    if (hit && now - hit.fetchedAt < hit.ttlMs && this.fits(hit, cost)) {
      hit.spent += cost;
      return this.result(key, hit.decision, true);
    }
    if ((this.unavailableUntil.get(key) ?? 0) > now) return this.unavailable(options);

    let pending = this.inflight.get(key);
    const started = !pending;
    if (!pending) {
      pending = this.fetchDecision(url, apiKey, app, model, cost).finally(() => this.inflight.delete(key));
      this.inflight.set(key, pending);
    }
    const entry = await pending;
    if (!entry) {
      this.unavailableUntil.set(key, this.now() + UNAVAILABLE_BACKOFF_MS);
      return this.unavailable(options);
    }
    this.unavailableUntil.delete(key);
    if (started) this.cache.set(key, entry);
    // The fetch asked with the first call's cost; every call that shares the decision counts against its headroom.
    entry.spent += cost;
    return this.result(key, entry.decision, !started);
  }

  private fits(entry: Entry, cost: number): boolean {
    const h = entry.decision.headroomUsd;
    return h === null || h === undefined || entry.spent + cost <= h;
  }

  private async fetchDecision(url: string, apiKey: string, app: string, model: string | undefined, cost: number): Promise<Entry | null> {
    const doFetch = this.opts.fetch ?? (typeof fetch === 'function' ? fetch : undefined);
    if (!doFetch) return null;
    const q = new URLSearchParams({ app });
    if (model) q.set('model', model);
    if (cost > 0) q.set('cost', cost.toFixed(6));
    const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
    const timer = setTimeout(() => controller?.abort(), this.opts.timeoutMs ?? 3000);
    try {
      const res = await doFetch(`${url.replace(/\/+$/, '')}/api/budgets/decision?${q.toString()}`, {
        headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
        signal: controller?.signal,
      });
      if (!res.ok) return null;
      const decision = (await res.json()) as Decision;
      if (!decision || typeof decision !== 'object' || !ACTIONS.includes(decision.action as BudgetAction)) return null;
      this.failClosedHint = decision.failClosed === true;
      const ttl = Number(decision.ttlSeconds) > 0 ? Math.min(Number(decision.ttlSeconds) * 1000, MAX_TTL_MS) : DEFAULT_TTL_MS;
      return { decision, fetchedAt: this.now(), ttlMs: ttl, spent: 0 };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Throttle is a per-subject sliding minute, as the CLI keeps it. */
  private throttled(key: string, rpm: number): boolean {
    const now = this.now();
    const recent = (this.calls.get(key) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= rpm) {
      this.calls.set(key, recent);
      return true;
    }
    recent.push(now);
    this.calls.set(key, recent);
    return false;
  }

  private result(key: string, d: Decision, cached: boolean): BudgetCheckResult {
    const action = (ACTIONS.includes(d.action as BudgetAction) ? d.action : 'allow') as BudgetAction;
    let allowed = action === 'allow' || action === 'warn';
    if (action === 'throttle') {
      const rpm = Math.max(1, Math.floor(Number(d.throttle?.requestsPerMinute) || 1));
      allowed = !this.throttled(key, rpm);
    }
    const headroom = typeof d.headroomUsd === 'number' && Number.isFinite(d.headroomUsd) ? d.headroomUsd : null;
    return {
      allowed,
      action,
      code: typeof d.code === 'string' ? d.code : `budget_${action === 'allow' ? 'ok' : action}`,
      reason: typeof d.reason === 'string' ? d.reason : '',
      limit: d.limit && typeof d.limit === 'object' ? { id: String(d.limit.id ?? ''), name: String(d.limit.name ?? ''), scope: String(d.limit.scope ?? '') } : null,
      headroomUsd: headroom,
      cached,
      unavailable: false,
    };
  }
}

let defaultClient: BudgetClient | null = null;

/** The process's client, built from init()'s URL, API key and applicationName. */
export function defaultBudgetClient(): BudgetClient {
  if (!defaultClient) defaultClient = new BudgetClient();
  return defaultClient;
}

/** Replace the process's client (init({ budgetCheck: { failClosed } }) and tests). */
export function configureBudgets(opts: BudgetClientOptions = {}): BudgetClient {
  defaultClient = new BudgetClient(opts);
  return defaultClient;
}

/** Shield360.budgets: check() with the process's client. */
export const budgets = {
  check: (options?: BudgetCheckOptions): Promise<BudgetCheckResult> => defaultBudgetClient().check(options),
  configure: configureBudgets,
  reset: (): void => defaultBudgetClient().reset(),
};

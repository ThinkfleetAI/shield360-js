/**
 * Shield360 feature flags for Node: fetch an environment's flags, evaluate
 * them locally, and stamp the variation served on the active span.
 *
 *   import Shield360 from 'shield360';
 *   Shield360.init({ applicationName: 'checkout-api' });  // or SHIELD360_URL / SHIELD360_API_KEY
 *   if (Shield360.flags.isEnabled('new-checkout', { key: user.id, plan: user.plan })) { ... }
 *   const model = Shield360.flags.getFlag('model-choice', { key: user.id }, 'gpt-4o-mini');
 *
 * The client polls GET /api/flags/rules (every 30 seconds by default, with
 * jitter, sending the last ETag so an unchanged environment costs a 304),
 * keeps the rules in memory and evaluates with the same engine as the server
 * (./engine.ts, a byte-identical copy of sdk/flags-core). It never throws
 * into the app: until rules arrive, for an unknown flag, or on any error, the
 * caller's default is returned.
 *
 * Each evaluation sets `shield360.flag.<key>` = the served variation's key on
 * the active span, so cost, latency and evals can be compared per variant.
 */

import { diag, trace } from '@opentelemetry/api';
import Shield360Config from '../config';
import PromptHub from '../features/prompt-hub';
import {
  evaluate,
  validateFlag,
  validateSegment,
  type Evaluation,
  type EvaluationContext,
  type FlagDefinition,
  type FlagValue,
  type Segment,
} from './engine';

export const RULES_PATH = '/api/flags/rules';
export const SPAN_ATTRIBUTE_PREFIX = 'shield360.flag.';
export const DEFAULT_POLL_INTERVAL_MS = 30_000;
const MIN_POLL_INTERVAL_MS = 5_000;
const DEFAULT_TIMEOUT_MS = 10_000;

export interface FlagsOptions {
  /** Shield360's URL; defaults to init()'s shield360Url, then SHIELD360_URL. */
  url?: string;
  /** The environment's API key; defaults to init()'s shield360ApiKey, then SHIELD360_API_KEY. */
  apiKey?: string;
  /** service.name, for flags scoped to one app; defaults to init()'s applicationName. */
  applicationName?: string;
  /** How often to poll, in milliseconds (at least 5,000). Default 30,000. */
  pollIntervalMs?: number;
  /** Per-request timeout in milliseconds. Default 10,000. */
  timeoutMs?: number;
  /** Set `shield360.flag.<key>` on the active span. Default true. */
  recordOnSpan?: boolean;
  /** For tests: the fetch to use. */
  fetch?: typeof fetch;
}

export type FlagDetail<T> = {
  value: T;
  /** The served variation's key; null when the caller's default was returned. */
  variation: string | null;
  reason: Evaluation['reason'] | { kind: 'FLAG_NOT_FOUND' | 'NOT_READY' | 'WRONG_TYPE' | 'ERROR' };
};

type RulesBody = { version?: unknown; flags?: unknown; segments?: unknown };

/** A Prompt Hub prompt a flag variation names: `{ name, version? }`, or the text `name` / `name@version`. */
export type PromptRef = { name: string; version?: string };

export type PromptFlagOptions = {
  /** Variables to compile the prompt with. */
  variables?: Record<string, unknown>;
  /** Compile the prompt with the variables. Default: true when variables are given. */
  shouldCompile?: boolean;
};

export type PromptFlagResult = {
  name: string;
  version: string | null;
  /** The served variation's key; null when the default reference was used. */
  variation: string | null;
  /** What Prompt Hub answered for it (its `res`), or null when it could not be fetched. */
  prompt: unknown;
  error: string | null;
};

/** The Prompt Hub reference a flag value names, or null. */
export function promptRefOf(value: unknown): PromptRef | null {
  if (typeof value === 'string') {
    const text = value.trim();
    const at = text.lastIndexOf('@');
    const name = at > 0 ? text.slice(0, at) : text;
    const version = at > 0 ? text.slice(at + 1) : '';
    if (!name || (at === 0)) return null;
    return version ? { name, version } : { name };
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const v = value as Record<string, unknown>;
    if (typeof v.name !== 'string' || !v.name.trim()) return null;
    if (v.version !== undefined && v.version !== null && typeof v.version !== 'string') return null;
    return v.version ? { name: v.name.trim(), version: v.version as string } : { name: v.name.trim() };
  }
  return null;
}

function sameKind(value: FlagValue, fallback: unknown): boolean {
  if (fallback === undefined || fallback === null) return true;
  if (typeof fallback === 'object') return value !== null && typeof value === 'object';
  return typeof value === typeof fallback;
}

export class FlagsClient {
  private options: FlagsOptions;
  private flags = new Map<string, FlagDefinition>();
  private segments: Segment[] = [];
  private etag: string | null = null;
  private fetched = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private started = false;
  private inFlight: Promise<boolean> | null = null;
  private waiters: Array<(ready: boolean) => void> = [];
  private warned = false;

  constructor(options: FlagsOptions = {}) {
    this.options = { ...options };
  }

  /** Changes the options; takes effect on the next fetch. */
  configure(options: FlagsOptions): void {
    this.options = { ...this.options, ...options };
  }

  private destination(): { url: string; apiKey: string } | null {
    const env = typeof process !== 'undefined' ? process.env : ({} as Record<string, string | undefined>);
    const url = (this.options.url ?? Shield360Config.shield360Url ?? env.SHIELD360_URL ?? '').trim().replace(/\/+$/, '');
    const apiKey = (this.options.apiKey ?? Shield360Config.shield360ApiKey ?? env.SHIELD360_API_KEY ?? '').trim();
    return url && apiKey ? { url, apiKey } : null;
  }

  private applicationName(): string | undefined {
    return this.options.applicationName ?? Shield360Config.applicationName;
  }

  /** Starts polling (once). Called on first use; call it at startup to fetch early. */
  start(): void {
    if (this.started) return;
    this.started = true;
    void this.refresh().finally(() => this.schedule());
  }

  private schedule(): void {
    if (!this.started) return;
    const interval = Math.max(this.options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS, MIN_POLL_INTERVAL_MS);
    // ±10% jitter, so many processes started together do not poll together.
    const delay = Math.round(interval * (0.9 + Math.random() * 0.2));
    this.timer = setTimeout(() => {
      void this.refresh().finally(() => this.schedule());
    }, delay);
    const t = this.timer as unknown as { unref?: () => void };
    if (typeof t.unref === 'function') t.unref();
  }

  /** Stops polling. Rules already fetched keep being served. */
  close(): void {
    this.started = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  /** Whether rules have been fetched at least once. */
  isReady(): boolean {
    return this.fetched;
  }

  /** Resolves true once rules have been fetched, or false after `timeoutMs`. */
  ready(timeoutMs = DEFAULT_TIMEOUT_MS): Promise<boolean> {
    this.start();
    if (this.fetched) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      const t = timer as unknown as { unref?: () => void };
      if (typeof t.unref === 'function') t.unref();
      this.waiters.push((ok) => {
        clearTimeout(timer);
        resolve(ok);
      });
    });
  }

  /** Fetches the rules now. Resolves true when the rules are current; never rejects. */
  refresh(): Promise<boolean> {
    if (!this.inFlight) {
      this.inFlight = this.fetchRules().finally(() => {
        this.inFlight = null;
      });
    }
    return this.inFlight;
  }

  private async fetchRules(): Promise<boolean> {
    const dest = this.destination();
    if (!dest) {
      if (!this.warned) {
        this.warned = true;
        diag.warn('shield360 flags: no Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY); every flag serves its default.');
      }
      return false;
    }
    const doFetch = this.options.fetch ?? (typeof fetch === 'function' ? fetch : undefined);
    if (!doFetch) return false;
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timeout = setTimeout(() => controller?.abort(), this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    try {
      const headers: Record<string, string> = { Authorization: `Bearer ${dest.apiKey}`, Accept: 'application/json' };
      if (this.etag) headers['If-None-Match'] = this.etag;
      const response = await doFetch(`${dest.url}${RULES_PATH}`, { method: 'GET', headers, signal: controller?.signal });
      if (response.status === 304) {
        this.markFetched();
        return true;
      }
      if (!response.ok) {
        diag.debug(`shield360 flags: rules fetch answered ${response.status}`);
        return false;
      }
      const body = (await response.json()) as RulesBody;
      if (!body || !Array.isArray(body.flags)) return false;
      const next = new Map<string, FlagDefinition>();
      for (const raw of body.flags) {
        // A flag that does not validate is left out: its callers get their default.
        if (validateFlag(raw).length) continue;
        const flag = raw as FlagDefinition;
        next.set(flag.key, flag);
      }
      const segments: Segment[] = [];
      for (const raw of Array.isArray(body.segments) ? body.segments : []) {
        if (!validateSegment(raw).length) segments.push(raw as Segment);
      }
      this.flags = next;
      this.segments = segments;
      this.etag = response.headers.get('etag');
      this.markFetched();
      return true;
    } catch (err) {
      diag.debug(`shield360 flags: rules fetch failed: ${err instanceof Error ? err.name : 'error'}`);
      return false;
    } finally {
      clearTimeout(timeout);
    }
  }

  private markFetched(): void {
    this.fetched = true;
    const waiting = this.waiters;
    this.waiters = [];
    for (const w of waiting) w(true);
  }

  /** The flag's value for this context, with the variation and why; never throws. */
  getFlagDetail<T extends FlagValue | undefined>(key: string, context: EvaluationContext = {}, defaultValue: T): FlagDetail<T> {
    try {
      this.start();
      if (!this.fetched) return { value: defaultValue, variation: null, reason: { kind: 'NOT_READY' } };
      const flag = this.flags.get(key);
      const app = this.applicationName();
      if (!flag || (flag.appName && flag.appName !== app)) {
        return { value: defaultValue, variation: null, reason: { kind: 'FLAG_NOT_FOUND' } };
      }
      const result = evaluate(flag, context, this.segments);
      if (result.variation === null) return { value: defaultValue, variation: null, reason: result.reason };
      if (!sameKind(result.value, defaultValue)) {
        return { value: defaultValue, variation: null, reason: { kind: 'WRONG_TYPE' } };
      }
      if (this.options.recordOnSpan !== false) {
        const span = trace.getActiveSpan();
        if (span && span.isRecording()) span.setAttribute(`${SPAN_ATTRIBUTE_PREFIX}${key}`, result.variation);
      }
      return { value: result.value as T, variation: result.variation, reason: result.reason };
    } catch {
      return { value: defaultValue, variation: null, reason: { kind: 'ERROR' } };
    }
  }

  /** The flag's value for this context, or `defaultValue`; never throws. */
  getFlag(key: string, context: EvaluationContext | undefined, defaultValue: boolean): boolean;
  getFlag(key: string, context: EvaluationContext | undefined, defaultValue: string): string;
  getFlag(key: string, context: EvaluationContext | undefined, defaultValue: number): number;
  getFlag<T extends FlagValue | undefined>(key: string, context: EvaluationContext | undefined, defaultValue: T): T;
  getFlag(key: string, context: EvaluationContext = {}, defaultValue: FlagValue | undefined): FlagValue | undefined {
    return this.getFlagDetail(key, context, defaultValue).value;
  }

  /** Whether a boolean flag is on for this context; false until rules arrive, for an unknown flag, or on error. */
  isEnabled(key: string, context: EvaluationContext = {}): boolean {
    return this.getFlag(key, context, false) === true;
  }

  /**
   * AI: the model a model-switch flag serves this context — a string flag whose
   * variations are provider/model ids such as `openai/gpt-4o-mini`. The default
   * until rules arrive, for an unknown flag, or for an empty value.
   */
  model(key: string, context: EvaluationContext = {}, defaultModel: string): string {
    const value = this.getFlag(key, context, defaultModel);
    return typeof value === 'string' && value.trim() ? value : defaultModel;
  }

  /**
   * AI: whether a kill switch is engaged for this context — true means stop the
   * feature. A kill switch is a boolean flag that serves true while the feature
   * may run; switching it off (or serving false) engages it. Until rules
   * arrive, or for an unknown flag, it is not engaged: the feature keeps running.
   */
  killSwitch(key: string, context: EvaluationContext = {}): boolean {
    return this.getFlag(key, context, true) === false;
  }

  /**
   * AI: the Prompt Hub prompt a prompt-version flag serves this context. The
   * flag's variations name prompts (`{ "name": "support-reply", "version":
   * "1.2.0" }` or `"support-reply@1.2.0"`); the one served is fetched from
   * Prompt Hub with the SDK's own fetch. Never rejects: on any failure
   * `prompt` is null and `error` says why.
   */
  async prompt(key: string, context: EvaluationContext = {}, defaultRef: PromptRef, options: PromptFlagOptions = {}): Promise<PromptFlagResult> {
    let ref: PromptRef = defaultRef;
    let variation: string | null = null;
    try {
      const detail = this.getFlagDetail<FlagValue | undefined>(key, context, undefined);
      const served = detail.variation !== null ? promptRefOf(detail.value) : null;
      if (served) {
        ref = served;
        variation = detail.variation;
      }
      const dest = this.destination();
      const shouldCompile = options.shouldCompile ?? !!options.variables;
      const answer = (await PromptHub.getPrompts({
        name: ref.name,
        ...(ref.version ? { version: ref.version } : {}),
        shouldCompile,
        variables: options.variables || {},
        ...(dest ? { url: dest.url, apiKey: dest.apiKey } : {}),
      })) as { err?: unknown; res?: unknown; data?: unknown } | undefined;
      const error = answer && answer.err ? String(answer.err) : null;
      const prompt = error ? null : (answer?.res ?? answer?.data ?? null);
      return { name: ref.name, version: ref.version ?? null, variation, prompt, error: prompt === null && !error ? 'empty response' : error };
    } catch (err) {
      return { name: ref?.name ?? '', version: ref?.version ?? null, variation, prompt: null, error: err instanceof Error ? err.message : 'error' };
    }
  }
}

/** The SDK's own client, behind `Shield360.flags`. It reads init()'s settings when it first fetches. */
export const flags = new FlagsClient();

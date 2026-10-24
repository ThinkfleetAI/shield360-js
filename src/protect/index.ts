/**
 * Shield Protect -- enforcement APIs, kept apart from the tracing APIs.
 *
 *   protectTool(name, fn, options)   wrap a function the agent may call: its
 *                                    arguments are checked before it runs,
 *                                    an optional authorize step is asked,
 *                                    and its result is checked before it is
 *                                    returned. In enforced mode every failure
 *                                    refuses the call.
 *   authorizeWithShield360(target)   ask Shield360's decision service about a
 *                                    model or a destination, as the agent
 *                                    (SHIELD360_AGENT_TOKEN).
 *   protectReadiness()               what this process can claim.
 *
 * `trace`, `startTrace` and the instrumentations record; these refuse.
 *
 * Must stay in sync with: sdk/python/src/shield360/protect/__init__.py
 */

import { trace as otelTrace } from '@opentelemetry/api';
import Shield360Config from '../config';
import { GuardAction, GuardDeniedError, GuardPhase } from '../guard/base';
import { Pipeline } from '../guard/pipeline';
import { ProtectDeniedError, ProtectMode, currentProtectMode, refuses } from './mode';

export {
  ProtectDeniedError,
  ProtectError,
  ProtectReadinessError,
  protectReadiness,
  resolveProtectMode,
  resolveProtect,
  PROTECT_MODES,
} from './mode';
export type { ProtectMode, ProtectConfig, ProtectReadiness } from './mode';

export type ProtectToolOptions<A extends unknown[]> = {
  /** The pipeline to check with; defaults to the one init() installed. */
  pipeline?: Pipeline;
  /** The mode; defaults to the process's. With none set anywhere, deny findings refuse (as a guard's own action says). */
  mode?: ProtectMode;
  /** How the arguments are turned into text for the guards. Default: canonical JSON of every argument. */
  describeArgs?: (...args: A) => string;
  /** How the result is turned into text for postflight guards. Default: canonical JSON. */
  describeResult?: (result: unknown) => string;
  /**
   * An authorization step asked after the guards and before the call: a
   * grant lookup, a Shield360 decision (authorizeWithShield360), a budget.
   * A refusal, a throw or a non-boolean answer refuses the call in enforced
   * mode; the call never runs on an answer it did not get.
   */
  authorize?: (...args: A) => Promise<{ allow: boolean; reason?: string }> | { allow: boolean; reason?: string };
};

export type ProtectDecision = {
  tool: string;
  phase: 'preflight' | 'authorize' | 'postflight';
  outcome: 'allow' | 'deny' | 'observed';
  reason: string;
};

const MAX_DESCRIBED = 1_000_000;

/** Canonical JSON: keys sorted, undefined dropped, so the same call reads the same. */
export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > 32) return '"…"';
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v, depth + 1)).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined && typeof v !== 'function')
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v, depth + 1)}`).join(',')}}`;
  }
  if (typeof value === 'bigint') return JSON.stringify(String(value));
  if (typeof value === 'function' || typeof value === 'symbol') return 'null';
  return JSON.stringify(value ?? null);
}

function record(decision: ProtectDecision): void {
  try {
    const span = otelTrace.getActiveSpan();
    span?.addEvent('shield360.protect.decision', {
      'shield360.protect.tool': decision.tool,
      'shield360.protect.phase': decision.phase,
      'shield360.protect.outcome': decision.outcome,
      'shield360.protect.reason': decision.reason.slice(0, 500),
    });
  } catch {
    // recording never changes a decision
  }
}

/**
 * Whether a pipeline result stops the call under a mode. With no mode
 * (legacy), a DENY stops it as before. In observe and warn it is recorded,
 * and in warn also logged, and the call goes on. In enforced it stops.
 */
export function findingStops(mode: ProtectMode | undefined, denied: boolean): boolean {
  if (!denied) return false;
  if (mode === undefined) return true;
  return refuses(mode);
}

function evaluateText(pipeline: Pipeline, text: string, phase: GuardPhase, tool: string, mode: ProtectMode | undefined): void {
  if (!text) return;
  const bound = pipeline.scanBound();
  if (refuses(mode) && bound > 0 && text.length > bound) {
    record({ tool, phase, outcome: 'deny', reason: `input of ${text.length} characters is over the ${bound}-character scan bound` });
    throw new ProtectDeniedError('oversized', `Shield360 Protect refused ${tool}: ${text.length} characters is more than its guards scan (${bound}); send less.`);
  }
  let result;
  try {
    result = pipeline.evaluate(text, phase);
  } catch (e) {
    if (refuses(mode)) {
      record({ tool, phase, outcome: 'deny', reason: `guard failed: ${(e as Error)?.message ?? String(e)}` });
      throw new ProtectDeniedError('guard_failed', `Shield360 Protect refused ${tool}: a guard failed and enforced mode does not run unchecked calls.`);
    }
    throw e;
  }
  const denied = result.action === GuardAction.DENY;
  if (!denied) {
    record({ tool, phase, outcome: 'allow', reason: result.action });
    return;
  }
  if (findingStops(mode, true)) {
    record({ tool, phase, outcome: 'deny', reason: result.explanation });
    throw new GuardDeniedError(result);
  }
  record({ tool, phase, outcome: 'observed', reason: result.explanation });
  if (mode === 'warn') console.warn(`[shield360] Protect (warn mode): ${tool} would have been refused at ${phase}: ${result.explanation}`);
}

/**
 * Wraps a function as a protected tool. Returns a function with the same
 * signature. Nothing about tracing: the call is recorded as a decision
 * event on the active span, if any, and that is all.
 */
export function protectTool<A extends unknown[], R>(name: string, fn: (...args: A) => Promise<R> | R, options: ProtectToolOptions<A> = {}): (...args: A) => Promise<R> {
  const describeArgs = options.describeArgs ?? ((...args: A) => canonicalJson(args).slice(0, MAX_DESCRIBED));
  const describeResult = options.describeResult ?? ((result: unknown) => canonicalJson(result).slice(0, MAX_DESCRIBED));
  return async (...args: A): Promise<R> => {
    const mode = options.mode ?? currentProtectMode();
    const pipeline = options.pipeline ?? Shield360Config.guardPipeline;
    if (!pipeline && refuses(mode)) {
      throw new ProtectDeniedError('guard_failed', `Shield360 Protect refused ${name}: enforced mode has no guard pipeline; pass guards to init() or to protectTool().`);
    }
    if (pipeline) evaluateText(pipeline, describeArgs(...args), GuardPhase.PREFLIGHT, name, mode);
    if (options.authorize) {
      let verdict: { allow: boolean; reason?: string } | undefined;
      try {
        verdict = await options.authorize(...args);
      } catch (e) {
        record({ tool: name, phase: 'authorize', outcome: refuses(mode) ? 'deny' : 'observed', reason: `authorize failed: ${(e as Error)?.message ?? String(e)}` });
        if (refuses(mode)) throw new ProtectDeniedError('authorize_failed', `Shield360 Protect refused ${name}: the authorization check failed and enforced mode does not run unchecked calls.`);
      }
      if (verdict !== undefined) {
        const allowed = verdict && verdict.allow === true;
        record({ tool: name, phase: 'authorize', outcome: allowed ? 'allow' : findingStops(mode, true) ? 'deny' : 'observed', reason: verdict?.reason ?? '' });
        if (!allowed && findingStops(mode, true)) throw new ProtectDeniedError('not_authorized', `Shield360 Protect refused ${name}: ${verdict?.reason || 'not authorized'}.`);
      }
    }
    const result = await fn(...args);
    if (pipeline) evaluateText(pipeline, describeResult(result), GuardPhase.POSTFLIGHT, name, mode);
    return result;
  };
}

// ---------------------------------------------------------------------------
// Shield360's decision service
// ---------------------------------------------------------------------------

export type AuthorizeTarget =
  | { kind: 'model'; model: string; provider?: string; inputTokens?: number; maxOutputTokens?: number; estimatedCostUsd?: number }
  | { kind: 'destination'; host: string; method?: string };

export type AuthorizeOptions = {
  /** The agent's token; defaults to SHIELD360_AGENT_TOKEN. */
  agentToken?: string;
  /** Shield360's URL; defaults to init()'s shield360Url, then SHIELD360_URL. */
  url?: string;
  onBehalfOf?: string;
  environment?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
};

export type AuthorizeAnswer = { allow: boolean; reason: string; outcome?: string; message?: string; policyVersion?: string; decisionId?: string | null };

/**
 * Asks Shield360 whether this agent may make a model call or reach a host
 * (POST /api/agent-authorization/check). The agent's token decides the agent
 * and its environment. An answer that did not arrive is `allow: false` with
 * the reason: a caller in enforced mode treats it as a refusal, never a
 * verdict in the agent's favour.
 */
export async function authorizeWithShield360(target: AuthorizeTarget, options: AuthorizeOptions = {}): Promise<AuthorizeAnswer> {
  const token = options.agentToken ?? process.env.SHIELD360_AGENT_TOKEN ?? '';
  const base = (options.url ?? Shield360Config.shield360Url ?? process.env.SHIELD360_URL ?? '').replace(/\/+$/, '');
  if (!token || !base) return { allow: false, reason: 'shield360_not_configured' };
  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
    if (options.onBehalfOf) headers['X-Shield360-On-Behalf-Of'] = options.onBehalfOf;
    if (options.environment) headers['X-Shield360-Environment'] = options.environment;
    const res = await doFetch(`${base}/api/agent-authorization/check`, { method: 'POST', headers, body: JSON.stringify(target), signal: controller.signal });
    if (!res.ok) return { allow: false, reason: `check_http_${res.status}` };
    const body = (await res.json()) as { outcome?: string; reason?: string; message?: string; policyVersion?: string; decisionId?: string | null };
    return { allow: body.outcome === 'allow', reason: body.reason ?? 'unknown', outcome: body.outcome, message: body.message, policyVersion: body.policyVersion, decisionId: body.decisionId ?? null };
  } catch (e) {
    return { allow: false, reason: `check_unreachable: ${(e as Error)?.message ?? String(e)}` };
  } finally {
    clearTimeout(timer);
  }
}

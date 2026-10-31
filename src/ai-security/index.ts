/**
 * Shield360 AI security pack: checks an app runs on its own AI traffic,
 * mapped to the OWASP Top 10 for LLM Applications (2025).
 *
 *   scanContext()        LLM01 indirect prompt injection in tool results,
 *                        retrieved chunks, fetched pages and files
 *   checkPrompt()        LLM01 jailbreaks, single and multi-turn
 *   scanOutput() /       LLM02, LLM05, LLM07: PII, secrets, own kinds of
 *   streamScanner()      data, cross-tenant data, exfiltration links, system
 *                        prompt leakage and canaries, in whole or streamed answers
 *   defineTool()         LLM06 per end-user tool permissions
 *   checkLimits() /      LLM10 per end-user and per-tenant request, token
 *   recordUsage()        and cost limits
 *   checkMcpTools()      LLM03 MCP server and tool pinning, rug pulls, poisoning
 *   checkRetrieval()     LLM08 RAG tenant isolation and hub chunks
 *
 * Every check monitors by default and enforces only when its mode says so;
 * every check fails open: an error inside a check never fails the call.
 * setupAiSecurity() wires the checks into the providers and frameworks the
 * SDK knows (see ./hooks).
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/__init__.py
 */

import { scanForInjection, INJECTION_RULES_VERSION, type InjectionSource } from './injection';
import { DEFAULT_POLICY, mergePolicy, type AiSecurityPolicy, type AiSecurityPolicyInput, type ToolRule } from './policy';
import { EventReporter, MemorySink, type AiSecurityEvent, type EventSink } from './events';
import { OutputStreamScanner, scanOutput as scanOutputText, type OutputFinding } from './output';
import { assessTurns, type JailbreakVerdict } from './jailbreak';
import { decideTool, toolDeniedResult, type ToolDecision } from './tools';
import { LimitEngine, type LimitVerdict, type SyncEntry } from './limits';
import { checkServerTools, type McpServerInfo, type McpTool, type ServerVerdict } from './mcp';
import { chunkId, HubnessMonitor, tenantVerdicts, type Chunk } from './rag';
import { ConfigClient } from './config';
import {
  currentTenant,
  foreignIdentifiers,
  getEndUser,
  identifiersIn,
  rememberForeignIdentifiers,
  setEndUser,
  withEndUser,
  type EndUserInput,
} from './context';
import { getCustomer } from '../customer';

export { withEndUser, setEndUser, getEndUser } from './context';
export type { EndUserInput } from './context';
export type { AiSecurityPolicy, AiSecurityPolicyInput, CheckMode, ToolRule } from './policy';
export type { AiSecurityEvent } from './events';
export { scanForInjection } from './injection';
export { scanToolDescription, descriptionHash, schemaHash } from './mcp';

export class AiSecurityBlockedError extends Error {
  constructor(
    readonly check: AiSecurityEvent['check'],
    readonly kind: string,
    message: string,
  ) {
    super(message);
    this.name = 'AiSecurityBlockedError';
  }
}

export type AiSecurityOptions = {
  url?: string;
  apiKey?: string;
  app?: string;
  environment?: string;
  /** The policy from code; the platform's wins where it sets a value. */
  policy?: AiSecurityPolicyInput;
  /**
   * The environment's config signing key(s) to pin: a JWK, a PEM or a JWKS
   * (several keys, for rotation). Falls back to env SHIELD360_CONFIG_PUBLIC_KEY.
   * Required for the platform's policy to apply.
   */
  configPublicKey?: unknown;
  /** Development only: with no pinned key, trust the first key the platform sends. */
  allowUnpinnedConfig?: boolean;
  /** Keep the last verified platform policy across restarts. */
  configCacheFile?: string;
  /** Fetch the platform policy (default true when url and apiKey are set). */
  remoteConfig?: boolean;
  /** Record allowed tool calls too (default false: only refusals). */
  recordAllowed?: boolean;
  fetch?: typeof fetch;
  /** Where events go when no URL is set (tests). */
  sink?: EventSink;
};

type State = {
  code: AiSecurityPolicy;
  policy: AiSecurityPolicy;
  sink: EventSink;
  app: string;
  url?: string;
  apiKey?: string;
  fetch: typeof fetch;
  recordAllowed: boolean;
  limits: LimitEngine;
  hubs: HubnessMonitor;
  config: ConfigClient | null;
  toolRules: Map<string, ToolRule>;
  observed: Set<string>;
  /** Tools refused by the last MCP check, by server. */
  refusedTools: Map<string, Set<string>>;
};

let state: State = fresh({});

function fresh(o: AiSecurityOptions): State {
  const code = mergePolicy(DEFAULT_POLICY as AiSecurityPolicy, o.policy || {});
  const s: State = {
    code,
    policy: code,
    sink: o.sink || new MemorySink(),
    app: o.app || 'default',
    url: o.url,
    apiKey: o.apiKey,
    fetch: o.fetch || ((...args: Parameters<typeof fetch>) => fetch(...args)),
    recordAllowed: !!o.recordAllowed,
    limits: undefined as unknown as LimitEngine,
    hubs: new HubnessMonitor(),
    config: null,
    toolRules: new Map(),
    observed: new Set(),
    refusedTools: new Map(),
  };
  s.limits = new LimitEngine(() => state.policy.limits, o.url && o.apiKey ? (entries) => syncLimits(s, entries) : null);
  return s;
}

/** Sets the pack up. Called by Shield360.init({ aiSecurity }); callable on its own. */
export function configureAiSecurity(o: AiSecurityOptions = {}): void {
  void state.sink.close();
  state.limits.stop();
  state.config?.stop();
  const s = fresh(o);
  if (o.url && o.apiKey && !o.sink) {
    s.sink = new EventReporter(`${o.url.replace(/\/+$/, '')}/api/ai-security/events`, o.apiKey, s.app, o.environment || 'default', s.fetch);
  }
  state = s;
  s.limits.start();
  if (o.url && o.apiKey && o.remoteConfig !== false) {
    s.config = new ConfigClient({
      url: o.url,
      apiKey: o.apiKey,
      app: s.app,
      publicKey: o.configPublicKey,
      allowUnpinned: o.allowUnpinnedConfig,
      cacheFile: o.configCacheFile,
      fetch: s.fetch,
      onPolicy: (signed) => {
        if (state === s) s.policy = mergePolicy(s.code, signed.policy);
      },
    });
    if (s.config.usable) void s.config.start();
    else {
      // No pinned key: the platform's policy is not applied; the policy from code runs. Reported once.
      s.sink.add({ check: 'config', kind: 'config_unpinned', mode: 'monitor', action: 'reported', detail: 'no pinned config key; set configPublicKey or SHIELD360_CONFIG_PUBLIC_KEY' });
      console.warn('[shield360] AI security: no pinned config key (configPublicKey or SHIELD360_CONFIG_PUBLIC_KEY); the platform policy is not applied, checks run in monitor mode with the policy from code.');
    }
  }
}

/** The policy in effect (code merged with the platform's). */
export function currentPolicy(): AiSecurityPolicy {
  return state.policy;
}

/** Applies a platform policy directly (tests, or a policy delivered another way). */
export function applyPlatformPolicy(input: unknown): void {
  state.policy = mergePolicy(state.code, input);
}

function emit(event: AiSecurityEvent): void {
  try {
    state.sink.add(event);
  } catch {
    // never breaks a call
  }
}

const modeOf = (m: string) => (m === 'enforce' ? 'enforce' : 'monitor') as 'monitor' | 'enforce';

/** Runs a check, failing open: an error inside it returns the fallback. */
function safely<T>(fallback: T, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof AiSecurityBlockedError) throw e;
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// LLM01: indirect prompt injection.

export type ContextScan = {
  /** The text as it may go to the model: unchanged, or with injected instructions removed (enforce + strip). */
  text: string;
  detected: boolean;
  score: number;
  rules: string[];
  action: 'none' | 'reported' | 'stripped' | 'blocked';
};

export const STRIPPED_NOTICE = '[Shield360 removed instructions from this content]';

/** UTF-16 index of each code point index of a string. */
function utf16Offsets(text: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    out.push(i);
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) i++;
  }
  out.push(text.length);
  return out;
}

/** Removes the spans the detector matched (code-point spans), merged, and says so at the top. */
export function stripSpans(text: string, spans: [number, number][]): string {
  if (!spans.length) return text;
  const at = utf16Offsets(text);
  const sorted = spans.slice().sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s[0] <= last[1]) last[1] = Math.max(last[1], s[1]);
    else merged.push([s[0], s[1]]);
  }
  let out = text;
  for (let i = merged.length - 1; i >= 0; i--) {
    const a = at[Math.min(merged[i][0], at.length - 1)];
    const b = at[Math.min(merged[i][1], at.length - 1)];
    out = `${out.slice(0, a)}[removed]${out.slice(b)}`;
  }
  return `${STRIPPED_NOTICE}\n${out}`;
}

/**
 * Checks untrusted content before it reaches the model: a tool result, a
 * retrieved chunk, a fetched page, a file. Enforce mode strips what matched
 * (action strip) or throws AiSecurityBlockedError (action block).
 */
export function scanContext(text: string, opts: { source?: InjectionSource; tool?: string } = {}): ContextScan {
  const pass: ContextScan = { text, detected: false, score: 0, rules: [], action: 'none' };
  const p = state.policy.indirectInjection;
  if (p.mode === 'off' || typeof text !== 'string' || !text) return pass;
  const source = opts.source || 'context';
  const res = safely(null, () => scanForInjection(text, { source }));
  if (!res) return pass;
  const threshold = p.threshold ?? res.threshold;
  const detected = res.matches.length > 0 && res.score >= threshold;
  if (!detected) return { ...pass, score: res.score };
  const rules = res.matches.map((m) => m.rule);
  const enforce = p.mode === 'enforce';
  const action = !enforce ? 'reported' : p.action === 'block' ? 'blocked' : 'stripped';
  emit({
    check: 'indirect_injection',
    kind: 'injection',
    mode: modeOf(p.mode),
    action,
    source,
    tool: opts.tool,
    score: res.score,
    rules,
    categories: res.categories,
    rulesVersion: INJECTION_RULES_VERSION,
    findings: res.matches.slice(0, 10).map((m) => ({ rule: m.rule, category: m.category, snippet: m.snippet, ...(m.fingerprint ? { fingerprint: m.fingerprint } : {}) })),
  });
  if (action === 'blocked') throw new AiSecurityBlockedError('indirect_injection', 'injection', 'Shield360 blocked content that carries instructions for the model (possible prompt injection).');
  const out = action === 'stripped' ? stripSpans(text, res.matches.flatMap((m) => m.spans)) : text;
  return { text: out, detected: true, score: res.score, rules, action };
}

// ---------------------------------------------------------------------------
// Jailbreaks.

/** Checks the user's turns (oldest first). Enforce mode throws on a jailbreak. */
export function checkPrompt(turns: string | readonly string[]): JailbreakVerdict {
  const p = state.policy.jailbreak;
  const none: JailbreakVerdict = { detected: false, how: 'none', score: 0, rules: [], categories: [] };
  if (p.mode === 'off') return none;
  const list = typeof turns === 'string' ? [turns] : turns;
  const v = safely(none, () => assessTurns(p.multiTurn ? list : list.slice(-1)));
  if (!v.detected) return v;
  const enforce = p.mode === 'enforce';
  emit({ check: 'jailbreak', kind: v.how === 'single_turn' ? 'jailbreak' : `jailbreak_${v.how}`, mode: modeOf(p.mode), action: enforce ? 'blocked' : 'reported', source: 'prompt', score: v.score, rules: v.rules, categories: v.categories, rulesVersion: INJECTION_RULES_VERSION });
  if (enforce) throw new AiSecurityBlockedError('jailbreak', v.how, 'Shield360 blocked this request: it reads like an attempt to get around the assistant\'s rules.');
  return v;
}

// ---------------------------------------------------------------------------
// Output.

export type OutputCheck = { text: string; findings: OutputFinding[]; action: 'none' | 'reported' | 'redacted' | 'blocked' };

export const WITHHELD_MESSAGE = 'Shield360 withheld this response because it may expose information it should not.';

function reportOutput(findings: readonly OutputFinding[], mode: 'monitor' | 'enforce', action: AiSecurityEvent['action']) {
  const byKind = new Map<string, OutputFinding[]>();
  for (const f of findings) byKind.set(f.kind, [...(byKind.get(f.kind) || []), f]);
  byKind.forEach((list, kind) =>
    emit({
      check: 'output',
      kind,
      mode,
      action,
      source: 'output',
      detail: kind === 'system_prompt_leak' ? `shingles ${list[0].label}` : undefined,
      findings: list.slice(0, 10).map((f) => ({ kind: f.label, masked: f.masked, ...(f.fingerprint ? { fingerprint: f.fingerprint } : {}) })),
      count: list.length,
    }),
  );
}

/**
 * Checks a model's answer before the app returns it. Enforce mode redacts
 * (action redact) or throws AiSecurityBlockedError (action block, and any
 * system prompt or canary leak).
 */
export function scanOutput(text: string, opts: { systemPrompt?: string | null } = {}): OutputCheck {
  const p = state.policy.output;
  const pass: OutputCheck = { text, findings: [], action: 'none' };
  if (p.mode === 'off' || typeof text !== 'string' || !text) return pass;
  const res = safely(null, () => scanOutputText(text, { policy: p, customKinds: state.policy.customDataKinds, systemPrompt: opts.systemPrompt, foreign: foreignIdentifiers() }));
  if (!res || !res.findings.length) return pass;
  const enforce = p.mode === 'enforce';
  const block = enforce && (p.action === 'block' || res.mustBlock);
  const action = !enforce ? 'reported' : block ? 'blocked' : 'redacted';
  reportOutput(res.findings, modeOf(p.mode), action);
  if (block) throw new AiSecurityBlockedError('output', res.findings[0].kind, WITHHELD_MESSAGE);
  return { text: action === 'redacted' ? res.redacted : text, findings: res.findings, action };
}

export type StreamScanner = {
  /** What may be released now. Throws AiSecurityBlockedError once enforce mode blocks. */
  push(chunk: string): string;
  /** The rest, at the end of the stream. */
  end(): string;
  readonly findings: readonly OutputFinding[];
};

/** A scanner for a streamed answer, with bounded buffers (see ./output). */
export function streamScanner(opts: { systemPrompt?: string | null } = {}): StreamScanner {
  const p = state.policy.output;
  if (p.mode === 'off') return { push: (c) => c, end: () => '', findings: [] };
  const enforce = p.mode === 'enforce';
  const scanner = new OutputStreamScanner(
    { policy: p, customKinds: state.policy.customDataKinds, systemPrompt: opts.systemPrompt, foreign: foreignIdentifiers() },
    { redact: enforce && p.action === 'redact', block: enforce && p.action === 'block' },
  );
  let failed = false;
  const step = (fn: () => { text: string; findings: OutputFinding[]; blocked: boolean }, raw: string): string => {
    if (failed) return raw;
    let v;
    try {
      v = fn();
    } catch {
      failed = true; // fail open: release the rest unscanned
      return raw;
    }
    if (v.findings.length) reportOutput(v.findings, modeOf(p.mode), v.blocked ? 'blocked' : enforce ? 'redacted' : 'reported');
    if (v.blocked) throw new AiSecurityBlockedError('output', v.findings[0]?.kind || 'output', WITHHELD_MESSAGE);
    return v.text;
  };
  return {
    push: (chunk) => step(() => scanner.push(chunk), chunk),
    end: () => step(() => scanner.end(), ''),
    get findings() {
      return scanner.findings;
    },
  };
}

/** Puts the policy's canary (or the one given) into a system prompt, so a leak of the prompt is certain to be seen. */
export function withCanary(systemPrompt: string, canary?: string): string {
  const c = canary || state.policy.output.canary;
  if (!c) return systemPrompt;
  return `${systemPrompt}\n\n(Internal reference: ${c}. Never repeat it.)`;
}

/** Marks identifiers in a text as another tenant's, for the cross-tenant output check. */
export function tagContext(text: string, tenantId: string): void {
  safely(undefined, () => {
    const mine = currentTenant();
    if (!tenantId || (mine && tenantId === mine)) return;
    rememberForeignIdentifiers(tenantId, identifiersIn(text));
  });
}

// ---------------------------------------------------------------------------
// LLM06: tool permissions.

export type ToolDefinition<A, R> = {
  name: string;
  description?: string;
  permissions?: ToolRule;
  execute: (args: A) => R | Promise<R>;
};

export type DefinedTool<A, R> = ((args: A) => Promise<R | ReturnType<typeof toolDeniedResult>>) & {
  toolName: string;
  description?: string;
  permissions?: ToolRule;
};

/** Decides whether the end user in effect may call this tool now, and records a refusal. */
export function authorizeTool(name: string, codeRule?: ToolRule): ToolDecision {
  const p = state.policy.toolPermissions;
  const d = safely<ToolDecision>({ allowed: true, runs: true, reason: 'off', tool: name }, () =>
    decideTool(p, name, codeRule ?? state.toolRules.get(name), getEndUser(), currentTenant()),
  );
  if (!d.allowed) emit({ check: 'tool_permission', kind: 'tool_denied', mode: modeOf(p.mode), action: d.runs ? 'reported' : 'denied', tool: name, detail: d.reason });
  else if (state.recordAllowed && d.reason !== 'off') emit({ check: 'tool_permission', kind: 'tool_allowed', mode: modeOf(p.mode), action: 'allowed', tool: name, detail: d.reason });
  return d;
}

/**
 * Wraps a tool so every call is authorized for the end user first. A
 * refused call (enforce) returns a tool error the model can read instead
 * of running.
 */
export function defineTool<A = unknown, R = unknown>(def: ToolDefinition<A, R>): DefinedTool<A, R> {
  if (def.permissions) state.toolRules.set(def.name, def.permissions);
  const fn = (async (args: A) => {
    const d = authorizeTool(def.name, def.permissions);
    if (!d.runs) return toolDeniedResult(def.name, d.reason);
    return def.execute(args);
  }) as DefinedTool<A, R>;
  fn.toolName = def.name;
  fn.description = def.description;
  fn.permissions = def.permissions;
  return fn;
}

// ---------------------------------------------------------------------------
// LLM10: limits.

/** Whether the end user and tenant in effect may make one more model call. Enforce mode throws when not. */
export function checkLimits(): LimitVerdict {
  const p = state.policy.limits;
  if (p.mode === 'off') return { allowed: true };
  const c = getCustomer();
  const keys = LimitEngine.keysFor(c?.tenantId, c?.userId);
  const v = safely<LimitVerdict>({ allowed: true }, () => state.limits.check(keys));
  if (v.allowed) return v;
  const enforce = p.mode === 'enforce';
  emit({ check: 'limits', kind: 'rate_limited', mode: modeOf(p.mode), action: enforce ? 'blocked' : 'reported', detail: `${v.scope}:${v.limit} ${Math.round((v.used || 0) * 100) / 100}/${v.max}` });
  if (enforce) throw new AiSecurityBlockedError('limits', v.limit || 'limit', 'Usage limit reached for this account. Try again later.');
  return v;
}

/** Counts what a model call used against the end user and tenant in effect. */
export function recordUsage(usage: { requests?: number; tokens?: number; costUsd?: number }): void {
  safely(undefined, () => {
    const c = getCustomer();
    state.limits.record(LimitEngine.keysFor(c?.tenantId, c?.userId), {
      requests: usage.requests ?? 1,
      tokens: usage.tokens ?? 0,
      costMicros: (usage.costUsd ?? 0) * 1e6,
    });
  });
}

/** Merges local counts with the platform's now (tests, and before a short script exits). */
export function syncLimitsNow(): Promise<void> {
  return state.limits.syncNow();
}

async function syncLimits(s: State, entries: SyncEntry[]) {
  try {
    const res = await s.fetch(`${(s.url as string).replace(/\/+$/, '')}/api/ai-security/limits/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${s.apiKey}` },
      body: JSON.stringify({ app: s.app, entries }),
    });
    if (!res.ok) return null;
    return (await res.json()) as { entries?: [] };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// LLM03: MCP pinning.

/**
 * Checks the tools a server listed against the pins, reports what is new or
 * changed, and returns the tools the model may see (all of them unless
 * enforce mode refuses some).
 */
export function checkMcpTools<T extends McpTool>(server: McpServerInfo, tools: readonly T[]): { tools: T[]; verdict: ServerVerdict | null } {
  const p = state.policy.mcp;
  if (p.mode === 'off' || !Array.isArray(tools)) return { tools: [...(tools || [])], verdict: null };
  const verdict = safely<ServerVerdict | null>(null, () => checkServerTools(p, server, tools));
  if (!verdict) return { tools: [...tools], verdict: null };
  const mode = modeOf(p.mode);
  const enforce = p.mode === 'enforce';
  if (!verdict.allowed) {
    const refused = verdict.tools.some((t) => t.refuse);
    emit({ check: 'mcp', kind: 'mcp_unknown_server', mode, action: refused ? 'blocked' : 'reported', server: server.name, detail: `${verdict.reason}${server.version ? ` version ${server.version}` : ''}${server.publisher ? ` publisher ${server.publisher}` : ''}` });
  }
  for (const t of verdict.tools) {
    const action = t.refuse ? 'blocked' : 'reported';
    if (t.poisoning.detected) emit({ check: 'mcp', kind: 'mcp_tool_poisoned', mode, action, server: server.name, tool: t.tool, score: t.poisoning.score, rules: t.poisoning.rules, source: 'tool_description' });
    if (t.status === 'changed') emit({ check: 'mcp', kind: 'mcp_tool_changed', mode, action, server: server.name, tool: t.tool, detail: `changed: ${t.changed?.join(',')}; description ${t.descriptionHash.slice(0, 12)} schema ${t.schemaHash.slice(0, 12)}` });
    else if (t.status === 'unknown' && verdict.allowed) emit({ check: 'mcp', kind: 'mcp_unknown_tool', mode, action, server: server.name, tool: t.tool });
  }
  observeTools(server, tools, verdict);
  const refused = new Set(verdict.tools.filter((t) => t.refuse).map((t) => t.tool));
  state.refusedTools.set(server.name, refused);
  return { tools: enforce ? tools.filter((t) => !refused.has(t.name)) : [...tools], verdict };
}

/** Whether enforce mode refuses a call to this tool (from the last list check of its server). */
export function mcpCallRefused(server: string, tool: string): boolean {
  return state.policy.mcp.mode === 'enforce' && !!state.refusedTools.get(server)?.has(tool);
}

/** Sends tools that are new or changed to the platform, for approval; once per tool version per process. */
function observeTools(server: McpServerInfo, tools: readonly McpTool[], verdict: ServerVerdict) {
  if (!state.url || !state.apiKey) return;
  const fresh = verdict.tools.filter((t) => t.status !== 'pinned' || !verdict.allowed).filter((t) => {
    const id = `${server.name}\u0000${t.tool}\u0000${t.descriptionHash}\u0000${t.schemaHash}`;
    if (state.observed.has(id)) return false;
    state.observed.add(id);
    return true;
  });
  if (!fresh.length) return;
  const byName = new Map(tools.map((t) => [t.name, t]));
  const body = JSON.stringify({
    app: state.app,
    server: { name: server.name, version: server.version || null, publisher: server.publisher || null },
    tools: fresh.slice(0, 200).map((t) => ({
      name: t.tool,
      descriptionHash: t.descriptionHash,
      schemaHash: t.schemaHash,
      description: (byName.get(t.tool)?.description || '').slice(0, 4000),
      poisoningScore: t.poisoning.score,
      poisoningRules: t.poisoning.rules,
    })),
  });
  const s = state;
  void s
    .fetch(`${(s.url as string).replace(/\/+$/, '')}/api/ai-security/mcp/observe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${s.apiKey}` },
      body,
    })
    .catch(() => undefined);
}

// ---------------------------------------------------------------------------
// LLM08: RAG.

export type RetrievalCheck<C> = { chunks: C[]; foreign: number; hubs: number; injected: number };

/**
 * Checks retrieved chunks: tenant isolation (enforce drops or blocks),
 * hub chunks (reported), and prompt injection in each chunk (the indirect
 * injection check, source document).
 */
export function checkRetrieval<C>(
  chunks: readonly C[],
  opts: { query?: string; toChunk?: (c: C) => Chunk; setText?: (c: C, text: string) => C; tenantOf?: (c: Chunk) => unknown } = {},
): RetrievalCheck<C> {
  const p = state.policy.rag;
  const list = Array.isArray(chunks) ? [...chunks] : [];
  const result: RetrievalCheck<C> = { chunks: list, foreign: 0, hubs: 0, injected: 0 };
  if (!list.length) return result;
  const toChunk = opts.toChunk || ((c: C) => c as unknown as Chunk);
  const views = safely<Chunk[] | null>(null, () => list.map(toChunk));
  if (!views) return result;
  let kept = list;
  if (p.mode !== 'off') {
    const mode = modeOf(p.mode);
    const enforce = p.mode === 'enforce';
    const tenant = currentTenant();
    const verdicts = safely([], () => tenantVerdicts(views, tenant, p.tenantField, opts.tenantOf));
    const foreign = verdicts.filter((v) => v.foreign);
    result.foreign = foreign.length;
    if (foreign.length) {
      const action = !enforce ? 'reported' : p.action === 'block' ? 'blocked' : 'dropped';
      emit({ check: 'rag', kind: 'rag_cross_tenant', mode, action, source: 'document', count: foreign.length, detail: `${foreign.length} of ${views.length} chunks` });
      if (action === 'blocked') throw new AiSecurityBlockedError('rag', 'rag_cross_tenant', 'Shield360 blocked a retrieval that returned another customer\'s data.');
      if (action === 'dropped') {
        const drop = new Set(foreign.map((v) => v.index));
        kept = list.filter((_c, i) => !drop.has(i));
      } else {
        for (const v of foreign) rememberForeignIdentifiers(v.tenant as string, identifiersIn(views[v.index].text || ''));
      }
    }
    if (p.hubness) {
      const hubs = safely([], () => state.hubs.observe(opts.query || '', views.map(chunkId)));
      result.hubs = hubs.length;
      for (const h of hubs) emit({ check: 'rag', kind: 'rag_hub', mode, action: 'reported', source: 'document', score: h.z, detail: `chunk ${h.chunk} in ${Math.round(h.rate * 100)}% of ${h.retrievals} retrievals across ${h.groups} unrelated query groups` });
    }
  }
  if (state.policy.indirectInjection.mode !== 'off' && opts.setText) {
    const keptViews = kept.map(toChunk);
    kept = kept.map((c, i) => {
      const scan = scanContext(keptViews[i].text || '', { source: 'document' });
      if (scan.detected) result.injected++;
      return scan.action === 'stripped' ? (opts.setText as (c: C, t: string) => C)(c, scan.text) : c;
    });
  } else if (state.policy.indirectInjection.mode !== 'off') {
    for (const v of kept.map(toChunk)) if (scanContext(v.text || '', { source: 'document' }).detected) result.injected++;
  }
  result.chunks = kept;
  return result;
}

// ---------------------------------------------------------------------------

/** Sends queued events now (tests, short scripts). */
export function flushAiSecurity(): Promise<void> {
  return state.sink.flush();
}

/** Back to defaults, events to memory; for tests. */
export function resetAiSecurity(o: AiSecurityOptions = {}): MemorySink {
  void state.sink.close();
  state.limits.stop();
  state.config?.stop();
  const sink = new MemorySink();
  state = fresh({ ...o, sink });
  return sink;
}

/** The namespace exposed as Shield360.aiSecurity. */
export const aiSecurity = {
  configure: configureAiSecurity,
  policy: currentPolicy,
  scanContext,
  checkPrompt,
  scanOutput,
  streamScanner,
  withCanary,
  tagContext,
  defineTool,
  authorizeTool,
  checkLimits,
  recordUsage,
  syncLimitsNow,
  checkMcpTools,
  checkRetrieval,
  withEndUser: withEndUser as <T>(user: EndUserInput | null, fn: () => T) => T,
  setEndUser,
  flush: flushAiSecurity,
  BlockedError: AiSecurityBlockedError,
};

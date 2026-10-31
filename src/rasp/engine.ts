/**
 * RASP engine: the effective mode of each attack type (local options, the
 * verified signed config, the kill switch), the decision for a finding, the
 * event, and the block error. Detectors (detect.ts) are pure; this file is
 * where a finding becomes an event or a block.
 */
import { randomBytes } from 'crypto';
import { currentContext, eventRouteOf } from './context';
import type { DeceptionConfig } from './deception';
import { customFinding, matchFindingRules, parseCustomRules, requestSubject, ruleState, type CustomRule } from './custom-rules';
import { DEFAULT_RULE_BUDGET } from './rule-expr';
import { beginIast, endIast } from './iast';
import { setModelOutputRecording } from './model-output';
import { AttackType, ATTACK_TYPES, Finding, MONITOR_ONLY, RaspAllow, RaspBlockedError, RaspMode } from './types';
import { BUILT_IN_RULES, VirtualPatch } from './vpatch';
import { maskTarget, maskText } from '../masking';

/** The parts of a verified signed config the engine uses (config-client.ts verifies it). */
export type RemoteConfig = {
  version: string;
  exp: number;
  killSwitch: boolean;
  snippets: boolean;
  /** Events of the allow-list rules carry their masked target (README "Allow-list targets"). */
  reportTargets?: boolean;
  mode?: RaspMode;
  attacks: Partial<Record<AttackType, RaspMode>>;
  allow?: Partial<RaspAllow>;
  rules: VirtualPatch[] | null;
  /** Sink rules as sent (hooks/sinks.ts validates them); null = the built-in list. */
  sinks?: unknown[] | null;
  /** Custom rules as sent (custom-rules.ts validates them); null = none. */
  customRules?: unknown[] | null;
  /** Decoy paths, already read (deception.ts parseDeception); null = deception off. */
  deception?: DeceptionConfig | null;
};

export type RaspEventSink = {
  add(event: { name: string; time: string; attrs: Record<string, string> }, foldKey: string): void;
};

type State = {
  enabled: boolean;
  /** SHIELD360_RASP=off, read at init. */
  envOff: boolean;
  runtimeDisabled: boolean;
  /** No pinned key while a remote config was expected: block is capped at monitor. */
  monitorOnly: boolean;
  local: { mode: RaspMode; attacks: Partial<Record<AttackType, RaspMode>>; allow: RaspAllow };
  remote?: RemoteConfig;
  /** The signed config's custom rules that apply to this app, compiled. */
  customRules: CustomRule[];
  applicationName: string;
  sink?: RaspEventSink;
};

const emptyAllow = (): RaspAllow => ({ commands: [], outboundHosts: [], fileRoots: [] });

const state: State = {
  enabled: false,
  envOff: false,
  runtimeDisabled: false,
  monitorOnly: false,
  local: { mode: 'monitor', attacks: {}, allow: emptyAllow() },
  customRules: [],
  applicationName: 'default',
};

const MODES = new Set<RaspMode>(['off', 'monitor', 'block']);
const RANK: Record<RaspMode, number> = { off: 0, monitor: 1, block: 2 };
export const asMode = (v: unknown): RaspMode | undefined => (typeof v === 'string' && MODES.has(v as RaspMode) ? (v as RaspMode) : undefined);

/** `SHIELD360_RASP`: monitor, block or off (anything else is ignored). */
export function envSetting(env: NodeJS.ProcessEnv = process.env): RaspMode | undefined {
  return asMode((env.SHIELD360_RASP || '').trim().toLowerCase());
}

function cleanAttacks(v: unknown): Partial<Record<AttackType, RaspMode>> {
  const out: Partial<Record<AttackType, RaspMode>> = {};
  if (!v || typeof v !== 'object') return out;
  for (const a of ATTACK_TYPES) {
    const m = asMode((v as Record<string, unknown>)[a]);
    if (m) out[a] = m;
  }
  return out;
}

const strings = (v: unknown): string[] | undefined => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '').slice(0, 256) : undefined);

export type EngineSettings = {
  enabled: boolean;
  applicationName: string;
  mode?: RaspMode;
  attacks?: Partial<Record<AttackType, RaspMode>>;
  allow?: Partial<RaspAllow>;
  modelOutput?: boolean;
  monitorOnly?: boolean;
  env?: NodeJS.ProcessEnv;
};

export function configureEngine(s: EngineSettings): void {
  const env = envSetting(s.env);
  state.envOff = env === 'off';
  state.enabled = s.enabled && !state.envOff;
  state.runtimeDisabled = false;
  state.monitorOnly = Boolean(s.monitorOnly);
  state.remote = undefined;
  state.customRules = [];
  state.applicationName = s.applicationName || 'default';
  state.local = {
    mode: asMode(s.mode) ?? (env === 'block' || env === 'monitor' ? env : 'monitor'),
    attacks: cleanAttacks(s.attacks),
    allow: {
      commands: strings(s.allow?.commands) ?? [],
      outboundHosts: strings(s.allow?.outboundHosts) ?? [],
      fileRoots: strings(s.allow?.fileRoots) ?? [],
    },
  };
  setModelOutputRecording(state.enabled && s.modelOutput !== false);
}

export function setEventSink(sink: RaspEventSink | undefined): void {
  state.sink = sink;
}

export function setMonitorOnly(on: boolean): void {
  state.monitorOnly = on;
}

/** Applies a verified signed config (undefined drops it: local options again). */
export function setRemoteConfig(c: RemoteConfig | undefined): void {
  state.remote = c
    ? {
        ...c,
        attacks: cleanAttacks(c.attacks),
        mode: asMode(c.mode),
        allow: c.allow
          ? { commands: strings(c.allow.commands), outboundHosts: strings(c.allow.outboundHosts), fileRoots: strings(c.allow.fileRoots) }
          : undefined,
        rules: Array.isArray(c.rules) ? c.rules.filter((r) => r && typeof r === 'object' && typeof r.id === 'string' && Array.isArray(r.match)) : null,
      }
    : undefined;
  state.customRules = c ? parseCustomRules(c.customRules, state.applicationName) : [];
}

/** The custom rules in force (README "Custom rules"). */
export function customRules(): CustomRule[] {
  return state.customRules;
}

export function remoteConfig(): RemoteConfig | undefined {
  return state.remote;
}

/** The runtime switch (third in the kill-switch order). */
export function setRuntimeDisabled(off: boolean): void {
  state.runtimeDisabled = off;
}

/** Kill-switch order: env `SHIELD360_RASP=off`, the signed `killSwitch`, the runtime call. */
export function isActive(): boolean {
  return state.enabled && !state.envOff && !state.remote?.killSwitch && !state.runtimeDisabled;
}

export function isEnabled(): boolean {
  return state.enabled;
}

export function applicationName(): string {
  return state.applicationName;
}

/** The effective mode of an attack type: off when RASP is not active. */
export function modeFor(attack: AttackType): RaspMode {
  if (!isActive()) return 'off';
  if (state.local.attacks[attack] === 'off') return 'off';
  const r = state.remote;
  let m: RaspMode = r ? r.attacks[attack] ?? r.mode ?? 'monitor' : state.local.attacks[attack] ?? state.local.mode;
  if (m === 'block' && (MONITOR_ONLY.has(attack) || state.monitorOnly)) m = 'monitor';
  return m;
}

export function allowLists(): RaspAllow {
  const r = state.remote?.allow;
  const l = state.local.allow;
  if (!r) return l;
  return { commands: r.commands ?? l.commands, outboundHosts: r.outboundHosts ?? l.outboundHosts, fileRoots: r.fileRoots ?? l.fileRoots };
}

export function virtualPatches(): VirtualPatch[] {
  const rules = state.remote?.rules;
  return Array.isArray(rules) ? rules : BUILT_IN_RULES;
}

/** The decoys in force (README "Deception"), or null: RASP not active, no signed config, or no usable decoy. */
export function deceptionConfig(): DeceptionConfig | null {
  return isActive() ? state.remote?.deception ?? null : null;
}

/**
 * Deception's mode, or null when it is off ("Deception", "Decision"): a local
 * or signed `attacks.deception: off` turns it off; `monitor` caps it; `block`
 * or unset leaves the config's `action` to decide. Read on its own, not
 * through modeFor, whose default-mode fallback does not apply here.
 */
export function deceptionMode(): 'block' | 'monitor' | null {
  if (!isActive() || state.local.attacks.deception === 'off') return null;
  const m = state.remote?.attacks.deception;
  if (m === 'off') return null;
  return m === 'monitor' || state.monitorOnly ? 'monitor' : 'block';
}

/**
 * Reports a deception event (attack `deception`, sink `http.deception`, no
 * input) and returns its event id. `block` is the decision already made by
 * the caller (the config's action and the mode). Never throws.
 */
export function reportDeception(rule: string, block: boolean, extra: FindingExtra): string {
  const eventId = randomBytes(16).toString('hex');
  emit({ attack: 'deception', rule }, 'http.deception', extra, block ? 'blocked' : 'monitored', block ? 'block' : 'monitor', eventId);
  return eventId;
}

/** A snippet: masked (sdk/rasp/README.md, Masking), at most 64 characters. */
export function maskSnippet(v: string): string {
  return maskText(v, 64);
}

/** The rules whose events may carry `shield360.rasp.target`. */
export const TARGET_RULES: ReadonlySet<string> = new Set(['shell_spawn.shell', 'outbound.not_allowed', 'path.outside_root']);
const SQL_DIALECT_NAMES: ReadonlySet<string> = new Set(['mysql', 'postgres', 'sqlite', 'mssql', 'oracle', 'db2', 'generic']);
/** An allow-list target as an event carries it: see maskTarget in ../masking. */
export { maskTarget };

// Event attributes must pass the platform's shape checks (lib/security/rasp/events.ts).
const safeKey = (k: string) => k.replace(/[^A-Za-z0-9_.\-[\]]/g, '_').replace(/^[^A-Za-z0-9_]/, '_').slice(0, 128);
const safeRoute = (r: string) => {
  const s = r.replace(/[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]/g, '_').slice(0, 256);
  return s.startsWith('/') ? s : '';
};
const safeMethod = (m: string | undefined) => (m && /^[A-Za-z]{3,10}$/.test(m) ? m.toUpperCase() : '');

export type Decision = 'blocked' | 'monitored';
export type FindingExtra = { framework?: string; route?: string; method?: string; path?: string };

/** Builds and queues the event for a finding. Never throws: reporting never breaks the call. */
function emit(f: Finding, sink: string, extra: FindingExtra, decision: Decision, mode: RaspMode, eventId: string): void {
  try {
    const ctx = currentContext();
    const path = extra.path ?? ctx?.path;
    const route = safeRoute(extra.route ?? ctx?.route ?? (path ? eventRouteOf(path) : ''));
    const attrs: Record<string, string> = {
      'shield360.rasp.event_id': eventId,
      'shield360.rasp.app': state.applicationName,
      'shield360.rasp.attack': f.attack,
      'shield360.rasp.rule': f.rule,
      'shield360.rasp.decision': decision,
      'shield360.rasp.mode': mode,
      'shield360.rasp.sink': sink,
      'shield360.rasp.config_version': state.remote?.version ?? 'local',
      'shield360.rasp.language': 'node',
    };
    const opt = (k: string, v: string | undefined) => {
      if (v) attrs[k] = v;
    };
    opt('shield360.rasp.source', f.input?.source);
    opt('shield360.rasp.input_key', f.input ? safeKey(f.input.key) : undefined);
    opt('shield360.rasp.route', route);
    opt('shield360.rasp.method', safeMethod(extra.method ?? ctx?.method));
    opt('shield360.rasp.framework', extra.framework ?? ctx?.framework);
    opt('shield360.rasp.cve', f.cve && /^CVE-\d{4}-\d{4,7}$/.test(f.cve) ? f.cve : undefined);
    if (state.remote?.snippets && f.input) attrs['shield360.rasp.snippet'] = maskSnippet(f.input.value);
    if (state.remote?.reportTargets && TARGET_RULES.has(f.rule)) opt('shield360.rasp.target', maskTarget(f.target));
    if (f.attack === 'sql_injection' && f.dialect && SQL_DIALECT_NAMES.has(f.dialect)) attrs['shield360.rasp.sql.dialect'] = f.dialect;
    state.sink?.add({ name: 'shield360.rasp.event', time: new Date().toISOString(), attrs }, [f.attack, f.rule, sink, route, decision].join('\u0000'));
  } catch {
    // reporting never breaks the call
  }
}

/**
 * Applies a finding: reports it and, when the decision is `blocked`, throws
 * the block error. Returns the decision, or null when the attack type is off.
 */
export function handleFinding(f: Finding, sink: string, extra: FindingExtra = {}): Decision | null {
  let mode = modeFor(f.attack);
  // A rule's own action (virtual patches, sink rules) caps the mode.
  if (f.action && RANK[f.action] < RANK[mode]) mode = f.action;
  if (mode === 'off') return null;
  const decision: Decision = mode === 'block' && !MONITOR_ONLY.has(f.attack) ? 'blocked' : 'monitored';
  const eventId = randomBytes(16).toString('hex');
  emit(f, sink, extra, decision, mode, eventId);
  // Custom rules that look at built-in findings; the first blocking decision wins, the built-in one first.
  const custom = f.attack === 'custom_rule' ? undefined : runFindingRules(f, sink, extra);
  if (decision === 'blocked') throw new RaspBlockedError(f.attack, f.rule, eventId);
  if (custom) throw custom;
  return decision;
}

/** Reports each custom finding rule the finding matches; returns the block error of the first that blocks. Never throws. */
function runFindingRules(f: Finding, sink: string, extra: FindingExtra): RaspBlockedError | undefined {
  try {
    // Mode off skips custom rules: nothing is evaluated.
    if (!state.customRules.length || modeFor('custom_rule') === 'off') return undefined;
    const ctx = currentContext();
    const subject = requestSubject(ctx, state.applicationName);
    subject.sink = sink;
    subject.attack = { type: f.attack, rule: f.rule };
    const budget = ctx ? ruleState(ctx).budget : { steps: DEFAULT_RULE_BUDGET };
    for (const m of matchFindingRules(state.customRules, subject, budget)) {
      try {
        handleFinding(customFinding(m.rule, m.input ?? f.input), sink, extra);
      } catch (e) {
        if (e instanceof RaspBlockedError) return e;
      }
    }
  } catch {
    // fail open
  }
  return undefined;
}

/**
 * Of several findings for one call, the one whose decision is strongest
 * (block over monitor; an attack type that is off never counts), so a
 * finding for a type in monitor or off mode cannot hide another that blocks.
 * Ties go to the earlier finding (the contract's order).
 */
export function strongest(...findings: (Finding | null | undefined)[]): Finding | null {
  let best: Finding | null = null;
  let bestRank = 0;
  for (const f of findings) {
    if (!f) continue;
    let mode = modeFor(f.attack);
    if (f.action && RANK[f.action] < RANK[mode]) mode = f.action;
    if (RANK[mode] > bestRank) {
      best = f;
      bestRank = RANK[mode];
    }
  }
  return best;
}

/**
 * Runs a check at a sink and applies what it finds. Fail open: any error
 * other than the block error is swallowed. The entry point later sink hooks use.
 */
export function check(sink: string, run: () => Finding | null | undefined, extra?: FindingExtra): Decision | null {
  // Passive IAST (iast.ts): armed for sampled checks while it is on; reports only when no attack was found.
  const iast = isActive() ? beginIast() : null;
  try {
    const f = run();
    if (iast) endIast(iast, f ? undefined : { sink, extra });
    return f ? handleFinding(f, sink, extra) : null;
  } catch (e) {
    if (e instanceof RaspBlockedError) throw e;
    return null;
  } finally {
    if (iast) endIast(iast);
  }
}

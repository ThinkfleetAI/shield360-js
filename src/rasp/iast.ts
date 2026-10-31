/**
 * Passive IAST (README "Passive IAST"): while RASP checks its sinks during
 * normal traffic, report the places where a request input reaches a sink
 * verbatim and unparameterized, even when the value is harmless and no
 * attack happened, so developers can fix "route X builds SQL from query.id"
 * before anyone attacks it.
 *
 * Off by default; turned on by the signed config (`iast: "on"`), the local
 * option (`rasp: { iast: true }`) or `SHIELD360_IAST=on`. Never blocks and
 * does not depend on the attack modes. It adds work only to sink checks that
 * already run with request input in scope, and only for sampled checks.
 *
 * Each vulnerability has a fingerprint (route, sink, input key, rule) and is
 * reported at most once per process per hour, with how many times it was
 * seen since the last report. Events name locations, never values, and carry
 * no snippet: the code location (the app's own stack frame, captured once
 * per fingerprint) replaces it.
 */
import { createHash, randomBytes } from 'crypto';
import { relative, resolve, sep } from 'path';
import { currentContext, eventRouteOf } from './context';

/** Where reports go: the RASP reporter. `add` returning false means it refused the event (rate limit, full queue). */
export type IastEventSink = { add(event: { name: string; time: string; attrs: Record<string, string> }, foldKey: string): boolean | void };
import { armIastSlot, closeIastSlot, type IastSlot } from './iast-scope';
import type { Vuln } from './iast-rules';

export const RASP_VULNERABILITY = 'shield360.rasp.vulnerability';
/** A fingerprint is reported at most once per this period per process. */
export const IAST_REPORT_EVERY_MS = 60 * 60 * 1000;
/** Fingerprints remembered per process; the oldest is forgotten past this. */
export const IAST_MAX_FINGERPRINTS = 10_000;
export const IAST_DEFAULT_RATE = 1;
export const IAST_DEFAULT_RATE_PRODUCTION = 0.1;

export type IastSetting = 'on' | 'off';
/** `init({ rasp: { iast } })`: true / false, or options. */
export type IastOptions = boolean | { enabled?: boolean; sampleRate?: number };

type Seen = { lastSent: number; pending: number; location: string };

type State = {
  env: IastSetting | undefined;
  envRate: number | undefined;
  local: boolean | undefined;
  localRate: number | undefined;
  remote: IastSetting | undefined;
  remoteRate: number | undefined;
  configVersion: string;
  production: boolean;
  app: string;
  sink?: IastEventSink;
  seen: Map<string, Seen>;
  now: () => number;
  random: () => number;
};

const fresh = (): State => ({
  env: undefined,
  envRate: undefined,
  local: undefined,
  localRate: undefined,
  remote: undefined,
  remoteRate: undefined,
  configVersion: 'local',
  production: false,
  app: 'default',
  seen: new Map(),
  now: Date.now,
  random: Math.random,
});

let state: State = fresh();

const PRODUCTION = /^prod(uction)?$/i;
const asSetting = (v: unknown): IastSetting | undefined => {
  const s = typeof v === 'string' ? v.trim().toLowerCase() : typeof v === 'boolean' ? (v ? 'on' : 'off') : '';
  return s === 'on' || s === 'off' ? s : undefined;
};
const asRate = (v: unknown): number | undefined => {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
};

export type IastSettings = {
  option?: IastOptions;
  applicationName: string;
  environment?: string;
  env?: NodeJS.ProcessEnv;
  /** Tests: a clock and a sampler. */
  now?: () => number;
  random?: () => number;
};

/** Reads the local option and the environment (`SHIELD360_IAST`, `SHIELD360_IAST_SAMPLE_RATE`). Forgets what was seen. */
export function configureIast(s: IastSettings): void {
  const env = s.env ?? process.env;
  const o = s.option;
  state = {
    ...fresh(),
    env: asSetting(env.SHIELD360_IAST),
    envRate: asRate(env.SHIELD360_IAST_SAMPLE_RATE),
    local: typeof o === 'boolean' ? o : o && typeof o === 'object' ? o.enabled !== false : undefined,
    localRate: o && typeof o === 'object' ? asRate(o.sampleRate) : undefined,
    production: [env.NODE_ENV, env.ENVIRONMENT, s.environment].some((v) => PRODUCTION.test((v || '').trim())),
    app: s.applicationName || 'default',
    now: s.now ?? Date.now,
    random: s.random ?? Math.random,
  };
}

/** The verified signed config's switch and rate (undefined drops them). */
export function setIastRemote(c: { iast?: unknown; iastSampleRate?: unknown; version?: string } | undefined): void {
  state.remote = asSetting(c?.iast);
  state.remoteRate = asRate(c?.iastSampleRate);
  state.configVersion = c?.version || 'local';
}

export function setIastSink(sink: IastEventSink | undefined): void {
  state.sink = sink;
}

/**
 * Whether passive IAST is on. Order: `SHIELD360_IAST=off` wins; then the
 * signed config's `iast`; then the local option or `SHIELD360_IAST=on`.
 */
export function iastEnabled(): boolean {
  if (state.env === 'off') return false;
  if (state.remote) return state.remote === 'on';
  return state.local === true || state.env === 'on';
}

/** The share of checks that run the IAST rules: env, then the signed config, then the option, then 1.0 (0.1 in production). */
export function iastSampleRate(): number {
  return state.envRate ?? state.remoteRate ?? state.localRate ?? (state.production ? IAST_DEFAULT_RATE_PRODUCTION : IAST_DEFAULT_RATE);
}

/**
 * Arms the IAST slot for one check, or returns null: off, not sampled, or
 * no request input in scope. engine.check calls it only while RASP is active.
 */
export function beginIast(): IastSlot | null {
  try {
    if (!iastEnabled()) return null;
    const ctx = currentContext();
    if (!ctx || (!ctx.inputs.length && !ctx.late)) return null;
    const rate = iastSampleRate();
    if (rate <= 0 || (rate < 1 && state.random() >= rate)) return null;
    return armIastSlot();
  } catch {
    return null;
  }
}

export type IastExtra = { framework?: string; route?: string; method?: string; path?: string };

/**
 * Disarms the slot. With a sink (the check found no attack), reports the
 * vulnerability its detectors noted, if any. Never throws.
 */
export function endIast(slot: IastSlot, report?: { sink: string; extra?: IastExtra }): void {
  const vuln = closeIastSlot(slot);
  if (!vuln || !report) return;
  try {
    reportVulnerability(vuln, report.sink, report.extra ?? {});
  } catch {
    // reporting never breaks the call
  }
}

// Event attributes must pass the platform's shape checks (lib/security/rasp/vulnerabilities.ts); same shapes as engine.ts.
const safeKey = (k: string) => k.replace(/[^A-Za-z0-9_.\-[\]]/g, '_').replace(/^[^A-Za-z0-9_]/, '_').slice(0, 128);
const safeRoute = (r: string) => {
  const s = r.replace(/[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]/g, '_').slice(0, 256);
  return s.startsWith('/') ? s : '';
};
const safeMethod = (m: string | undefined) => (m && /^[A-Za-z]{3,10}$/.test(m) ? m.toUpperCase() : '');
const SINK = /^[A-Za-z_][A-Za-z0-9_]*(?:[.:/][A-Za-z0-9_]+)*$/;

/** The fingerprint: SHA-256 of route, sink, input key and rule (NUL-separated), first 32 hex. */
export function vulnFingerprint(route: string, sink: string, inputKey: string, rule: string): string {
  return createHash('sha256').update([route, sink, inputKey, rule].join('\u0000')).digest('hex').slice(0, 32);
}

function reportVulnerability(v: Vuln, sink: string, extra: IastExtra): void {
  if (!SINK.test(sink) || sink.length > 64) return;
  const ctx = currentContext();
  const path = extra.path ?? ctx?.path;
  const template = extra.route ?? ctx?.route;
  const route = safeRoute(template ?? (path ? eventRouteOf(path) : ''));
  const inputKey = safeKey(v.input.key);
  if (!inputKey) return;
  const fp = vulnFingerprint(route, sink, inputKey, v.rule);
  const now = state.now();
  let seen = state.seen.get(fp);
  if (seen && now - seen.lastSent < IAST_REPORT_EVERY_MS) {
    seen.pending++;
    return;
  }
  if (!seen) {
    // First sight in this process: the one time the stack is read.
    seen = { lastSent: -Infinity, pending: 0, location: codeLocation() };
    if (state.seen.size >= IAST_MAX_FINGERPRINTS) {
      const oldest = state.seen.keys().next().value;
      if (oldest !== undefined) state.seen.delete(oldest);
    }
    state.seen.set(fp, seen);
  }
  const attrs: Record<string, string> = {
    'shield360.rasp.kind': 'vulnerability',
    'shield360.rasp.event_id': randomBytes(16).toString('hex'),
    'shield360.rasp.app': state.app,
    'shield360.rasp.rule': v.rule,
    'shield360.rasp.sink': sink,
    'shield360.rasp.source': 'request',
    'shield360.rasp.input_key': inputKey,
    'shield360.rasp.config_version': state.configVersion,
    'shield360.rasp.language': 'node',
    'shield360.rasp.vuln.fingerprint': fp,
    'shield360.rasp.vuln.position': v.position,
    'shield360.rasp.count': String(seen.pending + 1),
  };
  const opt = (k: string, value: string | undefined) => {
    if (value) attrs[k] = value;
  };
  opt('shield360.rasp.route', route);
  opt('shield360.rasp.method', safeMethod(extra.method ?? ctx?.method));
  opt('shield360.rasp.framework', extra.framework ?? ctx?.framework);
  opt('shield360.rasp.vuln.location', seen.location);
  const sinkTo = state.sink;
  // Refused (rate limit, full queue) or nowhere to send: count it, and try again at the next sighting.
  // No fold key: IAST dedupes and counts its own sightings, so a refused report must leave nothing
  // in the reporter that could be sent later behind its back.
  if (!sinkTo || sinkTo.add({ name: RASP_VULNERABILITY, time: new Date(now).toISOString(), attrs }, '') === false) {
    seen.pending++;
    return;
  }
  seen.lastSent = now;
  seen.pending = 0;
}

/** The route of a finding whose framework gave no template: the event route (README "Event route"). */
export const iastRouteOf = eventRouteOf;

// The SDK's own files (src/ or dist/): frames there are not the app's. Its tests are.
const SDK_ROOT = resolve(__dirname, '..');
const FRAME_TAIL = /:(\d{1,7}):\d{1,7}$/;
const LOCATION_CHARS = /[^A-Za-z0-9_./@+~-]/g;

/** Whether a stack frame's file is the app's own code. */
export function isAppFrame(file: string): boolean {
  const f = file.replace(/\\/g, '/');
  if (!f || f.startsWith('node:') || f.startsWith('internal/') || f.includes('/node_modules/')) return false;
  const root = SDK_ROOT.replace(/\\/g, '/');
  if ((f === root || f.startsWith(root + '/')) && !f.includes('/__tests__/')) return false;
  return f.startsWith('/') || /^[A-Za-z]:\//.test(f);
}

/**
 * The top stack frame in the app's own code (outside node_modules, Node's
 * internals and the SDK), as `path:line` relative to the working directory
 * (only the last three segments when outside it), or '' when there is none.
 */
export function codeLocation(stack?: string): string {
  let text = stack;
  if (text === undefined) {
    const limit = Error.stackTraceLimit;
    try {
      Error.stackTraceLimit = 64;
      text = new Error().stack || '';
    } finally {
      Error.stackTraceLimit = limit;
    }
  }
  for (const raw of text.split('\n').slice(1)) {
    let line = raw.trim();
    if (!line.startsWith('at ')) continue;
    line = line.slice(3);
    const open = line.lastIndexOf('(');
    if (open >= 0 && line.endsWith(')')) line = line.slice(open + 1, -1);
    const m = FRAME_TAIL.exec(line);
    if (!m) continue;
    const file = line.slice(0, m.index).replace(/^file:\/\//, '');
    if (!isAppFrame(file)) continue;
    const rel = relative(process.cwd(), file);
    const shown = rel && !rel.startsWith('..') && !rel.startsWith(sep) && !/^[A-Za-z]:/.test(rel) ? rel : file.split(/[\\/]/).slice(-3).join('/');
    return `${shown.replace(/\\/g, '/').replace(LOCATION_CHARS, '_').slice(0, 240)}:${m[1]}`;
  }
  return '';
}

/** Forgets every fingerprint seen and the configuration (tests, re-init). */
export function resetIast(): void {
  state = fresh();
}

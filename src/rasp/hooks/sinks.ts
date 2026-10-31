/**
 * Sink rules (README "Sink rules"): data from the built-in list or the
 * verified signed config that points an existing detector at a library
 * function the SDK does not hook itself. No rule carries code: a rule names
 * a module, a dotted path to a function, an argument and one of the checks,
 * and the generic wrapper here runs that check.
 *
 * Rules are applied to modules already loaded and, through one
 * require-in-the-middle registration per rule set, to modules loaded later.
 * Wrappers are RASP's own (not shimmer's), as in the database hook, so
 * tracing that wraps the same function stacks in either order.
 */
import { InstrumentationBase, InstrumentationNodeModuleDefinition } from '@opentelemetry/instrumentation';
import { currentContext, inputsOf } from '../context';
import {
  detectCode,
  detectCommand,
  detectDeserialization,
  detectNoSql,
  detectPath,
  detectSql,
  detectSsrf,
  detectXml,
  type DeserFormat,
  type FileOp,
} from '../detect';
import { allowLists, check, isActive } from '../engine';
import { SQL_DIALECTS, type SqlDialect } from '../lexers';
import { RaspBlockedError, type Finding, type RaspMode } from '../types';
import builtIn from '../data/default-sinks.json';
import { isRaspWrapper, markRaspWrapper } from './marks';
import { moduleExports } from './esm';

export type SinkCheck = 'sql' | 'nosql' | 'command' | 'path' | 'ssrf' | 'code' | 'deser' | 'xml';

export type SinkRule = {
  id: string;
  title?: string;
  runtimes?: string[];
  module: string;
  target: string;
  check: SinkCheck;
  arg: number;
  field?: string;
  dialect?: SqlDialect;
  op?: FileOp;
  format?: DeserFormat;
  resolvesExternal?: boolean;
  action: Exclude<RaspMode, 'off'>;
};

const MAX_RULES = 64;
/** Rule ids: dot-separated words, short enough that the event sink `rule:<id>` fits its 64 characters. */
const RULE_ID = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$/;
const SEGMENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const MODULE = /^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(\/[\w.-]+)*$/i;
const CHECKS = new Set<SinkCheck>(['sql', 'nosql', 'command', 'path', 'ssrf', 'code', 'deser', 'xml']);
const DIALECTS = new Set<SqlDialect>(SQL_DIALECTS);
const OPS = new Set<FileOp>(['read', 'write', 'append', 'delete', 'rename', 'list', 'open']);
const FORMATS = new Set<DeserFormat>([
  'pickle',
  'marshal',
  'yaml',
  'jsonpickle',
  'node_serialize',
  'funcster',
  'binaryformatter',
  'typename',
  'java',
  'snakeyaml',
]);

/** One rule, checked field by field; null drops it (never the whole list). */
export function parseSinkRule(raw: unknown): SinkRule | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.id !== 'string' || r.id.length > 59 || !RULE_ID.test(r.id)) return null;
  if (typeof r.module !== 'string' || r.module.length > 200 || !MODULE.test(r.module)) return null;
  if (typeof r.target !== 'string') return null;
  const segments = r.target.split('.');
  if (!segments.length || segments.length > 4 || segments.some((s) => !SEGMENT.test(s) || s === '__proto__' || s === 'constructor')) return null;
  if (typeof r.check !== 'string' || !CHECKS.has(r.check as SinkCheck)) return null;
  if (r.runtimes !== undefined && !(Array.isArray(r.runtimes) && r.runtimes.every((x) => typeof x === 'string'))) return null;
  if (Array.isArray(r.runtimes) && !r.runtimes.includes('node')) return null;
  const arg = r.arg === undefined ? 0 : r.arg;
  if (typeof arg !== 'number' || !Number.isInteger(arg) || arg < 0 || arg > 16) return null;
  if (r.field !== undefined && (typeof r.field !== 'string' || !SEGMENT.test(r.field))) return null;
  if (r.dialect !== undefined && !DIALECTS.has(r.dialect as SqlDialect)) return null;
  if (r.op !== undefined && !OPS.has(r.op as FileOp)) return null;
  if (r.check === 'deser' && !FORMATS.has(r.format as DeserFormat)) return null;
  const action = r.action === undefined ? 'monitor' : r.action;
  if (action !== 'monitor' && action !== 'block') return null;
  return {
    id: r.id,
    title: typeof r.title === 'string' ? r.title : undefined,
    module: r.module,
    target: r.target,
    check: r.check as SinkCheck,
    arg,
    field: r.field as string | undefined,
    dialect: r.dialect as SqlDialect | undefined,
    op: r.op as FileOp | undefined,
    format: r.format as DeserFormat | undefined,
    resolvesExternal: r.resolvesExternal === true,
    action,
  };
}

/** A list: at most 64 rules, invalid ones dropped, duplicate ids keep the first. */
export function parseSinkRules(raw: unknown): SinkRule[] {
  if (!Array.isArray(raw)) return [];
  const out: SinkRule[] = [];
  const ids = new Set<string>();
  for (const item of raw) {
    if (out.length >= MAX_RULES) break;
    const rule = parseSinkRule(item);
    if (rule && !ids.has(rule.id)) {
      ids.add(rule.id);
      out.push(rule);
    }
  }
  return out;
}

export const BUILT_IN_SINKS: SinkRule[] = parseSinkRules((builtIn as { sinks?: unknown }).sinks);

/** The value a rule checks, from the call's arguments. */
function valueOf(rule: SinkRule, values: unknown[]): unknown {
  const v = values[rule.arg];
  if (rule.check === 'nosql') return v;
  if (typeof v === 'string') return v;
  if (rule.field && v && typeof v === 'object') {
    const f = (v as Record<string, unknown>)[rule.field];
    if (typeof f === 'string') return f;
  }
  return undefined;
}

function detect(rule: SinkRule, value: unknown): Finding | null {
  const ctx = currentContext();
  if (!ctx) return null;
  const inputs = inputsOf(ctx);
  if (!inputs.length) return null;
  if (rule.check === 'nosql') return value && typeof value === 'object' ? detectNoSql(value, ctx.trees, inputs) : null;
  if (typeof value !== 'string') return null;
  switch (rule.check) {
    case 'sql':
      return detectSql(value, inputs, rule.dialect ?? 'generic');
    case 'command':
      return detectCommand(value, inputs);
    case 'path':
      return detectPath(value, rule.op ?? 'read', inputs, allowLists().fileRoots, ctx.inRequest);
    case 'ssrf':
      return detectSsrf(value, inputs, []);
    case 'code':
      return detectCode(value, inputs);
    case 'deser':
      return detectDeserialization(rule.format as DeserFormat, value, inputs);
    case 'xml':
      return detectXml(value, inputs, Boolean(rule.resolvesExternal));
    default:
      return null;
  }
}

let checking = false;

function inspect(rule: SinkRule, values: unknown[]): void {
  if (checking || !isActive()) return;
  checking = true;
  try {
    // The rule's action caps the decision (the attack type's mode still applies).
    check(`rule:${rule.id}`, () => {
      const f = detect(rule, valueOf(rule, values));
      return f ? { ...f, action: rule.action } : null;
    });
  } catch (error) {
    if (error instanceof RaspBlockedError) throw error;
  } finally {
    checking = false;
  }
}

type Method = (...args: unknown[]) => unknown;
/** Per owner and key: the original, RASP's wrapper, and the rule it currently checks (none = pass through). */
type Wrapped = { original: Method; wrapper: Method; rule?: SinkRule };
const registry = new Map<object, Map<string, Wrapped>>();

/** The owner object and key a rule's target names in a module's exports. */
function resolve(exports: unknown, target: string): { owner: object; key: string } | null {
  const segments = target.split('.');
  let owner: unknown = exports;
  for (const s of segments.slice(0, -1)) {
    if (!owner || (typeof owner !== 'object' && typeof owner !== 'function')) return null;
    owner = Reflect.get(owner as object, s);
  }
  if (!owner || (typeof owner !== 'object' && typeof owner !== 'function')) return null;
  return { owner: owner as object, key: segments[segments.length - 1] };
}

function apply(rule: SinkRule, exports: unknown): void {
  try {
    const at = resolve(exports, rule.target);
    if (!at) return;
    let methods = registry.get(at.owner);
    const known = methods?.get(at.key);
    if (known) {
      known.rule = rule;
      return;
    }
    const descriptor = Object.getOwnPropertyDescriptor(at.owner, at.key);
    const current = descriptor?.value;
    // Not an own function, or already one of RASP's built-in hooks: one check per call.
    if (typeof current !== 'function' || isRaspWrapper(current)) return;
    const entry: Wrapped = { original: current, wrapper: current, rule };
    const wrapper = function (this: unknown, ...values: unknown[]): unknown {
      if (entry.rule) inspect(entry.rule, values);
      return new.target ? Reflect.construct(current, values, new.target) : Reflect.apply(current, this, values);
    };
    for (const key of Reflect.ownKeys(current)) {
      if (key === '__wrapped' || key === '__original' || key === '__unwrap') continue;
      Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(current, key)!);
    }
    entry.wrapper = wrapper;
    markRaspWrapper(wrapper);
    Object.defineProperty(at.owner, at.key, { ...descriptor, value: wrapper });
    if (!methods) registry.set(at.owner, (methods = new Map()));
    methods.set(at.key, entry);
  } catch {
    // A shape the rule does not fit: leave the module alone.
  }
}

/** Switches every rule off; puts originals back where RASP's wrapper is still on top. */
function releaseAll(): void {
  for (const [owner, methods] of [...registry]) {
    for (const [key, entry] of [...methods]) {
      entry.rule = undefined;
      if (Object.getOwnPropertyDescriptor(owner, key)?.value === entry.wrapper) {
        const descriptor = Object.getOwnPropertyDescriptor(owner, key)!;
        Object.defineProperty(owner, key, { ...descriptor, value: entry.original });
        methods.delete(key);
      }
    }
    if (!methods.size) registry.delete(owner);
  }
}

let pending: SinkRule[] = [];

/** Registers the rule set's modules for when the app loads them. */
export class RaspSinkInstrumentation extends InstrumentationBase {
  constructor() {
    super('shield360/instrumentation-rasp-sinks', '1.0.0', { enabled: false });
  }
  protected init(): InstrumentationNodeModuleDefinition[] {
    const byModule = new Map<string, SinkRule[]>();
    for (const r of pending) byModule.set(r.module, [...(byModule.get(r.module) ?? []), r]);
    return [...byModule].map(
      ([name, rules]) =>
        new InstrumentationNodeModuleDefinition(name, ['*'], (exports) => {
          for (const r of rules) apply(r, moduleExports(exports));
          return exports;
        }),
    );
  }
}

let instrumentation: RaspSinkInstrumentation | undefined;
let current: SinkRule[] = [];

/** Rules for modules the app has already loaded (never loads a module). */
function applyLoaded(rules: SinkRule[]): void {
  for (const rule of rules) {
    try {
      const cached = require.cache[require.resolve(rule.module)];
      if (cached) apply(rule, cached.exports);
    } catch {
      // not installed, or not resolvable from the SDK
    }
  }
}

/**
 * Makes `rules` the rule set: rules no longer listed stop checking at once,
 * new ones apply to loaded modules now and to others when loaded. Never throws.
 */
export function setSinkRules(rules: SinkRule[]): void {
  try {
    releaseAll();
    current = rules;
    try {
      instrumentation?.disable();
    } catch {
      // never
    }
    instrumentation = undefined;
    if (!rules.length) return;
    pending = rules;
    instrumentation = new RaspSinkInstrumentation();
    instrumentation.enable();
    applyLoaded(rules);
  } catch {
    // fail open
  }
}

/** The rule set in force (tests, diagnostics). */
export function sinkRules(): SinkRule[] {
  return current;
}

/** Applies the built-in rules. Idempotent; never throws. */
export function installSinkHooks(): boolean {
  setSinkRules(BUILT_IN_SINKS);
  return true;
}

export function uninstallSinkHooks(): void {
  setSinkRules([]);
}

/** Tests: apply one rule to a module object directly. */
export function applySinkRule(rule: SinkRule, exports: unknown): void {
  current = [...current, rule];
  apply(rule, exports);
}

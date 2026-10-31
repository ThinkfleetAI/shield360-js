/**
 * Database sink hook (README "SQL", "NoSQL"): SQL text sent through pg,
 * mysql2, mysql, sqlite3, better-sqlite3, mssql, tedious (SQL Server),
 * oracledb (Oracle) and ibm_db (Db2), and MongoDB filter,
 * update and pipeline documents, are checked for injection before the
 * driver sends them. Drivers are hooked by name when the app loads them; no
 * driver is imported. Drafted with ChatGPT, reviewed and adapted by the
 * repository owner.
 *
 * Wrappers are RASP's own, not shimmer's: the SDK's tracing (and other
 * OpenTelemetry instrumentations) wrap the same methods with shimmer, which
 * unwraps whatever shimmer-wrapped method it finds. Kept apart, the two
 * stack in either order and neither removes the other.
 */
import {
  InstrumentationBase, InstrumentationNodeModuleDefinition,
  InstrumentationNodeModuleFile,
} from '@opentelemetry/instrumentation';
import { currentContext, inputsOf } from '../context';
import { check, isActive } from '../engine';
import { detectSql, detectNoSql } from '../detect';
import type { SqlDialect } from '../lexers';
import { RaspBlockedError } from '../types';
import { markRaspWrapper } from './marks';
import { moduleExports } from './esm';

type Driver = 'pg' | 'mysql2' | 'mysql' | 'sqlite3' | 'better-sqlite3' | 'mssql' | 'tedious'
  | 'oracledb' | 'ibm_db' | 'mongodb';
type Method = (...args: unknown[]) => unknown;
type Prototype = Record<string, Method>;
type Spec = {
  version: string; constructor: string; methods: string[]; dialect?: SqlDialect;
  /** Property holding the SQL when the first argument is an object (`{ text }`, `{ sql }`, a tedious Request). */
  field?: string;
  /**
   * Methods that hand their text on, asynchronously, to another hooked call:
   * method -> the receiving `driver` or `driver.method`. The receiver skips
   * that text once (one check per call).
   */
  handsTo?: Record<string, string>;
  /** Other exported classes and their methods, checked the same way. */
  also?: Record<string, string[]>;
};
const specs: Record<Driver, Spec> = {
  pg: { version: '>=7', constructor: 'Client', methods: ['query'], dialect: 'postgres', field: 'text' },
  mysql2: { version: '>=2', constructor: 'Connection', methods: ['query', 'execute'], dialect: 'mysql', field: 'sql' },
  mysql: { version: '>=2', constructor: '', methods: ['query'], dialect: 'mysql', field: 'sql' },
  sqlite3: { version: '>=5', constructor: 'Database', methods: ['run', 'get', 'all', 'each', 'exec', 'prepare'], dialect: 'sqlite' },
  'better-sqlite3': { version: '>=7', constructor: '', methods: ['prepare', 'exec'], dialect: 'sqlite' },
  // query and batch live on mssql's shared base Request, which the exported Request inherits.
  mssql: { version: '>=6', constructor: 'Request', methods: ['query', 'batch', 'execute'], dialect: 'mssql',
    handsTo: { query: 'tedious', batch: 'tedious', execute: 'tedious' },
    // mssql prepares through sp_prepare (a tedious procedure call, not hooked), so its text is checked here.
    also: { PreparedStatement: ['prepare'] } },
  // tedious takes a Request built with the SQL text; mssql's default driver calls it too.
  tedious: { version: '>=6', constructor: 'Connection', methods: ['execSql', 'execSqlBatch', 'prepare'], dialect: 'mssql', field: 'sqlTextOrProcedure' },
  // queryStream runs this.execute on the next tick.
  oracledb: { version: '>=4', constructor: 'Connection', methods: ['execute', 'executeMany', 'queryStream'], dialect: 'oracle',
    handsTo: { queryStream: 'oracledb.execute' } },
  // queryStream delegates to queryResult, so it is covered there.
  ibm_db: { version: '>=2', constructor: 'Database', methods: [
    'query', 'querySync', 'queryResult', 'queryResultSync', 'prepare', 'prepareSync',
  ], dialect: 'db2', field: 'sql' },
  mongodb: { version: '>=4', constructor: 'Collection', methods: [
    'find', 'findOne', 'countDocuments', 'updateOne', 'updateMany', 'replaceOne',
    'deleteOne', 'deleteMany', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'aggregate',
  ] },
};
/**
 * Text a call already checked and handed on (mssql -> tedious, oracledb
 * queryStream -> execute), as `receiver\0text`, so the receiving call made
 * later (asynchronously, with the same text) is not checked again: one check
 * per call. Kept per RASP context, consumed by the receiver, at most 32.
 */
const handedOn = new WeakMap<object, string[]>();
let checking = false;
// Suppress synchronous delegation, e.g. sqlite Database.get -> prepare.
let depth = 0;

function inspect(driver: Driver, method: string, values: unknown[]): void {
  if (checking || depth) return;
  try {
    if (!isActive()) return;
    checking = true;
    const ctx = currentContext();
    if (!ctx) return;
    check(`db.${driver}.${method}`, () => {
      const inputs = inputsOf(ctx);
      if (driver === 'mongodb') {
        const docs = method === 'aggregate'
          ? Array.isArray(values[0]) ? values[0] : []
          : ['updateOne', 'updateMany', 'replaceOne', 'findOneAndUpdate', 'findOneAndReplace'].includes(method)
            ? [values[0], values[1]] : [values[0]];
        for (const doc of docs) {
          const finding = detectNoSql(doc, ctx.trees, inputs);
          if (finding) return finding;
        }
        return null;
      }
      const first = values[0];
      const field = specs[driver].field;
      const text = typeof first === 'string' ? first
        : first && typeof first === 'object' && field ? (first as Record<string, unknown>)[field] : undefined;
      if (typeof text !== 'string') return null;
      const seen = handedOn.get(ctx);
      if (seen) {
        let at = seen.indexOf(`${driver}.${method}\0${text}`);
        if (at < 0) at = seen.indexOf(`${driver}\0${text}`);
        if (at >= 0) { seen.splice(at, 1); return null; }
      }
      const finding = detectSql(text, inputs, specs[driver].dialect);
      const receiver = specs[driver].handsTo?.[method];
      if (receiver) {
        const list = seen ?? [];
        if (list.length >= 32) list.shift();
        list.push(`${receiver}\0${text}`);
        handedOn.set(ctx, list);
      }
      return finding;
    });
  } catch (error) {
    if (error instanceof RaspBlockedError) throw error;
  } finally { checking = false; }
}

/** What RASP wrapped, per prototype and method; one entry however many times patched. */
type Wrapped = { original: Method; wrapper: Method; on: boolean };
const registry = new Map<Prototype, Map<string, Wrapped>>();

/** The prototype in the chain that defines `method` itself (mssql's Request inherits query from its base). */
function ownerOf(proto: Prototype, method: string): Prototype | undefined {
  for (let p: Prototype | null = proto; p && p !== Object.prototype; p = Object.getPrototypeOf(p) as Prototype | null) {
    if (Object.prototype.hasOwnProperty.call(p, method)) return p;
  }
  return undefined;
}

function wrapMethods(driver: Driver, exported: Prototype, list: string[] = specs[driver].methods): void {
  for (const method of list) {
    const proto = ownerOf(exported, method);
    if (!proto) continue;
    let methods = registry.get(proto);
    if (!methods) registry.set(proto, (methods = new Map()));
    const descriptor = Object.getOwnPropertyDescriptor(proto, method);
    const current = descriptor?.value;
    if (typeof current !== 'function') continue;
    const known = methods.get(method);
    if (known) {
      // Patched again (a reload, or the app loaded the driver after patchLoaded): turn it back on.
      known.on = true;
      continue;
    }
    const entry: Wrapped = { original: current, wrapper: current, on: true };
    const wrapper = function (this: unknown, ...values: unknown[]): unknown {
      if (entry.on) inspect(driver, method, values);
      depth++;
      try {
        return Reflect.apply(current, this, values);
      } finally {
        depth--;
      }
    };
    for (const key of Reflect.ownKeys(current)) {
      if (key !== 'prototype') Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(current, key)!);
    }
    entry.wrapper = wrapper;
    markRaspWrapper(wrapper);
    Object.defineProperty(proto, method, { ...descriptor, value: wrapper });
    methods.set(method, entry);
  }
}

function restoreMethods(proto: Prototype): void {
  const methods = registry.get(proto);
  if (!methods) return;
  for (const [method, entry] of methods) {
    entry.on = false;
    // Put the original back only while ours is on top; under another
    // wrapper (tracing patched after RASP) ours stays, switched off.
    if (proto[method] === entry.wrapper) {
      const descriptor = Object.getOwnPropertyDescriptor(proto, method)!;
      Object.defineProperty(proto, method, { ...descriptor, value: entry.original });
      methods.delete(method);
    }
  }
  if (!methods.size) registry.delete(proto);
}

export class RaspDbInstrumentation extends InstrumentationBase {
  constructor() { super('shield360/instrumentation-rasp-db', '1.0.0', { enabled: false }); }

  protected init(): InstrumentationNodeModuleDefinition[] {
    return (Object.keys(specs) as Driver[]).map(driver => {
      const versions = [specs[driver].version];
      if (driver === 'mysql') return new InstrumentationNodeModuleDefinition(driver, versions, undefined, undefined, [
        new InstrumentationNodeModuleFile('mysql/lib/Connection.js', versions,
          exports => { this.patch(driver, exports); return exports; }, exports => this.unpatch(driver, exports)),
      ]);
      return new InstrumentationNodeModuleDefinition(driver, versions,
        exports => { this.patch(driver, moduleExports(exports)); return exports; }, exports => this.unpatch(driver, moduleExports(exports)));
    });
  }

  public patch(driver: Driver, exports: unknown): void {
    try {
      const spec = specs[driver];
      const ctor = spec.constructor ? (exports as Record<string, unknown>)?.[spec.constructor] : exports;
      const proto = (ctor as { prototype?: Prototype } | undefined)?.prototype;
      if (proto) wrapMethods(driver, proto);
      for (const [name, methods] of Object.entries(spec.also ?? {})) {
        const other = ((exports as Record<string, unknown>)?.[name] as { prototype?: Prototype } | undefined)?.prototype;
        if (other) wrapMethods(driver, other, methods);
      }
    } catch { /* Optional or unsupported driver shape: leave it alone. */ }
  }

  public unpatch(driver: Driver, exports: unknown): void {
    try {
      const spec = specs[driver];
      const ctors = [spec.constructor ? (exports as Record<string, unknown>)?.[spec.constructor] : exports,
        ...Object.keys(spec.also ?? {}).map(name => (exports as Record<string, unknown>)?.[name])];
      for (const ctor of ctors) {
        const proto = (ctor as { prototype?: Prototype } | undefined)?.prototype;
        for (let p: Prototype | null = proto ?? null; p && p !== Object.prototype; p = Object.getPrototypeOf(p) as Prototype | null) {
          restoreMethods(p);
        }
      }
    } catch { /* Fail open during driver unload. */ }
  }

  public restoreAll(): void {
    for (const proto of [...registry.keys()]) restoreMethods(proto);
  }
}

let manual: RaspDbInstrumentation | undefined;
let active: RaspDbInstrumentation | undefined;
const patcher = () => manual ?? (manual = new RaspDbInstrumentation());
export const patchPg = (exports: unknown): void => patcher().patch('pg', exports);
export const unpatchPg = (exports: unknown): void => manual?.unpatch('pg', exports);
export const patchMysql2 = (exports: unknown): void => patcher().patch('mysql2', exports);
export const unpatchMysql2 = (exports: unknown): void => manual?.unpatch('mysql2', exports);
export const patchMysql = (exports: unknown): void => patcher().patch('mysql', exports);
export const unpatchMysql = (exports: unknown): void => manual?.unpatch('mysql', exports);
export const patchSqlite3 = (exports: unknown): void => patcher().patch('sqlite3', exports);
export const unpatchSqlite3 = (exports: unknown): void => manual?.unpatch('sqlite3', exports);
export const patchBetterSqlite3 = (exports: unknown): void => patcher().patch('better-sqlite3', exports);
export const unpatchBetterSqlite3 = (exports: unknown): void => manual?.unpatch('better-sqlite3', exports);
export const patchMssql = (exports: unknown): void => patcher().patch('mssql', exports);
export const unpatchMssql = (exports: unknown): void => manual?.unpatch('mssql', exports);
export const patchTedious = (exports: unknown): void => patcher().patch('tedious', exports);
export const unpatchTedious = (exports: unknown): void => manual?.unpatch('tedious', exports);
export const patchOracledb = (exports: unknown): void => patcher().patch('oracledb', exports);
export const unpatchOracledb = (exports: unknown): void => manual?.unpatch('oracledb', exports);
export const patchIbmDb = (exports: unknown): void => patcher().patch('ibm_db', exports);
export const unpatchIbmDb = (exports: unknown): void => manual?.unpatch('ibm_db', exports);
export const patchMongodb = (exports: unknown): void => patcher().patch('mongodb', exports);
export const unpatchMongodb = (exports: unknown): void => manual?.unpatch('mongodb', exports);

/** Inspect the cache only: resolving a driver never executes its code. */
export function patchLoaded(): void {
  for (const driver of Object.keys(specs) as Driver[]) {
    try {
      const id = require.resolve(driver === 'mysql' ? 'mysql/lib/Connection.js' : driver);
      const cached = require.cache[id];
      if (cached) (active ?? patcher()).patch(driver, cached.exports);
    } catch { /* Driver absent or not resolvable from the SDK. */ }
  }
}

export function installDbHooks(): boolean {
  if (active) return true;
  let instance: RaspDbInstrumentation | undefined;
  try {
    instance = new RaspDbInstrumentation();
    instance.enable();
    active = instance;
    patchLoaded();
    return true;
  } catch {
    try { instance?.disable(); instance?.restoreAll(); } catch { /* Never throw. */ }
    active = undefined;
    return false;
  }
}
export function uninstallDbHooks(): void {
  try { active?.disable(); } finally {
    active?.restoreAll();
    manual?.restoreAll();
    active = undefined;
  }
}

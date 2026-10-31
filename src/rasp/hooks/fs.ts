/**
 * fs sink hook (README "Path"): reads, writes, deletes, renames, copies and
 * directory listings on `fs` and `fs.promises` are checked for path
 * traversal and script writes before the call. Install before application
 * modules capture bindings. Drafted with ChatGPT, reviewed and adapted by
 * the repository owner.
 *
 * Node calls its own public functions inside some of these (`readFileSync`
 * opens through `fs.openSync`, streams open through `fs.open` later), so a
 * path is checked once: calls made while a synchronous fs call runs are
 * Node's and are skipped, and within a request a path already checked for
 * the same kind of access is not checked again.
 */
import fs = require('fs');
import { syncBuiltinESMExports } from 'module';
import { fileURLToPath } from 'url';
import { promisify } from 'util';
import { currentContext, inputsOf, type RaspContext } from '../context';
import { allowLists, check, isActive, strongest } from '../engine';
import { detectPath, type FileOp } from '../detect';
import { RaspBlockedError, type Finding } from '../types';

const operations = {
  readFile: 'read', readFileSync: 'read', createReadStream: 'read',
  open: 'open', openSync: 'open',
  writeFile: 'write', writeFileSync: 'write', createWriteStream: 'write',
  appendFile: 'append', appendFileSync: 'append',
  unlink: 'delete', unlinkSync: 'delete', rm: 'delete', rmSync: 'delete',
  rename: 'rename', renameSync: 'rename', readdir: 'list', readdirSync: 'list',
  copyFile: 'read', copyFileSync: 'read',
} as const satisfies Record<string, FileOp>;
type Api = keyof typeof operations;
type Saved = { owner: object; api: Api; descriptor: PropertyDescriptor; wrapper: unknown };
let installed: Saved[] | undefined;
/** Bumped by every install and uninstall: a wrapper checks only while its generation is current. */
let generation = 0;
let checking = false;
/** Depth of synchronous fs calls in progress: anything nested is Node's own. */
let syncDepth = 0;
/** Per request: paths already checked, by kind of access (capped). */
const seen = new WeakMap<RaspContext, Set<string>>();
const SEEN_MAX = 256;

const accessOf = (op: FileOp): string => (op === 'append' || op === 'open' ? 'write' : op);

const seenKey = (path: string, op: FileOp) => `${accessOf(op)}\u0000${path}`;

/** True when this request already checked this path for this kind of access. */
function seenBefore(ctx: RaspContext | undefined, path: string, op: FileOp): boolean {
  return Boolean(ctx && seen.get(ctx)?.has(seenKey(path, op)));
}

/** Records that this request checked this path for this kind of access. */
function markSeen(ctx: RaspContext | undefined, path: string, op: FileOp): void {
  if (!ctx) return;
  let set = seen.get(ctx);
  if (!set) seen.set(ctx, (set = new Set()));
  if (set.size < SEEN_MAX) set.add(seenKey(path, op));
}

function pathString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString();
  if (value instanceof URL && value.protocol === 'file:') return fileURLToPath(value);
  return undefined;
}

function openOp(flags: unknown): FileOp {
  if (flags === undefined) return 'read';
  if (typeof flags === 'string') return /[wa+]/.test(flags) ? 'write' : 'read';
  if (typeof flags === 'number') {
    const c = fs.constants;
    return flags & (c.O_WRONLY | c.O_RDWR | c.O_CREAT | c.O_TRUNC | c.O_APPEND) ? 'write' : 'read';
  }
  return 'read';
}

function inspect(api: Api, values: unknown[], promises: boolean): void {
  if (checking || syncDepth > 0) return;
  try {
    if (!isActive()) return;
    checking = true;
    check(`fs.${promises ? 'promises.' : ''}${api}`, () => {
      const ctx = currentContext();
      const inputs = ctx ? inputsOf(ctx) : [];
      const roots = allowLists().fileRoots;
      const inRequest = Boolean(ctx?.inRequest);
      const op = operations[api] === 'open' ? openOp(values[1]) : operations[api];
      const paths: [string | undefined, FileOp][] = [[pathString(values[0]), op]];
      if (api === 'rename' || api === 'renameSync' || api === 'copyFile' || api === 'copyFileSync') {
        paths.push([pathString(values[1]), api.startsWith('copyFile') ? 'write' : 'rename']);
      }
      const checks: { path: string; op: FileOp; finding: Finding | null }[] = [];
      for (const [path, pathOp] of paths) {
        if (path !== undefined && !seenBefore(ctx, path, pathOp)) {
          checks.push({ path, op: pathOp, finding: detectPath(path, pathOp, inputs, roots, inRequest) });
        }
      }
      // Both paths are checked; the strongest decision wins.
      const winner = strongest(...checks.map((c) => c.finding));
      // A finding that lost to the winner was never applied: its path stays
      // unmarked, so a later call on it in this request is checked again.
      for (const c of checks) if (!(winner && c.finding && c.finding !== winner)) markSeen(ctx, c.path, c.op);
      return winner;
    });
  } catch (error) {
    if (error instanceof RaspBlockedError) throw error;
  } finally {
    checking = false;
  }
}

/**
 * Ends this generation (every wrapper stops checking) and puts back the
 * originals where RASP's wrapper is still the current value. A wrapper put
 * on top later (tracing) stays, calling RASP's, which now only passes through.
 */
function restore(saved: Saved[]): void {
  generation++;
  for (const entry of [...saved].reverse()) {
    if (Object.getOwnPropertyDescriptor(entry.owner, entry.api)?.value === entry.wrapper) {
      Object.defineProperty(entry.owner, entry.api, entry.descriptor);
    }
  }
}

/** Idempotent; a failed installation restores every replaced descriptor. */
export function installFsHooks(): boolean {
  if (installed) return true;
  const saved: Saved[] = [];
  const gen = ++generation;
  try {
    for (const [owner, promises] of [[fs, false], [fs.promises, true]] as const) {
      for (const api of Object.keys(operations) as Api[]) {
        const descriptor = Object.getOwnPropertyDescriptor(owner, api);
        if (!descriptor && promises) continue; // No synchronous or stream promise APIs.
        if (!descriptor || typeof descriptor.value !== 'function') throw new TypeError(api);
        const original = descriptor.value as (...args: unknown[]) => unknown;
        const sync = api.endsWith('Sync');
        const wrapper = function (this: unknown, ...values: unknown[]): unknown {
          try {
            if (gen === generation) inspect(api, values, promises);
          } catch (error) {
            if (promises) return Promise.reject(error);
            throw error;
          }
          if (!sync) return Reflect.apply(original, this, values);
          syncDepth++;
          try {
            return Reflect.apply(original, this, values);
          } finally {
            syncDepth--;
          }
        };
        for (const key of Reflect.ownKeys(original)) {
          if (key === 'prototype' || key === promisify.custom) continue;
          Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)!);
        }
        const custom = Object.getOwnPropertyDescriptor(original, promisify.custom);
        if (custom) {
          // Node's custom fs promisifiers (notably read/readv/write) return
          // named results. None of the covered APIs has that contract.
          const generic = promisify(wrapper);
          Object.defineProperty(wrapper, promisify.custom, { ...custom, value: generic });
        }
        Object.defineProperty(owner, api, { ...descriptor, value: wrapper });
        saved.push({ owner, api, descriptor, wrapper });
      }
    }
    syncBuiltinESMExports();
    installed = saved;
    return true;
  } catch {
    restore(saved);
    try { syncBuiltinESMExports(); } catch { /* Installation remains unsuccessful. */ }
    return false;
  }
}

export function uninstallFsHooks(): void {
  if (!installed) return;
  restore(installed);
  installed = undefined;
  syncBuiltinESMExports();
}

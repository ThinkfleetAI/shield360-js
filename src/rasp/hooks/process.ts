/**
 * child_process sink hook (README "Command"): every way Node starts a
 * process is checked before the process starts. Shell-interpreted commands
 * (`exec`, `execSync`, and `spawn`/`execFile` family calls with `shell`)
 * go through `detectCommand` and `shell_spawn`; argv spawns go through
 * `detectArgv`, the script of `sh -c <script>`, and `shell_spawn`.
 *
 * The module's functions are replaced in place by wrappers with the same
 * `name`, `length` and properties, and `syncBuiltinESMExports` carries the
 * change to ESM named imports. Not a Proxy: `exec` and `execFile` carry a
 * read-only `util.promisify.custom` that a Proxy may not replace, and the
 * original's would skip the check. A function an app took out of the module before
 * install (`const { exec } = require('child_process')` at load) is not
 * covered; initialise Shield360 before loading the app's modules.
 *
 * Fail open: anything that goes wrong in the hook lets the call through,
 * and Node validates its own arguments as before. Drafted with ChatGPT,
 * reviewed and adapted by the repository owner.
 */
import cp = require('child_process');
import { syncBuiltinESMExports } from 'module';
import { promisify } from 'util';
import { currentContext, inputsOf } from '../context';
import { detectArgv, detectCommand, detectShellSpawn, shellScriptOf } from '../detect';
import { allowLists, check, isActive, strongest } from '../engine';
import type { Finding, RaspInput } from '../types';

export type ProcessApi = 'exec' | 'execSync' | 'spawn' | 'spawnSync' | 'execFile' | 'execFileSync' | 'fork';

export const PROCESS_APIS: readonly ProcessApi[] = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];

/** What a call is about to run: a shell command line, or an argv. */
export type ProcessTarget = { command: string } | { argv: string[] };

type Saved = { descriptor: PropertyDescriptor; wrapper: (...args: unknown[]) => unknown };
let installed: Map<ProcessApi, Saved> | undefined;
/** Bumped by every install and uninstall: a wrapper checks only while its generation is current. */
let generation = 0;
let checking = false;

/**
 * The call's target, or null when the arguments are not ones Node accepts
 * (Node then raises its own error). The caller's argv is copied.
 */
export function processTarget(api: ProcessApi, values: unknown[]): ProcessTarget | null {
  const first = values[0];
  if (api === 'exec' || api === 'execSync') return typeof first === 'string' ? { command: first } : null;

  const file = typeof first === 'string' ? first : api === 'fork' && first instanceof URL ? first.href : undefined;
  if (file === undefined) return null;
  const args = Array.isArray(values[1]) ? (values[1] as unknown[]) : undefined;
  if (args?.some((a) => typeof a !== 'string')) return null;
  const rest = (args as string[] | undefined)?.slice() ?? [];
  const candidate = values[args ? 2 : 1];
  const options = candidate !== null && typeof candidate === 'object' ? (candidate as { shell?: unknown; execPath?: unknown }) : undefined;

  if (api === 'fork') {
    // fork runs a module under Node, or under options.execPath when given.
    const exe = typeof options?.execPath === 'string' && options.execPath ? options.execPath : process.execPath;
    return { argv: [exe, file, ...rest] };
  }
  const shell = options?.shell;
  if (shell === true || (typeof shell === 'string' && shell !== '')) {
    // Node joins the file and arguments with spaces and hands the line to the shell.
    return { command: [file, ...rest].join(' ') };
  }
  return { argv: [file, ...rest] };
}

/** Every finding of the contract's command checks for one target, in the contract's order. */
export function processFindings(target: ProcessTarget, inputs: RaspInput[], inRequest: boolean, allow: string[]): Finding[] {
  let found: (Finding | null)[];
  if ('command' in target) {
    found = [detectCommand(target.command, inputs), detectShellSpawn({ command: target.command, inRequest, allow })];
  } else {
    const { argv } = target;
    const script = shellScriptOf(argv);
    found = [detectArgv(argv, inputs)];
    if (script) found.push(detectCommand(script, inputs), detectShellSpawn({ command: script, inRequest: false, allow }));
    found.push(detectShellSpawn({ argv0: argv[0], inRequest, allow }));
  }
  return found.filter((f): f is Finding => f !== null);
}

/** The first finding of the contract's command checks for one target. */
export function detectProcess(target: ProcessTarget, inputs: RaspInput[], inRequest: boolean, allow: string[]): Finding | null {
  return processFindings(target, inputs, inRequest, allow)[0] ?? null;
}

function inspect(api: ProcessApi, values: unknown[]): void {
  if (checking || !isActive()) return;
  checking = true;
  try {
    // check() reports what it finds and throws only the block error.
    check(`child_process.${api}`, () => {
      const target = processTarget(api, values);
      if (!target) return null;
      const ctx = currentContext();
      // The strongest decision wins: a finding in monitor or off mode never hides one that blocks.
      return strongest(...processFindings(target, ctx ? inputsOf(ctx) : [], Boolean(ctx?.inRequest), allowLists().commands));
    });
  } finally {
    checking = false;
  }
}

/** Replaces the child_process functions with checked ones. Idempotent; never throws. */
export function installProcessHooks(): boolean {
  if (installed) return true;
  const saved = new Map<ProcessApi, Saved>();
  const gen = ++generation;
  try {
    for (const api of PROCESS_APIS) {
      const descriptor = Object.getOwnPropertyDescriptor(cp, api);
      if (!descriptor || typeof descriptor.value !== 'function') throw new TypeError(api);
      const original = descriptor.value as (...args: unknown[]) => unknown;
      const wrapper = function (this: unknown, ...values: unknown[]): unknown {
        if (gen === generation) inspect(api, values);
        return Reflect.apply(original, this, values);
      };
      saved.set(api, { descriptor, wrapper });
      for (const key of Reflect.ownKeys(original)) {
        if (key === 'prototype' || key === promisify.custom) continue;
        Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)!);
      }
      // Node's own promisified exec/execFile closes over the original function;
      // rebuild it around the wrapper so promisify() cannot skip the check.
      const promisified = (...values: unknown[]) => {
        let child: unknown;
        const promise = new Promise<{ stdout: unknown; stderr: unknown }>((resolve, reject) => {
          child = Reflect.apply(wrapper, undefined, [
            ...values,
            (error: Error | null, stdout: unknown, stderr: unknown) => {
              if (error) reject(Object.assign(error, { stdout, stderr }));
              else resolve({ stdout, stderr });
            },
          ]);
        });
        return Object.assign(promise, { child });
      };
      if (api === 'exec' || api === 'execFile') Object.defineProperty(wrapper, promisify.custom, { value: promisified });
      Object.defineProperty(cp, api, { ...descriptor, value: wrapper });
    }
    syncBuiltinESMExports();
    installed = saved;
    return true;
  } catch {
    restore(saved);
    try {
      syncBuiltinESMExports();
    } catch {
      // never
    }
    return false;
  }
}

/**
 * Ends this generation (every wrapper stops checking) and puts back the
 * originals where RASP's wrapper is still the current value. A wrapper put
 * on top later (tracing) stays, calling RASP's, which now only passes through.
 */
function restore(saved: Map<ProcessApi, Saved>): void {
  generation++;
  for (const [api, { descriptor, wrapper }] of saved) {
    if (Object.getOwnPropertyDescriptor(cp, api)?.value === wrapper) Object.defineProperty(cp, api, descriptor);
  }
}

/** Puts the original functions back exactly. Idempotent. */
export function uninstallProcessHooks(): void {
  if (!installed) return;
  restore(installed);
  installed = undefined;
  try {
    syncBuiltinESMExports();
  } catch {
    // never
  }
}

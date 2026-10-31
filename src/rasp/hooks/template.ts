/** Optional template engines: patch exports only after import, never load an engine. */
import { InstrumentationBase, InstrumentationNodeModuleDefinition, InstrumentationNodeModuleFile } from '@opentelemetry/instrumentation';
import { currentContext, inputsOf } from '../context';
import { check, isActive, modeFor } from '../engine';
import { detectTemplate } from '../template';
import { RaspBlockedError, type RaspInput } from '../types';
import { markRaspWrapper } from './marks';
import { moduleExports } from './esm';

type Method = (...args: unknown[]) => unknown;
type Entry = { owner: object; key: string; descriptor: PropertyDescriptor; wrapper: Method; generation: number };
const registry = new Map<object, Map<string, Entry>>();
let generation = 0;
/** Template sources whose engine call is in progress (synchronous, innermost last). */
const active: string[] = [];
let instrumentation: RaspTemplateInstrumentation | undefined;
/**
 * Inputs an enclosing template check has not already judged. Internal delegation
 * (render to compile) and code generated from the source carry the same input, so
 * it is checked once; an independent call with other input, such as a helper that
 * compiles request data, is still checked.
 */
export function unjudgedInputs(inputs: RaspInput[]): RaspInput[] {
  return active.length ? inputs.filter(input => !active.some(source => source.includes(input.value))) : inputs;
}
// Handlebars.create() instances call this internal module at call time, so patching it covers every instance.
const HANDLEBARS_COMPILER = 'handlebars/dist/cjs/handlebars/compiler/compiler.js';
/** Node engines hooked here; the detector's table also covers other SDKs' engines. */
export type HookedTemplateEngine = 'handlebars' | 'ejs' | 'pug' | 'nunjucks' | 'lodash';
const methods: Record<HookedTemplateEngine, string[]> = {
  handlebars: ['compile', 'precompile'], ejs: ['render', 'compile'], pug: ['compile', 'render', 'compileClient'],
  nunjucks: ['renderString'], lodash: ['template'],
};

export function patchTemplate(engine: HookedTemplateEngine, exports: unknown, keys: string[] = methods[engine]): void {
  try {
    if (!exports || (typeof exports !== 'object' && typeof exports !== 'function')) return;
    const owner = exports as Record<string, unknown>;
    let entries = registry.get(owner);
    if (!entries) registry.set(owner, entries = new Map());
    for (const key of keys) {
      if (entries.get(key)?.generation === generation) continue;
      const descriptor = Object.getOwnPropertyDescriptor(owner, key);
      if (typeof descriptor?.value !== 'function') continue;
      const original = descriptor.value as Method;
      const entry: Entry = { owner, key, descriptor, wrapper: original, generation };
      const wrapper = function (this: unknown, ...args: unknown[]): unknown {
        const source = args[0];
        if (entry.generation !== generation || typeof source !== 'string') return Reflect.apply(original, this, args);
        try {
          if (isActive() && modeFor('code_injection') !== 'off') {
            const ctx = currentContext();
            const inputs = unjudgedInputs(ctx ? inputsOf(ctx) : []);
            if (inputs.length) check(`${engine}.${key}`, () => detectTemplate(source, inputs, engine));
          }
        } catch (error) { if (error instanceof RaspBlockedError) throw error; }
        active.push(source);
        try { return Reflect.apply(original, this, args); } finally { active.pop(); }
      };
      for (const name of Reflect.ownKeys(original)) {
        if (name === '__wrapped' || name === '__original' || name === '__unwrap') continue;
        Object.defineProperty(wrapper, name, Object.getOwnPropertyDescriptor(original, name)!);
      }
      entry.wrapper = wrapper;
      markRaspWrapper(wrapper);
      Object.defineProperty(owner, key, { ...descriptor, value: wrapper });
      entries.set(key, entry);
    }
    // Nunjucks also exposes renderString on Environment instances.
    if (engine === 'nunjucks' && typeof owner.Environment === 'function') patchTemplate(engine, owner.Environment.prototype);
  } catch { /* Unsupported or immutable exports fail open. */ }
}
export const patchHandlebarsCompiler = (exports: unknown): void => patchTemplate('handlebars', exports, ['compile', 'precompile']);
export function unpatchTemplate(exports: unknown): void {
  const entries = registry.get(exports as object);
  for (const entry of entries?.values() ?? []) {
    entry.generation = -1;
    try {
      if (Object.getOwnPropertyDescriptor(entry.owner, entry.key)?.value === entry.wrapper) {
        Object.defineProperty(entry.owner, entry.key, entry.descriptor);
      }
    } catch { /* A later wrapper or frozen export belongs to the app. */ }
  }
  registry.delete(exports as object);
  try {
    const environment = (exports as { Environment?: { prototype?: unknown } })?.Environment;
    if (environment?.prototype) unpatchTemplate(environment.prototype);
  } catch { /* Optional export. */ }
}
export class RaspTemplateInstrumentation extends InstrumentationBase {
  constructor() { super('shield360/instrumentation-rasp-template', '1.0.0', { enabled: false }); }
  protected init(): InstrumentationNodeModuleDefinition[] {
    return (Object.keys(methods) as HookedTemplateEngine[]).map(engine => new InstrumentationNodeModuleDefinition(engine, ['*'],
      exports => { patchTemplate(engine, moduleExports(exports)); return exports; }, exports => unpatchTemplate(moduleExports(exports)),
      engine === 'handlebars' ? [new InstrumentationNodeModuleFile(HANDLEBARS_COMPILER, ['*'],
        exports => { patchHandlebarsCompiler(exports); return exports; }, exports => unpatchTemplate(exports))] : undefined));
  }
}
export function installTemplateHooks(): void {
  if (instrumentation) return;
  generation++;
  instrumentation = new RaspTemplateInstrumentation();
  instrumentation.enable();
  for (const engine of Object.keys(methods) as HookedTemplateEngine[]) {
    try {
      const cached = require.cache[require.resolve(engine)];
      if (cached) patchTemplate(engine, cached.exports);
    } catch { /* Never import an optional engine. */ }
  }
  try {
    const cached = require.cache[require.resolve(HANDLEBARS_COMPILER)];
    if (cached) patchHandlebarsCompiler(cached.exports);
  } catch { /* Handlebars absent or laid out differently. */ }
}
export function uninstallTemplateHooks(): void {
  generation++;
  try { instrumentation?.disable(); } catch { /* Fail open. */ }
  instrumentation = undefined;
  for (const owner of [...registry.keys()]) unpatchTemplate(owner);
}

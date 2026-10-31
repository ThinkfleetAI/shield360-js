/**
 * Code, deserialization, XML and response sink hooks (README "Code",
 * "Deserialization", "XXE", "XSS"): `vm` and the `Function` constructor are
 * checked for tainted code, node-serialize, funcster and js-yaml (unsafe
 * schemas) for tainted data, libxmljs for external entities, and HTML
 * responses for reflected input (monitor only). Drafted with ChatGPT,
 * reviewed and adapted by the repository owner.
 *
 * `eval` is deliberately not hooked: a call is direct eval (with the
 * caller's local scope) only when `eval` is the built-in itself, so
 * replacing `globalThis.eval` would turn every direct `eval(x)` in the app
 * into a global-scope evaluation and break it (webpack's eval source maps,
 * for one). The `Function` hook covers `Function(...)` and `new Function`,
 * not `(function () {}).constructor(...)`.
 */
// SHIELD: optional template-source sinks share the code-hook lifecycle.
import { installTemplateHooks, uninstallTemplateHooks, unjudgedInputs } from './template';
import vm = require('vm');
import http = require('http');
import { syncBuiltinESMExports } from 'module';
import { StringDecoder } from 'string_decoder';
import { InstrumentationBase, InstrumentationNodeModuleDefinition } from '@opentelemetry/instrumentation';
import { currentContext, inputsOf } from '../context';
import { check, isActive } from '../engine';
import { detectCode, detectDeserialization, detectXml, detectXss } from '../detect';
import { RaspBlockedError, type Finding, type RaspInput } from '../types';
import { markRaspWrapper } from './marks';
import { moduleExports } from './esm';

type Method = (...args: unknown[]) => unknown;
/** `descriptor` is the property RASP replaced; absent when RASP added the property. */
type Entry = { owner: object; key: string; descriptor?: PropertyDescriptor; wrapper: Method; on: boolean };
type Library = 'node-serialize' | 'funcster' | 'js-yaml' | 'libxmljs' | 'libxmljs2';
const registry = new Map<object, Map<string, Entry>>();
let builtins: Entry[] | undefined;
let checking = false;

// No "inside a wrapped call" skip: code run by vm runs inside the original
// call, and its own vm/Function calls must still be checked.
function inspect(sink: string, run: (inputs: RaspInput[]) => Finding | null): void {
  if (checking) return;
  try {
    if (!isActive()) return;
    checking = true;
    const ctx = currentContext();
    const all = ctx ? inputsOf(ctx) : [];
    // SHIELD: code generated from a template source was judged by the template check; other input is not.
    const inputs = sink === 'Function' || sink.startsWith('vm.') ? unjudgedInputs(all) : all;
    if (inputs.length) check(sink, () => run(inputs));
  } catch (error) { if (error instanceof RaspBlockedError) throw error; }
  finally { checking = false; }
}

function copy(original: Method, wrapper: Method): void {
  for (const key of Reflect.ownKeys(original)) {
    // Shimmer metadata must stay private to the tracing wrapper underneath us.
    if (key === '__wrapped' || key === '__original' || key === '__unwrap') continue;
    Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)!);
  }
}
function wrap(owner: object, key: string, before: (values: unknown[]) => void): Entry | undefined {
  let methods = registry.get(owner);
  const known = methods?.get(key);
  if (known) { known.on = true; return known; }
  const descriptor = Object.getOwnPropertyDescriptor(owner, key);
  if (!descriptor || typeof descriptor.value !== 'function') return;
  const original = descriptor.value as Method;
  const entry: Entry = { owner, key, descriptor, wrapper: original, on: true };
  const wrapper = function (this: unknown, ...values: unknown[]): unknown {
    if (entry.on) before(values);
    return new.target ? Reflect.construct(original, values, new.target) : Reflect.apply(original, this, values);
  };
  copy(original, wrapper);
  entry.wrapper = wrapper;
  markRaspWrapper(wrapper);
  Object.defineProperty(owner, key, { ...descriptor, value: wrapper });
  if (!methods) registry.set(owner, methods = new Map());
  methods.set(key, entry);
  return entry;
}
function restore(entry: Entry): void {
  entry.on = false;
  if (Reflect.get(entry.owner, entry.key) === entry.wrapper) {
    // No descriptor: RASP added the property itself (ServerResponse write/end), so remove it.
    if (entry.descriptor) Object.defineProperty(entry.owner, entry.key, entry.descriptor);
    else delete (entry.owner as Record<string, unknown>)[entry.key];
    registry.get(entry.owner)?.delete(entry.key);
    if (!registry.get(entry.owner)?.size) registry.delete(entry.owner);
  }
}

const MAX_BODY = 1024 * 1024;
type Body = { inputs: RaspInput[]; chunks: string[]; bytes: number; stopped: boolean; decoder: StringDecoder };
let bodies = new WeakMap<http.ServerResponse, Body>();
function response(res: http.ServerResponse, values: unknown[], end: boolean): void {
  if (checking) return;
  try {
    if (!isActive()) return;
    const type = res.getHeader('content-type');
    if (typeof type !== 'string' || !type.toLowerCase().includes('html')) return;
    let body = bodies.get(res);
    if (!body) {
      const ctx = currentContext();
      const inputs = ctx ? inputsOf(ctx).map((input: RaspInput) => ({ ...input })) : [];
      // Nothing to compare against: do not collect the body at all.
      body = { inputs, chunks: [], bytes: 0, stopped: !inputs.length, decoder: new StringDecoder('utf8') };
      bodies.set(res, body);
    }
    const chunk = values[0];
    if (!body.stopped && (typeof chunk === 'string' || Buffer.isBuffer(chunk))) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof values[1] === 'string' ? values[1] as BufferEncoding : 'utf8');
      body.bytes += buffer.length;
      if (body.bytes > MAX_BODY) { body.stopped = true; body.chunks = []; }
      else body.chunks.push(body.decoder.write(buffer));
    }
    if (end) {
      bodies.delete(res);
      if (!body.stopped && body.inputs.length) {
        checking = true;
        try {
          const text = body.chunks.join('') + body.decoder.end();
          check('http.response', () => detectXss(type, text, body!.inputs));
        } finally { checking = false; }
      }
    }
  } catch { /* A response must never be changed or blocked by monitoring. */ }
}

export function installCodeHooks(): boolean {
  if (builtins) return true;
  const saved: Entry[] = [];
  try {
    const add = (owner: object, key: string, before: (values: unknown[]) => void) => {
      const entry = wrap(owner, key, before);
      if (!entry) throw new TypeError(key);
      saved.push(entry);
    };
    for (const key of ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'Script']) {
      add(vm, key, values => inspect(`vm.${key}`, inputs => typeof values[0] === 'string' ? detectCode(values[0], inputs) : null));
    }
    const functionDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'Function');
    if (functionDescriptor?.configurable) add(globalThis, 'Function', values => inspect('Function', inputs => {
      const body = values[values.length - 1];
      const finding = typeof body === 'string' ? detectCode(body, inputs) : null;
      if (finding) return finding;
      const params = values.slice(0, -1);
      return params.length && params.every(value => typeof value === 'string') ? detectCode(params.join(','), inputs) : null;
    }));
    // write/end live on OutgoingMessage.prototype (shared with client
    // requests): RASP adds its own on ServerResponse.prototype, calling
    // whatever is inherited, and removes them again on uninstall.
    const proto = http.ServerResponse.prototype;
    for (const key of ['write', 'end']) {
      if (Object.prototype.hasOwnProperty.call(proto, key) || typeof Reflect.get(proto, key) !== 'function') continue;
      const inherited = Reflect.get(Object.getPrototypeOf(proto), key) as Method;
      const wrapper = function (this: http.ServerResponse, ...values: unknown[]): unknown {
        if (entry.on) response(this, values, key === 'end');
        return Reflect.apply(Reflect.get(Object.getPrototypeOf(proto), key) as Method, this, values);
      };
      copy(inherited, wrapper);
      Object.defineProperty(proto, key, { value: wrapper, writable: true, configurable: true, enumerable: false });
      const entry: Entry = { owner: proto, key, wrapper, on: true };
      saved.push(entry);
    }
    instrumentation = new RaspCodeInstrumentation();
    instrumentation.enable();
    patchLoaded();
    installTemplateHooks(); // SHIELD: patch only imported template engines.
    syncBuiltinESMExports();
    builtins = saved;
    return true;
  } catch {
    uninstallTemplateHooks(); // SHIELD: roll back optional template hooks.
    try { instrumentation?.disable(); } catch { /* Never throw. */ }
    instrumentation = undefined;
    for (const entry of saved.reverse()) { try { restore(entry); } catch { /* Never throw. */ } }
    try { syncBuiltinESMExports(); } catch { /* Never throw. */ }
    return false;
  }
}
export function uninstallCodeHooks(): void {
  uninstallTemplateHooks(); // SHIELD: invalidate template generations.
  for (const entry of builtins ?? []) { try { restore(entry); } catch { /* Never throw. */ } }
  builtins = undefined;
  bodies = new WeakMap();
  try { instrumentation?.disable(); } catch { /* Never throw. */ }
  instrumentation = undefined;
  for (const methods of [...registry.values()]) for (const entry of [...methods.values()]) {
    try { restore(entry); } catch { /* Never throw. */ }
  }
  try { syncBuiltinESMExports(); } catch { /* Never throw. */ }
}

function patch(library: Library, exports: unknown, version?: string): void {
  try {
    if (!exports || (typeof exports !== 'object' && typeof exports !== 'function')) return;
    const module = exports as Record<string, unknown>;
    const methods = library === 'node-serialize' ? ['unserialize'] : library === 'funcster' ? ['deepDeserialize']
      : library === 'js-yaml' ? ['load', 'loadAll'] : ['parseXml', 'parseXmlString'];
    for (const method of methods) wrap(module, method, values => inspect(`${library}.${method}`, inputs => {
      if (library === 'node-serialize') return detectDeserialization('node_serialize', String(values[0]), inputs);
      if (library === 'funcster') {
        const text = typeof values[0] === 'string' ? values[0] : JSON.stringify(values[0]);
        return typeof text === 'string' ? detectDeserialization('funcster', text, inputs) : null;
      }
      if (typeof values[0] !== 'string') return null;
      if (library === 'js-yaml') {
        const options = (method === 'loadAll' && typeof values[1] === 'function' ? values[2] : values[1]) as { schema?: unknown } | undefined;
        const schema = options?.schema;
        const major = version ? Number(version.split('.')[0]) : module.DEFAULT_FULL_SCHEMA ? 3 : 4;
        const unsafe = major < 4 ? !schema || schema === module.DEFAULT_FULL_SCHEMA
          : Boolean(schema && !['DEFAULT_SCHEMA', 'CORE_SCHEMA', 'JSON_SCHEMA', 'FAILSAFE_SCHEMA'].some(key => schema === module[key]));
        return unsafe ? detectDeserialization('yaml', values[0], inputs) : null;
      }
      const options = values[1] as { noent?: unknown; dtdload?: unknown } | undefined;
      return detectXml(values[0], inputs, Boolean(options && (options.noent || options.dtdload)));
    }));
  } catch { /* Optional library or unsupported shape. */ }
}
function unpatch(exports: unknown): void {
  const methods = registry.get(exports as object);
  for (const entry of [...(methods?.values() ?? [])]) { try { restore(entry); } catch { /* Fail open. */ } }
}
export const patchNodeSerialize = (exports: unknown): void => patch('node-serialize', exports);
export const unpatchNodeSerialize = unpatch;
export const patchFuncster = (exports: unknown): void => patch('funcster', exports);
export const unpatchFuncster = unpatch;
export const patchJsYaml = (exports: unknown, version?: string): void => patch('js-yaml', exports, version);
export const unpatchJsYaml = unpatch;
export const patchLibxmljs = (exports: unknown): void => patch('libxmljs', exports);
export const unpatchLibxmljs = unpatch;
export const patchLibxmljs2 = (exports: unknown): void => patch('libxmljs2', exports);
export const unpatchLibxmljs2 = unpatch;
const libraries: Library[] = ['node-serialize', 'funcster', 'js-yaml', 'libxmljs', 'libxmljs2'];
export class RaspCodeInstrumentation extends InstrumentationBase {
  constructor() { super('shield360/instrumentation-rasp-code', '1.0.0', { enabled: false }); }
  protected init(): InstrumentationNodeModuleDefinition[] {
    return libraries.map(name => new InstrumentationNodeModuleDefinition(name, ['*'],
      (exports, version) => { patch(name, moduleExports(exports), version); return exports; }, exports => unpatch(moduleExports(exports))));
  }
}
let instrumentation: RaspCodeInstrumentation | undefined;
export function patchLoaded(): void {
  for (const library of libraries) {
    try {
      const id = require.resolve(library);
      const cached = require.cache[id];
      if (cached) {
        let version: string | undefined;
        try {
          const manifest = require.cache[require.resolve(`${library}/package.json`)];
          version = (manifest?.exports as { version?: string } | undefined)?.version;
        } catch { /* Schema exports distinguish legacy js-yaml without loading it. */ }
        patch(library, cached.exports, version);
      }
    } catch { /* Never load an optional library. */ }
  }
}

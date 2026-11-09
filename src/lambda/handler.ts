/**
 * The Lambda layer's handler: starts Shield360 from the environment, loads the
 * function's own handler named by `SHIELD360_LAMBDA_HANDLER` (the same
 * `file.export` form as the function's Handler setting), and wraps it with
 * `wrapHandler`. No code changes in the function.
 *
 * Set by the layer's exec wrapper (`AWS_LAMBDA_EXEC_WRAPPER=/opt/shield360-wrapper`),
 * or by hand: Handler `/opt/nodejs/node_modules/shield360/dist/lambda/handler.handler`
 * and `SHIELD360_LAMBDA_HANDLER=index.handler`.
 *
 * Shield360 starts before the function's module loads, so the provider SDKs it
 * imports are instrumented.
 */
import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';
import { initFromEnvironment, wrapHandler, LambdaHandler } from './index';

const EXTENSIONS = ['.js', '.mjs', '.cjs'];

export interface HandlerSpec {
  /** Module path relative to the task root, without extension. */
  module: string;
  /** Export path inside the module, e.g. ['handler'] or ['handlers', 'api']. */
  exportPath: string[];
}

/** Splits `dir/file.export[.nested]` the way the Node.js runtime does. */
export function parseHandlerSpec(spec: string | undefined): HandlerSpec {
  const value = (spec ?? '').trim();
  if (!value) {
    throw new Error('Shield360: SHIELD360_LAMBDA_HANDLER is not set; set it to the function\'s own handler, e.g. index.handler.');
  }
  const slash = value.lastIndexOf('/');
  const base = value.slice(slash + 1);
  const dot = base.indexOf('.');
  if (dot <= 0 || dot === base.length - 1) {
    throw new Error(`Shield360: SHIELD360_LAMBDA_HANDLER "${value}" is not in the form file.export.`);
  }
  return {
    module: value.slice(0, slash + 1) + base.slice(0, dot),
    exportPath: base.slice(dot + 1).split('.'),
  };
}

function resolveModuleFile(taskRoot: string, modulePath: string): string {
  const base = path.resolve(taskRoot, modulePath);
  for (const ext of EXTENSIONS) {
    if (fs.existsSync(base + ext)) return base + ext;
  }
  if (fs.existsSync(base)) return base;
  throw new Error(`Shield360: cannot find the handler module ${modulePath} under ${taskRoot}.`);
}

// tsc compiles import() to require() for CommonJS output; this keeps a real dynamic import for ES modules.
const dynamicImport = new Function('specifier', 'return import(specifier)') as (s: string) => Promise<any>;

async function loadModule(file: string): Promise<any> {
  if (file.endsWith('.mjs')) return dynamicImport(pathToFileURL(file).href);
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(file);
  } catch (e) {
    const code = (e as { code?: string })?.code;
    if (code === 'ERR_REQUIRE_ESM' || code === 'ERR_REQUIRE_ASYNC_MODULE') return dynamicImport(pathToFileURL(file).href);
    throw e;
  }
}

/** Loads the function's own handler from `SHIELD360_LAMBDA_HANDLER` under `LAMBDA_TASK_ROOT`. */
export async function loadOriginalHandler(
  spec: string | undefined = process.env.SHIELD360_LAMBDA_HANDLER,
  taskRoot: string = process.env.LAMBDA_TASK_ROOT || process.cwd()
): Promise<LambdaHandler> {
  const { module: modulePath, exportPath } = parseHandlerSpec(spec);
  const mod = await loadModule(resolveModuleFile(taskRoot, modulePath));
  let target: any = mod;
  for (const key of exportPath) {
    target = target?.[key];
    // A CommonJS module imported as ESM puts its exports under `default`.
    if (target === undefined && mod?.default && key === exportPath[0]) target = mod.default[key];
  }
  if (typeof target !== 'function') {
    throw new Error(`Shield360: ${spec} is not a function exported by ${modulePath}.`);
  }
  return target as LambdaHandler;
}

let wrapped: Promise<(event: any, context: any) => Promise<any>> | undefined;

function wrappedHandler(): Promise<(event: any, context: any) => Promise<any>> {
  if (!wrapped) {
    initFromEnvironment();
    wrapped = loadOriginalHandler().then((h) => wrapHandler(h, { autoInit: false }));
  }
  return wrapped;
}

/** The entry point Lambda calls. */
export async function handler(event: any, context: any): Promise<any> {
  return (await wrappedHandler())(event, context);
}

/** Tests only. */
export function resetForTesting(): void {
  wrapped = undefined;
}

// Start Shield360 and load the function during the init phase, so the work counts as initialization,
// not as the first invocation. A load failure is reported by the first invocation.
if (process.env.SHIELD360_LAMBDA_HANDLER && process.env.SHIELD360_LAMBDA_EAGER !== 'false') {
  wrappedHandler().catch(() => undefined);
}

/**
 * Zero-code entry: starts Shield360 (telemetry and, when asked for, RASP)
 * from SHIELD360_* / OTEL_* environment variables before the app loads.
 *
 *   node --require shield360/register app.js
 *   NODE_OPTIONS="--require shield360/register" npm start
 *   node --import shield360/register app.mjs          (ESM apps)
 *
 * With RASP on (`SHIELD360_RASP=monitor|block`) the sink hooks go in before
 * the app takes references to `child_process`, `fs` and the drivers, and every
 * `http`/`https` server's requests are captured without middleware.
 * Where `module.register` exists, the OpenTelemetry ESM loader hook is
 * registered too, so instrumentations also patch packages the app `import`s
 * (`SHIELD360_ESM_HOOK=off` leaves it out).
 *
 * Fail open: anything that goes wrong prints one warning and the app starts
 * without Shield360. A later `Shield360.init()` in the app's code is a no-op.
 */
import type { Shield360Options } from './types';

const GLOBAL_SENTINEL = '__shield360_register_initialized__';
const MIN_NODE_MAJOR = 18;

declare global {
  // eslint-disable-next-line no-var
  var __shield360_register_initialized__: boolean | undefined;
}

function parseCSV(value?: string): string[] | undefined {
  if (!value) return undefined;
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length > 0 ? items : undefined;
}

function parseResourceAttributes(value?: string): Record<string, string> | null {
  if (!value) return null;
  const attrs: Record<string, string> = {};
  for (const item of value.split(',')) {
    const [rawKey, ...rawValue] = item.split('=');
    const key = rawKey?.trim();
    const attrValue = rawValue.join('=').trim();
    if (key && attrValue) attrs[key] = attrValue;
  }
  return Object.keys(attrs).length > 0 ? attrs : null;
}

function nodeVersionSupported(): boolean {
  const major = Number(process.versions.node.split('.')[0]);
  return Number.isFinite(major) && major >= MIN_NODE_MAJOR;
}

const isOff = (v: string | undefined) => ['off', 'false', '0', 'no'].includes((v || '').trim().toLowerCase());

/**
 * Node's module-hooks thread: a `--require` preload (NODE_OPTIONS included) runs there too. Starting
 * Shield360 or registering the loader hook again from inside it breaks every later `import`.
 */
function inModuleHooksThread(): boolean {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return (require('worker_threads') as { isInternalThread?: boolean }).isInternalThread === true;
}

/** The OpenTelemetry ESM loader hook (import-in-the-middle), so instrumentations see `import`ed packages. */
function registerEsmHook(): void {
  if (isOff(process.env.SHIELD360_ESM_HOOK)) return;
  // Registered once, from the main thread: hooks registered there apply to the whole process.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  if (!(require('worker_threads') as typeof import('worker_threads')).isMainThread) return;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('module') as { register?: (specifier: string, parentURL: string) => void };
  if (typeof mod.register !== 'function') return;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { pathToFileURL } = require('url') as typeof import('url');
  mod.register('@opentelemetry/instrumentation/hook.mjs', pathToFileURL(__filename).href);
}

function initFromEnv() {
  if (inModuleHooksThread()) return;
  if ((globalThis as any)[GLOBAL_SENTINEL]) return;
  (globalThis as any)[GLOBAL_SENTINEL] = true;

  if (!nodeVersionSupported()) {
    console.error(
      `Shield360 auto-instrumentation requires Node.js ${MIN_NODE_MAJOR} or newer; current runtime is ${process.version}.`
    );
    return;
  }

  try {
    // Loaded here, not at the top, so a module that fails to load is caught like any other start-up failure.
    /* eslint-disable @typescript-eslint/no-require-imports */
    const Shield360 = require('./index').default as { init: (o?: Shield360Options) => void };
    const { markZeroCodeStarted } = require('./zero-code') as typeof import('./zero-code');
    /* eslint-enable @typescript-eslint/no-require-imports */

    const options: Shield360Options = {
      applicationName: process.env.OTEL_SERVICE_NAME,
      environment: process.env.OTEL_DEPLOYMENT_ENVIRONMENT,
      disabledInstrumentors: parseCSV(process.env.SHIELD360_DISABLED_INSTRUMENTORS),
      customSpanAttributes: parseResourceAttributes(process.env.OTEL_RESOURCE_ATTRIBUTES),
    };

    Shield360.init(options);
    markZeroCodeStarted();

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const rasp = require('./rasp') as typeof import('./rasp');
    if (rasp.raspActive()) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      (require('./rasp/auto-http') as typeof import('./rasp/auto-http')).installAutoHttpCapture();
    }
    registerEsmHook();
  } catch (e) {
    console.warn(
      `Shield360: zero-code start-up failed (${e instanceof Error ? e.message : String(e)}); the app runs without Shield360.`
    );
  }
}

initFromEnv();

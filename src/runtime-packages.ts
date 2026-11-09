/**
 * SHIELD: runtime SCA — the packages this process runs, reported to Shield360
 * so it can match them against vulnerability data server-side (Security →
 * Code, target type "runtime").
 *
 * On by default whenever `init` has a Shield360 URL and API key, whether or
 * not runtime protection is on; `init({ runtimePackages: false })` or
 * `SHIELD360_RUNTIME_PACKAGES=off` turns it off. The report is the same
 * `shield360.rasp.component` record runtime protection sends (rasp/reporter.ts
 * `collectComponents`), on the same route (`POST /api/guard/events`, the app's
 * API key): the Node.js version, every npm package loaded through `require`
 * so far and the app's direct dependencies as installed. Names and versions
 * only, never a path; at most MAX_COMPONENTS. Sent once shortly after start
 * (so lazily required packages are in it) and then every day, off the call
 * path; a report that cannot be delivered is dropped.
 *
 * ESM: an ES module loaded with `import` is not in `require.cache`, so an app
 * that only imports ESM packages reports its direct dependencies and the
 * CommonJS packages it loads, not every transitive ESM package.
 *
 * Must stay in step with sdk/python/src/shield360/runtime_packages.py,
 * sdk/go/runtime_packages.go and sdk/dotnet/src/Shield360/RuntimePackages.cs.
 */
import { hostname } from 'os';
import { dirname } from 'path';
import { postGuardEvents } from './guard/report';
import { collectComponents, MAX_COMPONENTS, RASP_COMPONENT, type Component } from './rasp/reporter';

export const START_DELAY_MS = 15_000;
export const EVERY_MS = 24 * 60 * 60 * 1000;
const BATCH = 100;

export type RuntimePackagesContext = {
  url?: string;
  apiKey?: string;
  applicationName: string;
  environment?: string;
  sdkVersion?: string;
  fetchImpl?: typeof fetch;
  /** Tests: what to report instead of the real process. */
  collect?: () => Component[];
};

type State = { timers: Array<ReturnType<typeof setTimeout>>; report: () => Promise<boolean> };
let state: State | undefined;

/** Whether the report runs: the option wins when it is false; SHIELD360_RUNTIME_PACKAGES=off|false|0|no turns it off. */
export function runtimePackagesEnabled(option: boolean | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  if (option === false) return false;
  return !/^(off|false|0|no)$/i.test(String(env.SHIELD360_RUNTIME_PACKAGES ?? '').trim());
}

/** Whether the report is running (runtime protection then leaves its own components report to it). */
export function runtimePackagesActive(): boolean {
  return state !== undefined;
}

function moduleCache(): Record<string, unknown> {
  // Under a bundler or an ESM-only loader `require` may be missing.
  try {
    return typeof require === 'function' && require.cache ? (require.cache as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** The packages of this process: from the working directory and, when it differs, the entry script's. Names and versions only, at most MAX_COMPONENTS. */
export function collectRuntimePackages(cache: Record<string, unknown> = moduleCache(), cwd: string = process.cwd(), entry: string | null = process.argv[1] ?? null): Component[] {
  const out = collectComponents(cache, cwd);
  if (entry && out.length < MAX_COMPONENTS) {
    const seen = new Set(out.map((c) => `${c.ecosystem}\u0000${c.name}\u0000${c.version}`));
    for (let dir = dirname(entry), i = 0; i < 8 && dir !== cwd; i++, dir = dirname(dir)) {
      for (const c of collectComponents({}, dir)) {
        const id = `${c.ecosystem}\u0000${c.name}\u0000${c.version}`;
        if (seen.has(id) || out.length >= MAX_COMPONENTS) continue;
        seen.add(id);
        out.push(c);
      }
      if (dirname(dir) === dir) break;
    }
  }
  return out.slice(0, MAX_COMPONENTS);
}

function resource(ctx: RuntimePackagesContext): Record<string, string> {
  const r: Record<string, string> = { 'service.name': ctx.applicationName };
  try {
    const host = hostname();
    if (host) r['host.name'] = host;
  } catch {
    // no host name
  }
  if (ctx.environment) r['deployment.environment'] = ctx.environment;
  if (ctx.sdkVersion) r['service.version'] = ctx.sdkVersion;
  return r;
}

/** Sends one report now. Resolves whether every batch was accepted; never rejects. */
export async function reportRuntimePackages(ctx: RuntimePackagesContext): Promise<boolean> {
  if (!ctx.url || !ctx.apiKey) return false;
  let components: Component[];
  try {
    components = (ctx.collect ?? collectRuntimePackages)().slice(0, MAX_COMPONENTS);
  } catch {
    return false;
  }
  const time = new Date().toISOString();
  const events = components.map((c) => ({
    name: RASP_COMPONENT,
    time,
    attrs: {
      'shield360.rasp.app': ctx.applicationName,
      'shield360.rasp.component.ecosystem': c.ecosystem,
      'shield360.rasp.component.name': c.name,
      'shield360.rasp.component.version': c.version,
    },
  }));
  const endpoint = `${ctx.url.replace(/\/+$/, '')}/api/guard/events`;
  const res = resource(ctx);
  let ok = true;
  for (let i = 0; i < events.length; i += BATCH) {
    try {
      const sent = await postGuardEvents(endpoint, ctx.apiKey, { resource: res, events: events.slice(i, i + BATCH) }, { label: 'runtime package report', fetchImpl: ctx.fetchImpl });
      ok = ok && sent;
      if (!sent) break;
    } catch {
      return false;
    }
  }
  return ok;
}

/** Starts the report: once after START_DELAY_MS, then every EVERY_MS. Idempotent; never keeps the process alive. */
export function startRuntimePackages(ctx: RuntimePackagesContext, option?: boolean, env: NodeJS.ProcessEnv = process.env): boolean {
  if (state || !ctx.url || !ctx.apiKey || !runtimePackagesEnabled(option, env)) return false;
  const report = () => reportRuntimePackages(ctx).catch(() => false);
  const first = setTimeout(() => void report(), START_DELAY_MS);
  first.unref?.();
  const every = setInterval(() => void report(), EVERY_MS);
  every.unref?.();
  state = { timers: [first, every], report };
  return true;
}

/** Stops the report (tests, re-init). */
export function stopRuntimePackages(): void {
  if (!state) return;
  for (const t of state.timers) clearTimeout(t as ReturnType<typeof setTimeout>);
  state = undefined;
}

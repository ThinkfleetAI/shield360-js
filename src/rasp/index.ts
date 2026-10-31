/**
 * Shield360 runtime application self-protection (RASP), opt-in.
 *
 *   Shield360.init({ rasp: { enabled: true, configPublicKey: process.env.SHIELD360_CONFIG_PUBLIC_KEY } });
 *   app.use(raspExpress());
 *
 * or `SHIELD360_RASP=monitor|block`. `SHIELD360_RASP=off` always wins.
 * sdk/rasp/README.md is the contract. Fail open everywhere: the only error
 * RASP raises on purpose is `RaspBlockedError`, which the middleware turns
 * into a 403.
 *
 * This part covers request capture, model output as input, the detection
 * engine, virtual patches, the signed config, events, and the sink hooks:
 * child_process, fs, outbound HTTP, database drivers, and code,
 * deserialization, XML and HTML responses; and sink rules, which point those
 * checks at further library functions from data (built in, or the signed
 * config).
 */
import { tmpdir } from 'os';
import { join } from 'path';
import { runBaseline } from './baseline';
import { parseDeception } from './deception';
import { parsePublicKeys, RaspConfigClient, type RaspClaims } from './config-client';
import {
  applicationName,
  configureEngine,
  envSetting,
  isActive,
  setEventSink,
  setMonitorOnly,
  setRemoteConfig,
  setRuntimeDisabled,
  type RemoteConfig,
} from './engine';
import { installCodeHooks, uninstallCodeHooks } from './hooks/code';
import { installDbHooks, uninstallDbHooks } from './hooks/db';
import { installFsHooks, uninstallFsHooks } from './hooks/fs';
import { installHttpHooks, uninstallHttpHooks } from './hooks/http';
import { installIncludeHooks, uninstallIncludeHooks } from './hooks/include';
import { installProcessHooks, uninstallProcessHooks } from './hooks/process';
import { BUILT_IN_SINKS, installSinkHooks, parseSinkRules, setSinkRules, uninstallSinkHooks } from './hooks/sinks';
import { configureIast, setIastRemote, setIastSink } from './iast';
import { collectComponents, RaspReporter } from './reporter';
import type { RaspOptions } from './types';

const COMPONENTS_EVERY_MS = 24 * 60 * 60 * 1000;

export type RaspInitContext = {
  applicationName: string;
  environment?: string;
  url?: string;
  apiKey?: string;
  sdkVersion?: string;
  /** The OTLP endpoint the SDK exports to: always allowed outbound, like `url`. */
  otlpEndpoint?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
};

/** The hosts of the Shield360 URL and the OTLP endpoint (README "SSRF": always allowed). */
export function alwaysAllowedHosts(urls: (string | undefined)[]): string[] {
  const hosts = new Set<string>();
  for (const u of urls) {
    try {
      if (u) hosts.add(new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, ''));
    } catch {
      // not a URL: nothing to allow
    }
  }
  return [...hosts];
}

const PRODUCTION = /^prod(uction)?$/i;

/**
 * Whether trust on first use is allowed: the explicit opt-in
 * (`allowUnpinnedConfig` or `SHIELD360_CONFIG_TOFU=dev`), never when
 * `NODE_ENV` or `ENVIRONMENT` says production.
 */
export function tofuAllowed(option: boolean | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  const asked = option === true || (env.SHIELD360_CONFIG_TOFU || '').trim().toLowerCase() === 'dev';
  if (!asked) return false;
  return ![env.NODE_ENV, env.ENVIRONMENT].some((v) => PRODUCTION.test((v || '').trim()));
}

let warnedUnpinned = false;

/** One log line per process when the config key is not pinned (not a reported event). */
function warnUnpinnedOnce(): void {
  if (warnedUnpinned) return;
  warnedUnpinned = true;
  console.warn(
    "Shield360 RASP: the signed config key is not pinned, so the signed config is not used and RASP runs its built-in defaults in monitor mode. Set configPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY) to the environment's public key from the app's Runtime protection settings in Shield360.",
  );
}

/** Tests only: lets the once-per-process warning fire again. */
export function resetRaspWarnings(): void {
  warnedUnpinned = false;
}

type Runtime = { client?: RaspConfigClient; reporter?: RaspReporter; componentsTimer?: ReturnType<typeof setInterval> };
let runtime: Runtime = {};

export function toRemote(c: RaspClaims): RemoteConfig {
  return {
    version: c.version,
    exp: c.exp,
    killSwitch: c.killSwitch === true,
    snippets: c.snippets === true,
    reportTargets: c.reportTargets === true,
    mode: c.mode,
    attacks: c.attacks && typeof c.attacks === 'object' ? c.attacks : {},
    allow: c.allow && typeof c.allow === 'object' ? c.allow : undefined,
    rules: Array.isArray(c.rules) ? c.rules : null,
    sinks: Array.isArray(c.sinks) ? c.sinks : null,
    customRules: Array.isArray(c.customRules) ? c.customRules : null,
    deception: parseDeception(c.deception),
  };
}

/** Normalises `init({ rasp })`: true, false, or options (an object means on unless `enabled: false`). */
export function resolveRaspOptions(option: boolean | RaspOptions | undefined, env: NodeJS.ProcessEnv = process.env): RaspOptions & { enabled: boolean } {
  const e = envSetting(env);
  const o: RaspOptions = typeof option === 'object' && option !== null ? option : {};
  let enabled = option === true || (typeof option === 'object' && option !== null && option.enabled !== false);
  if (option === undefined && (e === 'monitor' || e === 'block')) enabled = true;
  if (e === 'off') enabled = false;
  return { ...o, enabled };
}

/** Stops polling, reporting and the components timer, and removes the sink hooks (tests, re-init). */
export async function shutdownRasp(): Promise<void> {
  const r = runtime;
  runtime = {};
  uninstallProcessHooks();
  uninstallFsHooks();
  uninstallHttpHooks();
  uninstallDbHooks();
  uninstallCodeHooks();
  uninstallSinkHooks();
  uninstallIncludeHooks();
  r.client?.stop();
  if (r.componentsTimer) clearInterval(r.componentsTimer);
  setEventSink(undefined);
  setIastSink(undefined);
  await r.reporter?.stop();
}

/**
 * Turns RASP on (or leaves it off) for this process. Returns whether it is
 * on. Never throws.
 */
export function initRasp(option: boolean | RaspOptions | undefined, ctx: RaspInitContext): boolean {
  try {
    void shutdownRasp();
    const env = ctx.env ?? process.env;
    const o = resolveRaspOptions(option, env);
    const remoteWanted = o.enabled && o.remote !== false && Boolean(ctx.url && ctx.apiKey);
    const pinned = parsePublicKeys(o.configPublicKey ?? env.SHIELD360_CONFIG_PUBLIC_KEY);
    const tofu = !pinned.length && tofuAllowed(o.allowUnpinnedConfig, env);
    const unpinned = remoteWanted && !pinned.length && !tofu;
    configureEngine({
      enabled: o.enabled,
      applicationName: ctx.applicationName,
      mode: o.mode,
      attacks: o.attacks,
      allow: o.allow,
      modelOutput: o.modelOutput,
      // No pinned key while a remote config was expected: built-in defaults, monitor only.
      monitorOnly: unpinned,
      env,
    });
    configureIast({ option: o.iast, applicationName: ctx.applicationName, environment: ctx.environment, env });
    if (!o.enabled) return false;
    installProcessHooks();
    installFsHooks();
    installHttpHooks({ alwaysAllowedHosts: alwaysAllowedHosts([ctx.url, ctx.otlpEndpoint]) });
    installDbHooks();
    installCodeHooks();
    installSinkHooks();
    installIncludeHooks();

    let reporter: RaspReporter | undefined;
    if (ctx.url && ctx.apiKey) {
      reporter = new RaspReporter({
        url: ctx.url,
        apiKey: ctx.apiKey,
        applicationName: ctx.applicationName,
        environment: ctx.environment,
        sdkVersion: ctx.sdkVersion,
        fetchImpl: ctx.fetchImpl,
      });
      reporter.start();
      setEventSink(reporter);
      setIastSink(reporter);
      runtime.reporter = reporter;
      if (o.components !== false) {
        const report = () => {
          try {
            reporter?.reportComponents(collectComponents());
          } catch {
            // never
          }
        };
        setImmediate(report).unref?.();
        runtime.componentsTimer = setInterval(report, COMPONENTS_EVERY_MS);
        runtime.componentsTimer.unref?.();
      }
    }

    // Logged, once per reason (the client dedupes); trust on first use was already announced at start.
    const warn = (reason: string) => {
      if (reason === 'trust_on_first_use') return;
      console.warn(`Shield360 RASP: a signed config was refused (${reason}); the last verified config or the local options stay in force.`);
    };

    if (unpinned) {
      warnUnpinnedOnce();
    } else if (remoteWanted) {
      if (tofu) console.warn('Shield360 RASP: trust on first use is on for the signed config (development only); set configPublicKey before production.');
      const client = new RaspConfigClient({
        url: ctx.url as string,
        apiKey: ctx.apiKey as string,
        app: ctx.applicationName,
        pinned,
        allowUnpinned: tofu,
        cacheDir: o.cacheDir || join(tmpdir(), 'shield360-rasp'),
        onConfig: (claims) => {
          const remote = claims ? toRemote(claims) : undefined;
          setRemoteConfig(remote);
          setIastRemote(claims ? { iast: claims.iast, iastSampleRate: claims.iastSampleRate, version: claims.version } : undefined);
          // The platform's sink rules replace the built-in list when present.
          setSinkRules(remote?.sinks ? parseSinkRules(remote.sinks) : BUILT_IN_SINKS);
        },
        onWarning: warn,
        fetchImpl: ctx.fetchImpl,
      });
      runtime.client = client;
      client.start();
    }
    // Off the start-up path, once the reporter is in place.
    setImmediate(() => runBaseline({ environment: ctx.environment, remoteWanted, pinned: pinned.length > 0, env })).unref?.();
    return true;
  } catch (e) {
    console.warn(`Shield360 RASP could not start: ${e instanceof Error ? e.name : 'error'}`);
    return false;
  }
}

/** The runtime kill switch: checks return immediately until `enableRasp()`. */
export function disableRasp(): void {
  setRuntimeDisabled(true);
}

/** Undoes `disableRasp()`. The env switch and the signed config's kill switch still win. */
export function enableRasp(): void {
  setRuntimeDisabled(false);
}

/** Whether RASP checks run right now (on, and no kill switch). */
export function raspActive(): boolean {
  return isActive();
}

export { applicationName as raspApplicationName, setMonitorOnly };
export { RaspBlockedError, RaspBlockedError as Shield360RaspBlocked, blockBody, BLOCK_MESSAGE, ATTACK_TYPES } from './types';
export type { RaspOptions, RaspMode, AttackType, RaspInput, Finding, ConfigPublicKey } from './types';
export type { RaspExpressOptions } from './middleware';
export { raspExpress, raspExpressErrorHandler, raspFastify, raspKoa, raspHttp, withRasp, recordRequestBody, isRaspBlocked, sendBlocked, blockedResponse } from './middleware';
export { recordModelOutput, recordToolArguments } from './model-output';
export { runInRaspScope, currentContext as currentRaspContext, inputsOf } from './context';
export { check as raspCheck } from './engine';
export { compileRuleExpr, evaluateRuleExpr, RULE_EXPR_LIMITS, RULE_FIELDS } from './rule-expr';
export type { RuleSubject, RuleExprErrorCode } from './rule-expr';

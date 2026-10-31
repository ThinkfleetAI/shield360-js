/**
 * Security baseline (README "Security baseline"): a one-time look, when RASP
 * starts, at how the running process is set up, reported as `baseline`
 * events (monitor only, never blocks). Each rule reads a flag, a version or
 * an id, never a secret value, and reports only that a setting is risky.
 * Adapted from the idea of OpenRASP's start-up security policy checks.
 */
import inspector = require('inspector');
import { check } from './engine';
import type { Finding } from './types';

const PRODUCTION = /^prod(uction)?$/i;
const INSPECT_FLAG = /(^|\s)--inspect(-brk|-port|-wait)?(=|\s|$)/;

/**
 * End of life of each Node.js release line (the last day it gets security
 * fixes). Odd lines end six months after their release; only the long-term
 * lines an app is likely to run are listed.
 */
export const NODE_END_OF_LIFE: Readonly<Record<number, string>> = Object.freeze({
  14: '2023-04-30',
  16: '2023-09-11',
  18: '2025-04-30',
  20: '2026-04-30',
  22: '2027-04-30',
  24: '2028-04-30',
});

export type BaselineInput = {
  env: NodeJS.ProcessEnv;
  /** The SDK's own environment name (init option). */
  environment?: string;
  /** A signed config was expected (URL and API key set, remote on). */
  remoteWanted: boolean;
  /** A config public key is pinned. */
  pinned: boolean;
  execArgv: readonly string[];
  nodeVersion: string;
  /** POSIX user id, when the platform has one. */
  uid?: number;
  /** Whether the inspector is listening. */
  inspectorOpen: boolean;
  now: Date;
};

export function isProduction(env: NodeJS.ProcessEnv, environment?: string): boolean {
  return [env.NODE_ENV, env.ENVIRONMENT, environment].some((v) => PRODUCTION.test((v || '').trim()));
}

/** The baseline rules that fire for this process, in a fixed order. Pure. */
export function baselineFindings(i: BaselineInput): Finding[] {
  const out: Finding[] = [];
  const production = isProduction(i.env, i.environment);
  const hit = (rule: string) => out.push({ attack: 'baseline', rule });

  // TLS certificate checks switched off for every outbound connection.
  if ((i.env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0') hit('baseline.tls_verify_off');
  // A debugger port open in production lets anyone who reaches it run code.
  if (production && (i.inspectorOpen || i.execArgv.some((a) => INSPECT_FLAG.test(a)) || INSPECT_FLAG.test(i.env.NODE_OPTIONS || ''))) {
    hit('baseline.inspector_in_production');
  }
  // The SDK says production while NODE_ENV says development: frameworks then run in development mode.
  if (PRODUCTION.test((i.environment || i.env.ENVIRONMENT || '').trim()) && (i.env.NODE_ENV || '').trim().toLowerCase() === 'development') {
    hit('baseline.development_mode_in_production');
  }
  if (i.uid === 0) hit('baseline.running_as_root');
  // In production the signed config must be verified against a pinned key.
  if (production && i.remoteWanted && !i.pinned) hit('baseline.config_key_unpinned');
  const major = Number(i.nodeVersion.replace(/^v/, '').split('.')[0]);
  const eol = NODE_END_OF_LIFE[major] ?? (major % 2 === 1 || major < 14 ? '1970-01-01' : undefined);
  if (eol && i.now.toISOString().slice(0, 10) > eol) hit('baseline.runtime_end_of_life');
  return out;
}

let ran = false;

/** Runs the baseline once per process and reports what it finds. Never throws. */
export function runBaseline(opts: { environment?: string; remoteWanted: boolean; pinned: boolean; env?: NodeJS.ProcessEnv }): void {
  if (ran) return;
  ran = true;
  try {
    const findings = baselineFindings({
      env: opts.env ?? process.env,
      environment: opts.environment,
      remoteWanted: opts.remoteWanted,
      pinned: opts.pinned,
      execArgv: process.execArgv,
      nodeVersion: process.versions.node,
      uid: typeof process.getuid === 'function' ? process.getuid() : undefined,
      inspectorOpen: Boolean(inspector.url()),
      now: new Date(),
    });
    for (const f of findings) check('startup', () => f);
  } catch {
    // fail open
  }
}

/** Tests only: lets the baseline run again. */
export function resetBaseline(): void {
  ran = false;
}

/**
 * Guard heartbeat: tells Shield360 which guards this app runs, in which mode.
 *
 * Guard reports (report.ts) carry only what a guard acted on, so an app whose
 * guards had nothing to stop looks the same as one with no guards. When
 * `init` is given guards and a Shield360 URL and API key, the SDK also sends
 * a heartbeat once at start and then about every five minutes (jittered):
 * the app's service name, each guard kind's mode (off, warn or block),
 * whether prompt-injection checks are on, and the SDK's name and version.
 * Never any text, host or user. It goes through the same queue and
 * transport as guard reports and never throws.
 *
 * Turn it off with `guardHeartbeat: false` in `init`, or
 * SHIELD360_GUARD_HEARTBEAT=false.
 *
 * Must stay in sync with: sdk/python/src/shield360/guard/_heartbeat.py
 */

import { Guard, GuardAction } from './base';

export const HEARTBEAT_EVENT_NAME = 'shield360.guard.heartbeat';
export const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000;
/** Up to this share of the interval is added or taken away at random, so a fleet does not beat in step. */
export const HEARTBEAT_JITTER = 0.2;
export const SDK_HEARTBEAT_NAME = 'shield360-typescript';

export type GuardMode = 'off' | 'warn' | 'block';
const RANK: Record<GuardMode, number> = { off: 0, warn: 1, block: 2 };
const KIND = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

/** A guard's mode: deny and redact keep data from the model (block), warn warns, allow does nothing. */
export function modeOf(action: GuardAction | string): GuardMode {
  if (action === GuardAction.DENY || action === GuardAction.REDACT) return 'block';
  if (action === GuardAction.WARN) return 'warn';
  return 'off';
}

/** Each guard kind's mode, the strongest when one kind is configured twice. Kinds that are not plain names are left out. */
export function guardModes(guards: readonly Guard[]): Record<string, GuardMode> {
  const modes: Record<string, GuardMode> = {};
  for (const guard of guards) {
    try {
      const kind = String(guard?.name || '').toLowerCase();
      if (!KIND.test(kind)) continue;
      const mode = modeOf(guard.action);
      if (!modes[kind] || RANK[mode] > RANK[modes[kind]]) modes[kind] = mode;
    } catch {
      // a guard that cannot be read is left out
    }
  }
  return modes;
}

/** The heartbeat's attributes. */
export function heartbeatAttrs(guards: readonly Guard[], app: string, sdkVersion: string): Record<string, string> {
  const modes = guardModes(guards);
  const injection = modes.prompt_injection ? modes.prompt_injection !== 'off' : false;
  return {
    'shield360.guard.app': app,
    'shield360.guard.modes': JSON.stringify(modes),
    'shield360.guard.injection': injection ? 'true' : 'false',
    'shield360.sdk.name': SDK_HEARTBEAT_NAME,
    'shield360.sdk.version': sdkVersion,
  };
}

/** The next delay: the interval give or take the jitter. */
export function nextDelay(random: () => number = Math.random): number {
  return Math.round(HEARTBEAT_INTERVAL_MS * (1 + (random() * 2 - 1) * HEARTBEAT_JITTER));
}

/** Whether heartbeats are wanted: on unless the option or the environment turns them off. */
export function heartbeatEnabled(option: boolean | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  if (option === false) return false;
  const value = (env.SHIELD360_GUARD_HEARTBEAT || '').trim().toLowerCase();
  return !['false', '0', 'no', 'off'].includes(value);
}

/**
 * Shield Protect -- the enforcement mode of this process.
 *
 *   observe   every check runs and its finding is recorded (span event,
 *             decision report); nothing is refused. For seeing what enforced
 *             mode would stop before turning it on.
 *   warn      as observe, and the finding is logged as a warning.
 *   enforced  a finding refuses the call; a guard that throws refuses the
 *             call (fail closed, whatever guardFailOpen says); a provider
 *             named in `required` that could not be wrapped stops startup;
 *             a streamed completion that postflight guards cannot inspect
 *             is refused; input past the scan bound is refused rather than
 *             scanned in part.
 *
 * The mode set in code is a floor: SHIELD360_PROTECT_MODE can raise it and
 * never lower it, so an environment variable in a shell or a container
 * cannot weaken what the application was deployed with. With no mode set
 * anywhere, guards behave as they always have (each guard's own action,
 * guardFailOpen as given): that is `legacy`, and nothing changes for an
 * application that never asked for Protect.
 *
 * What this layer can and cannot claim: it runs inside the application's
 * process. Code that can disable the SDK, import a provider the SDK does
 * not wrap, or reach a network directly is not stopped by it. The
 * mandatory boundary is the Shield360 gateway; this layer is monitored or
 * partially protected, and its readiness report says so.
 *
 * Must stay in sync with: sdk/python/src/shield360/protect/_mode.py
 */

export type ProtectMode = 'observe' | 'warn' | 'enforced';
export const PROTECT_MODES: readonly ProtectMode[] = ['observe', 'warn', 'enforced'];
const RANK: Record<ProtectMode, number> = { observe: 0, warn: 1, enforced: 2 };

export const PROTECT_MODE_ENV = 'SHIELD360_PROTECT_MODE';
export const PROTECT_REQUIRED_ENV = 'SHIELD360_PROTECT_REQUIRED';

export function isProtectMode(value: unknown): value is ProtectMode {
  return typeof value === 'string' && (PROTECT_MODES as readonly string[]).includes(value);
}

/** The stricter of two modes; undefined counts as nothing. */
export function strictestMode(a?: ProtectMode, b?: ProtectMode): ProtectMode | undefined {
  if (!a) return b;
  if (!b) return a;
  return RANK[a] >= RANK[b] ? a : b;
}

/**
 * The mode this process runs under: what the code set, raised by the
 * environment when the environment asks for more. An environment value
 * that is not a mode is ignored, never a downgrade.
 */
export function resolveProtectMode(fromCode?: ProtectMode, env: NodeJS.ProcessEnv = process.env): ProtectMode | undefined {
  const raw = (env[PROTECT_MODE_ENV] || '').trim().toLowerCase();
  const fromEnv = isProtectMode(raw) ? raw : undefined;
  return strictestMode(fromCode, fromEnv);
}

/** Providers that must be wrapped: the code's list plus the environment's. */
export function resolveRequired(fromCode: string[] = [], env: NodeJS.ProcessEnv = process.env): string[] {
  const fromEnv = (env[PROTECT_REQUIRED_ENV] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return Array.from(new Set([...fromCode, ...fromEnv]));
}

export type ProtectConfig = {
  mode?: ProtectMode;
  /** npm package names whose provider methods must be wrapped, or startup fails in enforced mode: "openai", "@anthropic-ai/sdk". */
  required?: string[];
};

export type ResolvedProtect = { mode?: ProtectMode; required: string[] };

export function resolveProtect(config: ProtectConfig | undefined, env: NodeJS.ProcessEnv = process.env): ResolvedProtect {
  return { mode: resolveProtectMode(config?.mode, env), required: resolveRequired(config?.required, env) };
}

export const refuses = (mode: ProtectMode | undefined): boolean => mode === 'enforced';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ProtectError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = 'ProtectError';
  }
}

/** A call refused by Protect for a reason that is not a guard finding: oversized input, uninspectable streaming, a failed check. */
export class ProtectDeniedError extends ProtectError {
  readonly code: 'oversized' | 'streaming' | 'guard_failed' | 'not_authorized' | 'authorize_failed';
  constructor(code: ProtectDeniedError['code'], message: string) {
    super(message);
    this.name = 'ProtectDeniedError';
    this.code = code;
  }
}

/** Enforced mode could not be set up: a required provider is not wrapped, or guards are missing. Thrown from init. */
export class ProtectReadinessError extends ProtectError {
  readonly missing: string[];
  constructor(missing: string[], message: string) {
    super(message);
    this.name = 'ProtectReadinessError';
    this.missing = missing;
  }
}

// ---------------------------------------------------------------------------
// Readiness: what this process can honestly claim
// ---------------------------------------------------------------------------

export type ProtectReadiness = {
  mode: ProtectMode | 'legacy';
  /** Provider packages whose methods were wrapped. */
  wrapped: string[];
  /** Provider packages named as required that were not wrapped. */
  missing: string[];
  /** monitored: in-process checks that code in the same process can bypass. Never "enforced": that is the gateway's claim. */
  level: 'monitored' | 'partially_protected';
  note: string;
};

let state: { mode?: ProtectMode; wrapped: string[]; missing: string[] } = { wrapped: [], missing: [] };

/** @internal */
export function setProtectState(next: { mode?: ProtectMode; wrapped: string[]; missing: string[] }): void {
  state = { mode: next.mode, wrapped: [...next.wrapped], missing: [...next.missing] };
}

/** @internal */
export function currentProtectMode(): ProtectMode | undefined {
  return state.mode;
}

export function protectReadiness(): ProtectReadiness {
  const mode = state.mode ?? 'legacy';
  const partial = mode === 'enforced' && state.missing.length === 0 && state.wrapped.length > 0;
  return {
    mode,
    wrapped: [...state.wrapped],
    missing: [...state.missing],
    level: partial ? 'partially_protected' : 'monitored',
    note: partial
      ? 'Supported provider calls in this process are refused before they leave when a guard finds a violation, and fail closed. Code in this process that bypasses the SDK is not covered; the mandatory boundary is the Shield360 gateway.'
      : 'Findings are recorded; calls are not refused by this layer. The mandatory boundary is the Shield360 gateway.',
  };
}

/** @internal for tests */
export function resetProtectState(): void {
  state = { wrapped: [], missing: [] };
}

/**
 * The RASP context of the request (or worker job) being served, kept in
 * AsyncLocalStorage. Inputs live here, in memory, for the life of the
 * request only; nothing in this file sends or stores them anywhere else.
 */
import { AsyncLocalStorage } from 'async_hooks';
import type { CustomRuleState } from './custom-rules';
import type { RaspInput } from './types';
import type { VpRequest } from './vpatch';

export type RaspContext = {
  inputs: RaspInput[];
  /** Parsed body and query trees (for nosql_injection). */
  trees: unknown[];
  inRequest: boolean;
  method?: string;
  path?: string;
  /** The route template when the framework knows it. */
  route?: string;
  framework?: string;
  /** The client address as the framework reports it (custom rules' `request.ip`). */
  ip?: string;
  /** Custom-rule state for this request (custom-rules.ts). */
  rules?: CustomRuleState;
  /** How many of `inputs` were known before the body (set when the body is captured): head rules see only these. */
  headInputs?: number;
  /** Virtual-patch state: the request as the rules see it. */
  vp?: { req: VpRequest; bodyKnown: boolean; ranHead: boolean; ranBody: boolean };
  /**
   * Captures a body that a parser set after the middleware ran (Express or
   * Koa with the body parser registered later). Called when a sink reads
   * the inputs, until it reports the body was found (returns other than false).
   */
  late?: () => boolean | void;
  /** SHIELD: set on the context the zero-code `http` capture (shield360/register) made. */
  auto?: boolean;
  /** SHIELD: deception already ran for this request (the zero-code capture runs it first), so middleware skips it. */
  deception?: boolean;
};

export const storage = new AsyncLocalStorage<RaspContext>();

export function currentContext(): RaspContext | undefined {
  return storage.getStore();
}

export function newContext(init: Partial<RaspContext> = {}): RaspContext {
  return { inputs: [], trees: [], inRequest: false, ...init };
}

/**
 * The context's inputs, after any late body capture. Sinks call this rather
 * than reading `inputs` directly. A virtual patch matched by the late body
 * throws the block error from here.
 */
export function inputsOf(ctx: RaspContext): RaspInput[] {
  const late = ctx.late;
  if (late) {
    ctx.late = undefined;
    if (late() === false) ctx.late = late;
  }
  return ctx.inputs;
}

/** Runs fn in a fresh context that is not a request (a worker acting on a model's answer). */
export function runInRaspScope<T>(fn: () => T): T {
  return storage.run(newContext(), fn);
}

/** Runs fn with a context holding the given inputs (workers, tests). */
export function runWithInputs<T>(inputs: RaspInput[], fn: () => T, extra: Partial<RaspContext> = {}): T {
  return storage.run(newContext({ inputs: [...inputs], ...extra }), fn);
}

const ID_SEGMENT = /^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,})$/i;

/** Route fallback: all-digit, UUID and hex (8+, with a digit) segments become `:id`. */
export function routeOf(path: string): string {
  return path
    .split('?')[0]
    .split('/')
    .map((s) => (ID_SEGMENT.test(s) ? ':id' : s))
    .join('/');
}

const KEPT_SEGMENT = /^(?:[a-z][a-z_.-]{0,15}|v\d{1,2})$/;

/**
 * The route every event carries when the framework gave no template (README
 * "Event route"): the route fallback, then every segment that is not a short
 * lower-case word (or an API version such as `v2`) becomes `:id`, so a token,
 * name or other value in the path never reaches an event.
 */
export function eventRouteOf(path: string): string {
  return routeOf(path)
    .split('/')
    .map((seg) => (seg === '' || seg === ':id' || KEPT_SEGMENT.test(seg) ? seg : ':id'))
    .join('/');
}

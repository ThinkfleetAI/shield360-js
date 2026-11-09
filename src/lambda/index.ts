/**
 * AWS Lambda support: `wrapHandler(handler)` traces each invocation as a
 * `faas` span (OpenTelemetry FaaS semantic conventions) and flushes traces,
 * metrics and logs before the invocation returns, so nothing is lost when
 * Lambda freezes the execution environment.
 *
 *   import { wrapHandler } from 'shield360/lambda';
 *   export const handler = wrapHandler(async (event, context) => { ... });
 *
 * The flush is bounded (`SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS`, 2000 ms by
 * default, and never past the invocation's own deadline), so a slow or
 * unreachable collector cannot make the function time out.
 *
 * The Shield360 Lambda layer starts Shield360 and wraps the function's
 * handler without code changes (see `./handler`).
 */
import { context as otelContext, metrics, propagation, trace, Span, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { logs } from '@opentelemetry/api-logs';

/** The parts of the Lambda context object this module reads. */
export interface LambdaContext {
  awsRequestId?: string;
  functionName?: string;
  functionVersion?: string;
  invokedFunctionArn?: string;
  memoryLimitInMB?: string | number;
  getRemainingTimeInMillis?: () => number;
  [key: string]: unknown;
}

export type LambdaCallback = (error?: unknown, result?: unknown) => void;
export type LambdaHandler = (event: any, context: any, callback?: LambdaCallback) => unknown;

export interface WrapHandlerOptions {
  /** Longest wait for the flush after each invocation, in ms (default 2000, or `SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS`). */
  flushTimeoutMs?: number;
  /**
   * Start Shield360 from SHIELD360_* / OTEL_* environment variables when nothing has started it yet
   * (default true). With false, the app calls `Shield360.init()` itself.
   */
  autoInit?: boolean;
}

export type FaasTrigger = 'http' | 'pubsub' | 'datasource' | 'timer' | 'other';

const DEFAULT_FLUSH_TIMEOUT_MS = 2000;
/** Time left for the runtime to return the result after the flush gives up. */
const DEADLINE_MARGIN_MS = 100;
const TRACER_NAME = 'shield360-lambda';

const COLD_START = '__shield360_lambda_cold_start__';
type ColdStartGlobal = typeof globalThis & { [COLD_START]?: boolean };

/**
 * True for the first invocation in this execution environment. An environment started for
 * provisioned concurrency was initialized ahead of the request, so its first invocation is not cold.
 */
function takeColdStart(): boolean {
  const g = globalThis as ColdStartGlobal;
  if (g[COLD_START] === false) return false;
  g[COLD_START] = false;
  return process.env.AWS_LAMBDA_INITIALIZATION_TYPE !== 'provisioned-concurrency';
}

/** Tests only. */
export function resetColdStartForTesting(): void {
  delete (globalThis as ColdStartGlobal)[COLD_START];
}

/** The `faas.trigger` value for an incoming event, read from its shape. */
export function detectTrigger(event: unknown): FaasTrigger {
  if (!event || typeof event !== 'object') return 'other';
  const e = event as Record<string, any>;
  // API Gateway (REST and HTTP APIs), function URLs and ALB targets.
  if (e.requestContext && (e.httpMethod || e.requestContext.http || e.requestContext.elb)) return 'http';
  if (e.httpMethod && e.headers) return 'http';
  if (Array.isArray(e.Records) && e.Records.length > 0) {
    const source = String(e.Records[0]?.eventSource ?? e.Records[0]?.EventSource ?? '');
    if (['aws:sqs', 'aws:sns', 'aws:kinesis', 'aws:kafka'].includes(source)) return 'pubsub';
    if (['aws:s3', 'aws:dynamodb'].includes(source)) return 'datasource';
  }
  if (e.source === 'aws.events' && e['detail-type'] === 'Scheduled Event') return 'timer';
  if (e.source === 'aws.scheduler') return 'timer';
  return 'other';
}

function accountFromArn(arn?: string): string | undefined {
  // arn:aws:lambda:<region>:<account>:function:<name>[:<qualifier>]
  const parts = (arn ?? '').split(':');
  return parts.length >= 5 && parts[4] ? parts[4] : undefined;
}

/** The function's ARN without an alias or version qualifier (`cloud.resource_id`). */
function unqualifiedArn(arn?: string): string | undefined {
  if (!arn) return undefined;
  const parts = arn.split(':');
  return parts.length > 7 ? parts.slice(0, 7).join(':') : arn;
}

function headersOf(event: any): Record<string, string> | undefined {
  const headers = event && typeof event === 'object' ? event.headers : undefined;
  if (!headers || typeof headers !== 'object') return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (typeof v === 'string') out[k.toLowerCase()] = v;
  }
  return out;
}

/** Span attributes for one invocation: FaaS and cloud semantic conventions, plus HTTP basics for HTTP triggers. */
export function invocationAttributes(
  event: unknown,
  ctx: LambdaContext | undefined,
  coldStart: boolean,
  trigger: FaasTrigger = detectTrigger(event)
): Record<string, string | number | boolean> {
  const attrs: Record<string, string | number | boolean> = {
    'faas.trigger': trigger,
    'faas.coldstart': coldStart,
    'cloud.provider': 'aws',
    'cloud.platform': 'aws_lambda',
  };
  const name = ctx?.functionName ?? process.env.AWS_LAMBDA_FUNCTION_NAME;
  if (name) attrs['faas.name'] = name;
  const version = ctx?.functionVersion ?? process.env.AWS_LAMBDA_FUNCTION_VERSION;
  if (version) attrs['faas.version'] = version;
  if (ctx?.awsRequestId) attrs['faas.invocation_id'] = ctx.awsRequestId;
  const memory = Number(ctx?.memoryLimitInMB ?? process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE);
  if (Number.isFinite(memory) && memory > 0) attrs['faas.max_memory'] = memory * 1024 * 1024;
  const region = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
  if (region) attrs['cloud.region'] = region;
  if (ctx?.invokedFunctionArn) {
    attrs['aws.lambda.invoked_arn'] = ctx.invokedFunctionArn;
    const resourceId = unqualifiedArn(ctx.invokedFunctionArn);
    if (resourceId) attrs['cloud.resource_id'] = resourceId;
    const account = accountFromArn(ctx.invokedFunctionArn);
    if (account) attrs['cloud.account.id'] = account;
  }
  if (trigger === 'http' && event && typeof event === 'object') {
    const e = event as Record<string, any>;
    const method = e.httpMethod ?? e.requestContext?.http?.method;
    if (method) attrs['http.request.method'] = String(method);
    const path = e.rawPath ?? e.path ?? e.requestContext?.http?.path;
    if (path) attrs['url.path'] = String(path);
    const route = e.routeKey && e.routeKey !== '$default' ? String(e.routeKey).replace(/^[A-Z]+ /, '') : e.resource;
    if (route) attrs['http.route'] = String(route);
  }
  return attrs;
}

function spanName(event: unknown, ctx: LambdaContext | undefined, attrs: Record<string, unknown>): string {
  if (attrs['faas.trigger'] === 'http' && attrs['http.request.method']) {
    return attrs['http.route'] ? `${attrs['http.request.method']} ${attrs['http.route']}` : String(attrs['http.request.method']);
  }
  return String(ctx?.functionName ?? process.env.AWS_LAMBDA_FUNCTION_NAME ?? 'lambda');
}

function spanKind(trigger: FaasTrigger): SpanKind {
  return trigger === 'pubsub' || trigger === 'datasource' ? SpanKind.CONSUMER : SpanKind.SERVER;
}

interface Flushable {
  forceFlush?: (...args: unknown[]) => Promise<unknown> | unknown;
}

/** The SDK providers registered globally: the trace provider behind the API's proxy, the meter and logger providers. */
function providers(): Flushable[] {
  const found: Flushable[] = [];
  const add = (p: unknown) => {
    if (p && typeof (p as Flushable).forceFlush === 'function' && !found.includes(p as Flushable)) found.push(p as Flushable);
  };
  const tracerProvider = trace.getTracerProvider() as unknown as { getDelegate?: () => unknown };
  add(typeof tracerProvider.getDelegate === 'function' ? tracerProvider.getDelegate() : tracerProvider);
  add(metrics.getMeterProvider());
  add(logs.getLoggerProvider());
  return found;
}

/** The flush budget for this invocation: the configured timeout, cut short by the invocation's deadline. */
export function flushBudget(ctx: LambdaContext | undefined, configured?: number): number {
  const fromEnv = Number(process.env.SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS);
  let budget = configured ?? (Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_FLUSH_TIMEOUT_MS);
  if (typeof ctx?.getRemainingTimeInMillis === 'function') {
    const remaining = ctx.getRemainingTimeInMillis() - DEADLINE_MARGIN_MS;
    if (Number.isFinite(remaining)) budget = Math.min(budget, Math.max(0, remaining));
  }
  return budget;
}

/**
 * Flushes every registered trace, metric and log provider, waiting at most `timeoutMs`.
 * Resolves to true when everything flushed in time. Never rejects.
 */
export async function flushTelemetry(timeoutMs: number = DEFAULT_FLUSH_TIMEOUT_MS): Promise<boolean> {
  const pending = providers().map((p) => Promise.resolve().then(() => p.forceFlush!()).catch(() => undefined));
  if (pending.length === 0) return true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), Math.max(0, timeoutMs));
  });
  try {
    return await Promise.race([Promise.all(pending).then(() => true as const), timedOut]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

let autoInitDone = false;

/** Starts Shield360 from the environment once, naming the service after the function unless OTEL_SERVICE_NAME says otherwise. */
export function initFromEnvironment(): void {
  if (autoInitDone) return;
  autoInitDone = true;
  if (!process.env.OTEL_SERVICE_NAME && process.env.AWS_LAMBDA_FUNCTION_NAME) {
    process.env.OTEL_SERVICE_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;
  }
  // The zero-code entry: fail-open, and a no-op when Shield360 already started.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require('../register');
}

/** Tests only. */
export function resetAutoInitForTesting(): void {
  autoInitDone = false;
}

function shield360Started(): boolean {
  const g = globalThis as Record<string, unknown>;
  if (g.__shield360_register_initialized__ || g.__shield360_zero_code_started__) return true;
  // Shield360.init() (or another OpenTelemetry SDK) registered a real tracer provider.
  const tp = trace.getTracerProvider() as unknown as { getDelegate?: () => unknown };
  const delegate = typeof tp.getDelegate === 'function' ? tp.getDelegate() : tp;
  return Boolean(delegate && delegate.constructor && delegate.constructor.name !== 'NoopTracerProvider');
}

/** Calls a handler that may be async or callback-style and settles with its result. */
function invoke(handler: LambdaHandler, event: unknown, ctx: unknown): Promise<unknown> {
  if (handler.length < 3) {
    return Promise.resolve().then(() => handler(event, ctx));
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (error?: unknown, result?: unknown) => {
      if (settled) return;
      settled = true;
      if (error !== undefined && error !== null) reject(error);
      else resolve(result);
    };
    try {
      const returned = handler(event, ctx, done);
      if (returned && typeof (returned as Promise<unknown>).then === 'function') {
        (returned as Promise<unknown>).then((r) => done(undefined, r), (e) => done(e ?? new Error('handler rejected')));
      }
    } catch (e) {
      done(e);
    }
  });
}

function recordResult(span: Span, trigger: FaasTrigger, result: unknown): void {
  if (trigger !== 'http' || !result || typeof result !== 'object') return;
  const status = Number((result as Record<string, unknown>).statusCode);
  if (!Number.isFinite(status)) return;
  span.setAttribute('http.response.status_code', status);
  if (status >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
}

/**
 * Wraps a Lambda handler (async or callback-style) so each invocation is traced and the
 * telemetry is flushed before the invocation returns. The wrapped handler is async.
 */
export function wrapHandler<H extends LambdaHandler>(handler: H, options: WrapHandlerOptions = {}): (event: any, context: any) => Promise<any> {
  if (typeof handler !== 'function') {
    throw new TypeError('Shield360: wrapHandler() expects the Lambda handler function.');
  }
  if (options.autoInit !== false && !shield360Started()) initFromEnvironment();

  return async function shield360LambdaHandler(event: any, context: any): Promise<any> {
    const ctx = (context ?? undefined) as LambdaContext | undefined;
    const coldStart = takeColdStart();
    const trigger = detectTrigger(event);
    const attributes = invocationAttributes(event, ctx, coldStart, trigger);
    const headers = trigger === 'http' ? headersOf(event) : undefined;
    const parent = headers ? propagation.extract(otelContext.active(), headers) : otelContext.active();
    const tracer = trace.getTracer(TRACER_NAME);
    const span = tracer.startSpan(spanName(event, ctx, attributes), { kind: spanKind(trigger), attributes }, parent);

    try {
      const result = await otelContext.with(trace.setSpan(parent, span), () => invoke(handler, event, context));
      recordResult(span, trigger, result);
      return result;
    } catch (err) {
      span.recordException(err instanceof Error ? err : String(err));
      span.setStatus({ code: SpanStatusCode.ERROR, message: err instanceof Error ? err.message : String(err) });
      throw err;
    } finally {
      span.end();
      await flushTelemetry(flushBudget(ctx, options.flushTimeoutMs));
    }
  };
}

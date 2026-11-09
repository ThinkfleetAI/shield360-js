/**
 * Cloudflare Workers support, with no dependencies and no Node.js APIs:
 * `withShield360(handler)` traces each `fetch`, `scheduled` and `queue`
 * invocation and sends the spans over OTLP/HTTP (JSON) with `fetch`, after the
 * response, through `ctx.waitUntil`.
 *
 *   import { withShield360, span, tracedFetch } from 'shield360/workers';
 *
 *   export default withShield360({
 *     async fetch(request, env, ctx) {
 *       const r = await tracedFetch(ctx, 'https://api.openai.com/v1/responses', { ... });
 *       return new Response(await r.text());
 *     },
 *   });
 *
 * Configuration comes from the Worker's bindings (`SHIELD360_URL` and
 * `SHIELD360_API_KEY`, or `OTEL_EXPORTER_OTLP_ENDPOINT` and
 * `OTEL_EXPORTER_OTLP_HEADERS`, plus `OTEL_SERVICE_NAME`), or from the second
 * argument. Without either, nothing is sent and the Worker runs as before.
 *
 * Workers have no async context, so child spans name their parent explicitly:
 * the invocation's `ctx`, or another span.
 */

export type AttributeValue = string | number | boolean | string[] | number[] | boolean[];
export type Attributes = Record<string, AttributeValue | undefined>;

export interface Shield360WorkersConfig {
  /** `service.name` (default: `OTEL_SERVICE_NAME`, else "cloudflare-worker"). */
  serviceName?: string;
  /** `deployment.environment` (default: `OTEL_DEPLOYMENT_ENVIRONMENT`). */
  environment?: string;
  /** Shield360 URL; with `apiKey`, spans go to its authenticated ingest route. */
  url?: string;
  apiKey?: string;
  /** An OTLP/HTTP endpoint of your own (the base URL; `/v1/traces` is added). Wins over `url`. */
  endpoint?: string;
  headers?: Record<string, string>;
  /** Extra resource attributes. */
  resourceAttributes?: Attributes;
  /** Longest wait for one export, in ms (default 5000). */
  exportTimeoutMs?: number;
  /** Add a W3C `traceparent` header to `tracedFetch` requests (default true). */
  propagate?: boolean;
  /** The fetch used to export (tests). */
  fetch?: typeof fetch;
}

export type ConfigInput = Shield360WorkersConfig | ((env: Record<string, unknown>) => Shield360WorkersConfig);

interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
}

export const SPAN_KIND = { INTERNAL: 1, SERVER: 2, CLIENT: 3, PRODUCER: 4, CONSUMER: 5 } as const;
export const STATUS_CODE = { UNSET: 0, OK: 1, ERROR: 2 } as const;

const SDK_NAME = 'shield360-workers';
const INGEST_PATH = '/api/ingest/otlp';
const DEFAULT_EXPORT_TIMEOUT_MS = 5000;

interface SpanEvent {
  name: string;
  timeMs: number;
  attributes?: Attributes;
}

interface Invocation {
  config: ResolvedConfig;
  spans: WorkerSpan[];
  root?: WorkerSpan;
}

interface ResolvedConfig {
  serviceName: string;
  environment?: string;
  tracesUrl?: string;
  headers: Record<string, string>;
  resourceAttributes: Attributes;
  exportTimeoutMs: number;
  propagate: boolean;
  fetch: typeof fetch;
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let out = '';
  for (const b of buf) out += b.toString(16).padStart(2, '0');
  return out;
}

/** A span in a Worker invocation. Ended spans are exported when the invocation finishes. */
export class WorkerSpan {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly kind: number;
  name: string;
  readonly startMs: number;
  endMs?: number;
  readonly attributes: Attributes = {};
  readonly events: SpanEvent[] = [];
  status: { code: number; message?: string } = { code: STATUS_CODE.UNSET };
  sampled: boolean;
  /** @internal */
  readonly invocation: Invocation;

  constructor(invocation: Invocation, name: string, kind: number, parent?: { traceId: string; spanId: string; sampled?: boolean }) {
    this.invocation = invocation;
    this.name = name;
    this.kind = kind;
    this.traceId = parent?.traceId ?? randomHex(16);
    this.parentSpanId = parent?.spanId;
    this.spanId = randomHex(8);
    this.sampled = parent?.sampled ?? true;
    this.startMs = Date.now();
    invocation.spans.push(this);
  }

  setAttribute(key: string, value: AttributeValue | undefined): this {
    if (value !== undefined) this.attributes[key] = value;
    return this;
  }

  setAttributes(attributes: Attributes): this {
    for (const [k, v] of Object.entries(attributes)) this.setAttribute(k, v);
    return this;
  }

  addEvent(name: string, attributes?: Attributes): this {
    this.events.push({ name, timeMs: Date.now(), attributes });
    return this;
  }

  recordException(error: unknown): this {
    const e = error instanceof Error ? error : new Error(String(error));
    return this.addEvent('exception', {
      'exception.type': e.name,
      'exception.message': e.message,
      'exception.stacktrace': e.stack,
    });
  }

  setStatus(code: number, message?: string): this {
    this.status = { code, message };
    return this;
  }

  end(): void {
    if (this.endMs === undefined) this.endMs = Date.now();
  }

  /** The W3C `traceparent` value for this span. */
  traceparent(): string {
    return `00-${this.traceId}-${this.spanId}-${this.sampled ? '01' : '00'}`;
  }
}

const invocations = new WeakMap<object, Invocation>();
let warm = false;

/** Parses a W3C `traceparent` header; undefined when absent or malformed. */
export function parseTraceparent(value: string | null | undefined): { traceId: string; spanId: string; sampled: boolean } | undefined {
  const m = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.exec((value ?? '').trim().toLowerCase());
  if (!m || m[1] === 'ff' || /^0+$/.test(m[2]) || /^0+$/.test(m[3])) return undefined;
  return { traceId: m[2], spanId: m[3], sampled: (parseInt(m[4], 16) & 1) === 1 };
}

function str(env: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = env?.[key];
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

/** OTEL_EXPORTER_OTLP_HEADERS: comma-separated name=value pairs, split on the first `=` only. */
export function parseHeaders(raw: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const pair of (raw ?? '').split(',')) {
    const at = pair.indexOf('=');
    if (at <= 0) continue;
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (name && value) headers[name] = value;
  }
  return headers;
}

/** Where spans go and how they are labeled: the explicit config first, then the Worker's bindings. */
export function resolveConfig(input: ConfigInput | undefined, env: Record<string, unknown> | undefined): ResolvedConfig {
  const given = (typeof input === 'function' ? input(env ?? {}) : input) ?? {};
  const headers: Record<string, string> = { ...parseHeaders(str(env, 'OTEL_EXPORTER_OTLP_HEADERS')), ...(given.headers ?? {}) };
  let tracesUrl: string | undefined;
  const endpoint = given.endpoint?.trim() || str(env, 'OTEL_EXPORTER_OTLP_ENDPOINT');
  if (endpoint) {
    tracesUrl = endpoint.replace(/\/+$/, '').replace(/\/v1\/traces$/, '') + '/v1/traces';
  } else {
    const url = (given.url?.trim() || str(env, 'SHIELD360_URL'))?.replace(/\/+$/, '');
    const apiKey = given.apiKey?.trim() || str(env, 'SHIELD360_API_KEY');
    if (url && apiKey) {
      tracesUrl = `${url}${INGEST_PATH}/v1/traces`;
      if (!Object.keys(headers).some((k) => k.toLowerCase() === 'authorization')) {
        headers.Authorization = `Bearer ${apiKey}`;
      }
    }
  }
  return {
    serviceName: given.serviceName || str(env, 'OTEL_SERVICE_NAME') || 'cloudflare-worker',
    environment: given.environment || str(env, 'OTEL_DEPLOYMENT_ENVIRONMENT'),
    tracesUrl,
    headers,
    resourceAttributes: given.resourceAttributes ?? {},
    exportTimeoutMs: given.exportTimeoutMs ?? DEFAULT_EXPORT_TIMEOUT_MS,
    propagate: given.propagate ?? true,
    fetch: given.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args)),
  };
}

function anyValue(v: AttributeValue): Record<string, unknown> {
  if (Array.isArray(v)) return { arrayValue: { values: (v as AttributeValue[]).map((x) => anyValue(x)) } };
  if (typeof v === 'boolean') return { boolValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  return { stringValue: String(v) };
}

function keyValues(attrs: Attributes | undefined): Array<{ key: string; value: Record<string, unknown> }> {
  return Object.entries(attrs ?? {})
    .filter(([, v]) => v !== undefined)
    .map(([key, v]) => ({ key, value: anyValue(v as AttributeValue) }));
}

const nanos = (ms: number) => `${Math.round(ms)}000000`;

/** The OTLP/HTTP JSON body (ExportTraceServiceRequest) for a set of ended spans. */
export function encodeSpans(spans: WorkerSpan[], config: Pick<ResolvedConfig, 'serviceName' | 'environment' | 'resourceAttributes'>): string {
  const resource: Attributes = {
    'service.name': config.serviceName,
    'deployment.environment': config.environment,
    'telemetry.sdk.name': SDK_NAME,
    'telemetry.sdk.language': 'js',
    'cloud.provider': 'cloudflare',
    ...config.resourceAttributes,
  };
  return JSON.stringify({
    resourceSpans: [
      {
        resource: { attributes: keyValues(resource) },
        scopeSpans: [
          {
            scope: { name: SDK_NAME },
            spans: spans.map((s) => ({
              traceId: s.traceId,
              spanId: s.spanId,
              ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
              name: s.name,
              kind: s.kind,
              startTimeUnixNano: nanos(s.startMs),
              endTimeUnixNano: nanos(s.endMs ?? s.startMs),
              attributes: keyValues(s.attributes),
              events: s.events.map((e) => ({ name: e.name, timeUnixNano: nanos(e.timeMs), attributes: keyValues(e.attributes) })),
              status: s.status.message ? { code: s.status.code, message: s.status.message } : { code: s.status.code },
            })),
          },
        ],
      },
    ],
  });
}

let warnedNoDestination = false;
let warnedExportFailure = false;

/** Sends the invocation's ended, sampled spans. Never rejects. */
async function exportInvocation(inv: Invocation): Promise<void> {
  const spans = inv.spans.filter((s) => s.endMs !== undefined && s.sampled);
  if (spans.length === 0) return;
  const { tracesUrl, headers, exportTimeoutMs } = inv.config;
  if (!tracesUrl) {
    if (!warnedNoDestination) {
      warnedNoDestination = true;
      console.warn('Shield360: no SHIELD360_URL and SHIELD360_API_KEY (or OTEL_EXPORTER_OTLP_ENDPOINT) binding, so no spans are sent.');
    }
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), exportTimeoutMs);
  try {
    const res = await inv.config.fetch(tracesUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: encodeSpans(spans, inv.config),
      signal: controller.signal,
    });
    if (!res.ok && !warnedExportFailure) {
      warnedExportFailure = true;
      console.warn(`Shield360: span export returned HTTP ${res.status}.`);
    }
  } catch (e) {
    if (!warnedExportFailure) {
      warnedExportFailure = true;
      console.warn(`Shield360: span export failed (${e instanceof Error ? e.message : String(e)}).`);
    }
  } finally {
    clearTimeout(timer);
  }
}

type Parent = ExecutionContextLike | WorkerSpan;

function parentSpan(parent: Parent): WorkerSpan | undefined {
  if (parent instanceof WorkerSpan) return parent;
  return invocations.get(parent as object)?.root;
}

/**
 * Starts a child span. Prefer `span()`, which ends it; with `startSpan` the caller calls `end()`.
 * Outside a wrapped invocation it returns a span that is never exported.
 */
export function startSpan(parent: Parent, name: string, attributes?: Attributes, kind: number = SPAN_KIND.INTERNAL): WorkerSpan {
  const p = parentSpan(parent);
  const inv = p?.invocation ?? { config: resolveConfig({}, {}), spans: [] };
  return new WorkerSpan(inv, name, kind, p ? { traceId: p.traceId, spanId: p.spanId, sampled: p.sampled } : undefined).setAttributes(attributes ?? {});
}

/** Runs `fn` in a child span of `parent` (the invocation's `ctx`, or a span), recording an error it throws. */
export async function span<T>(parent: Parent, name: string, fn: (span: WorkerSpan) => Promise<T> | T, attributes?: Attributes): Promise<T> {
  const s = startSpan(parent, name, attributes);
  try {
    return await fn(s);
  } catch (e) {
    s.recordException(e);
    s.setStatus(STATUS_CODE.ERROR, e instanceof Error ? e.message : String(e));
    throw e;
  } finally {
    s.end();
  }
}

function urlAttributes(url: URL): Attributes {
  return {
    'url.scheme': url.protocol.replace(/:$/, ''),
    'server.address': url.hostname,
    'server.port': url.port ? Number(url.port) : undefined,
    // The path, not the query: query strings often carry keys and tokens.
    'url.path': url.pathname,
  };
}

/** `fetch` in a CLIENT span of `parent`, with a `traceparent` header so the callee can join the trace. */
export async function tracedFetch(parent: Parent, input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const request = new Request(input as RequestInfo, init);
  const url = new URL(request.url);
  const s = startSpan(parent, request.method, { 'http.request.method': request.method, ...urlAttributes(url) }, SPAN_KIND.CLIENT);
  const headers = new Headers(request.headers);
  if (s.invocation.config.propagate) headers.set('traceparent', s.traceparent());
  try {
    const res = await fetch(new Request(request, { headers }));
    s.setAttribute('http.response.status_code', res.status);
    if (res.status >= 500) s.setStatus(STATUS_CODE.ERROR);
    return res;
  } catch (e) {
    s.recordException(e);
    s.setStatus(STATUS_CODE.ERROR, e instanceof Error ? e.message : String(e));
    throw e;
  } finally {
    s.end();
  }
}

function coldStart(): boolean {
  const cold = !warm;
  warm = true;
  return cold;
}

/** Tests only. */
export function resetForTesting(): void {
  warm = false;
  warnedNoDestination = false;
  warnedExportFailure = false;
}

async function runInvocation<T>(
  ctx: ExecutionContextLike | undefined,
  config: ResolvedConfig,
  root: (inv: Invocation) => WorkerSpan,
  run: (span: WorkerSpan) => Promise<T>,
  onResult?: (span: WorkerSpan, result: T) => void
): Promise<T> {
  const inv: Invocation = { config, spans: [] };
  const s = root(inv);
  inv.root = s;
  const key: object = ctx ?? {};
  invocations.set(key, inv);
  try {
    const result = await run(s);
    onResult?.(s, result);
    return result;
  } catch (e) {
    s.recordException(e);
    s.setStatus(STATUS_CODE.ERROR, e instanceof Error ? e.message : String(e));
    throw e;
  } finally {
    s.end();
    const pending = exportInvocation(inv);
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(pending);
    else await pending;
  }
}

/** A Worker module's handlers (the shape `export default { fetch, scheduled, queue }` takes). */
export interface WorkerHandler<Env = any> {
  fetch?: (request: Request, env: Env, ctx: any) => Response | Promise<Response>;
  scheduled?: (controller: any, env: Env, ctx: any) => void | Promise<void>;
  queue?: (batch: any, env: Env, ctx: any) => void | Promise<void>;
  [key: string]: unknown;
}

type TracedKeys = 'fetch' | 'scheduled' | 'queue';
/** The wrapped handlers: the traced ones take the Workers runtime's (request|controller|batch, env, ctx) arguments. */
/** The traced handlers as the wrapper returns them: always async. */
export interface WrappedHandlers<Env = any> {
  fetch: (request: Request, env: Env, ctx: any) => Promise<Response>;
  scheduled: (controller: any, env: Env, ctx: any) => Promise<void>;
  queue: (batch: any, env: Env, ctx: any) => Promise<void>;
}
export type WrappedWorker<H extends WorkerHandler> = Omit<H, TracedKeys> & Pick<WrappedHandlers, Extract<keyof H, TracedKeys>>;

/** Wraps a Worker's handlers so each invocation is traced and exported after it returns, via `ctx.waitUntil`. */
export function withShield360<H extends WorkerHandler>(handler: H, config?: ConfigInput): WrappedWorker<H> {
  const wrapped: WorkerHandler = { ...handler };

  if (typeof handler.fetch === 'function') {
    const inner = handler.fetch.bind(handler);
    wrapped.fetch = (request: Request, env: any, ctx: any) => {
      const url = new URL(request.url);
      const cf = (request as unknown as { cf?: Record<string, unknown> }).cf;
      return runInvocation<Response>(
        ctx,
        resolveConfig(config, env),
        (inv) =>
          new WorkerSpan(inv, request.method, SPAN_KIND.SERVER, parseTraceparent(request.headers.get('traceparent'))).setAttributes({
            'faas.trigger': 'http',
            'faas.coldstart': coldStart(),
            'faas.invocation_id': request.headers.get('cf-ray') ?? undefined,
            'http.request.method': request.method,
            ...urlAttributes(url),
            'user_agent.original': request.headers.get('user-agent') ?? undefined,
            'cloudflare.colo': typeof cf?.colo === 'string' ? cf.colo : undefined,
          }),
        () => Promise.resolve(inner(request, env, ctx)),
        (s, res) => {
          if (res && typeof res.status === 'number') {
            s.setAttribute('http.response.status_code', res.status);
            if (res.status >= 500) s.setStatus(STATUS_CODE.ERROR);
          }
        }
      );
    };
  }

  if (typeof handler.scheduled === 'function') {
    const inner = handler.scheduled.bind(handler);
    wrapped.scheduled = (controller: any, env: any, ctx: any) =>
      runInvocation<void>(
        ctx,
        resolveConfig(config, env),
        (inv) =>
          new WorkerSpan(inv, `scheduled ${controller?.cron ?? ''}`.trim(), SPAN_KIND.SERVER).setAttributes({
            'faas.trigger': 'timer',
            'faas.coldstart': coldStart(),
            'faas.cron': typeof controller?.cron === 'string' ? controller.cron : undefined,
          }),
        () => Promise.resolve(inner(controller, env, ctx))
      );
  }

  if (typeof handler.queue === 'function') {
    const inner = handler.queue.bind(handler);
    wrapped.queue = (batch: any, env: any, ctx: any) =>
      runInvocation<void>(
        ctx,
        resolveConfig(config, env),
        (inv) =>
          new WorkerSpan(inv, `${batch?.queue ?? 'queue'} process`, SPAN_KIND.CONSUMER).setAttributes({
            'faas.trigger': 'pubsub',
            'faas.coldstart': coldStart(),
            'messaging.system': 'cloudflare_queues',
            'messaging.operation.type': 'process',
            'messaging.destination.name': typeof batch?.queue === 'string' ? batch.queue : undefined,
            'messaging.batch.message_count': Array.isArray(batch?.messages) ? batch.messages.length : undefined,
          }),
        () => Promise.resolve(inner(batch, env, ctx))
      );
  }

  return wrapped as unknown as WrappedWorker<H>;
}

export default withShield360;

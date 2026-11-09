import * as fs from 'fs';
import * as path from 'path';
import {
  encodeSpans,
  parseTraceparent,
  resetForTesting,
  resolveConfig,
  span,
  tracedFetch,
  withShield360,
  STATUS_CODE,
} from '../index';

interface Sent {
  url: string;
  headers: Record<string, string>;
  body: any;
}

function ctxStub() {
  const pending: Promise<unknown>[] = [];
  return {
    pending,
    waitUntil: (p: Promise<unknown>) => {
      pending.push(p);
    },
    passThroughOnException: () => undefined,
  };
}

function exportMock() {
  const sent: Sent[] = [];
  const fn = jest.fn(async (url: any, init: any) => {
    sent.push({ url: String(url), headers: init.headers, body: JSON.parse(init.body) });
    return new Response('{}', { status: 200 });
  });
  return { sent, fn: fn as unknown as typeof fetch };
}

const env = { SHIELD360_URL: 'https://shield.example.com/', SHIELD360_API_KEY: 'k-123=', OTEL_SERVICE_NAME: 'edge-api' };

const spansOf = (s: Sent) => s.body.resourceSpans[0].scopeSpans[0].spans as any[];
const attr = (span: any, key: string) => {
  const kv = span.attributes.find((a: any) => a.key === key);
  return kv ? Object.values(kv.value)[0] : undefined;
};

beforeEach(() => resetForTesting());

describe('resolveConfig', () => {
  it('sends to the Shield360 ingest route with the API key as bearer token', () => {
    const c = resolveConfig({}, env);
    expect(c.tracesUrl).toBe('https://shield.example.com/api/ingest/otlp/v1/traces');
    expect(c.headers.Authorization).toBe('Bearer k-123=');
    expect(c.serviceName).toBe('edge-api');
  });

  it('prefers an explicit OTLP endpoint and its headers', () => {
    const c = resolveConfig(undefined, {
      ...env,
      OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com/v1/traces',
      OTEL_EXPORTER_OTLP_HEADERS: 'x-api-key=abc=',
    });
    expect(c.tracesUrl).toBe('https://otel.example.com/v1/traces');
    expect(c.headers).toEqual({ 'x-api-key': 'abc=' });
  });

  it('accepts a function of the bindings', () => {
    const c = resolveConfig((e) => ({ serviceName: `svc-${e.NAME}` }), { NAME: 'x' });
    expect(c.serviceName).toBe('svc-x');
    expect(c.tracesUrl).toBeUndefined();
  });
});

describe('parseTraceparent', () => {
  it('reads a valid header and rejects malformed ones', () => {
    expect(parseTraceparent('00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01')).toEqual({
      traceId: '0af7651916cd43dd8448eb211c80319c',
      spanId: 'b7ad6b7169203331',
      sampled: true,
    });
    expect(parseTraceparent('00-00000000000000000000000000000000-b7ad6b7169203331-01')).toBeUndefined();
    expect(parseTraceparent('garbage')).toBeUndefined();
    expect(parseTraceparent(null)).toBeUndefined();
  });
});

describe('withShield360', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('returns async handlers, so a route can return worker.fetch() as a Promise<Response>', async () => {
    const worker = withShield360({ fetch: () => new Response('sync') }, { fetch: exportMock().fn });
    // Type check: this is a compile error if the wrapped fetch may return a bare Response.
    const route = (request: Request): Promise<Response> => worker.fetch(request, {}, ctxStub());
    const res = await route(new Request('https://w.example.com/'));
    expect(await res.text()).toBe('sync');
  });

  it('traces a fetch invocation and exports through ctx.waitUntil after the response', async () => {
    const { sent, fn } = exportMock();
    const worker = withShield360(
      {
        async fetch(_req: Request, _env: unknown, ctx: any) {
          await span(ctx, 'render', (s) => {
            s.setAttribute('items', 3);
          });
          return new Response('hi', { status: 201 });
        },
      },
      { fetch: fn }
    );
    const ctx = ctxStub();
    const req = new Request('https://worker.example.com/orders?token=secret', {
      headers: { traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01', 'cf-ray': 'ray-1' },
    });
    const res = await worker.fetch!(req, env, ctx);
    expect(res.status).toBe(201);
    expect(ctx.pending).toHaveLength(1);
    await Promise.all(ctx.pending);

    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe('https://shield.example.com/api/ingest/otlp/v1/traces');
    expect(sent[0].headers.Authorization).toBe('Bearer k-123=');
    expect(sent[0].headers['content-type']).toBe('application/json');
    const spans = spansOf(sent[0]);
    const root = spans.find((s) => s.name === 'GET');
    const child = spans.find((s) => s.name === 'render');
    expect(root.kind).toBe(2);
    expect(root.traceId).toBe('0af7651916cd43dd8448eb211c80319c');
    expect(root.parentSpanId).toBe('b7ad6b7169203331');
    expect(attr(root, 'faas.trigger')).toBe('http');
    expect(attr(root, 'faas.coldstart')).toBe(true);
    expect(attr(root, 'faas.invocation_id')).toBe('ray-1');
    expect(attr(root, 'url.path')).toBe('/orders');
    expect(JSON.stringify(root)).not.toContain('secret');
    expect(attr(root, 'http.response.status_code')).toBe('201');
    expect(child.parentSpanId).toBe(root.spanId);
    expect(child.traceId).toBe(root.traceId);
    const resource = sent[0].body.resourceSpans[0].resource.attributes;
    expect(resource).toContainEqual({ key: 'service.name', value: { stringValue: 'edge-api' } });

    // The second invocation in the isolate is warm.
    const ctx2 = ctxStub();
    await worker.fetch!(new Request('https://worker.example.com/'), env, ctx2);
    await Promise.all(ctx2.pending);
    expect(attr(spansOf(sent[1])[0], 'faas.coldstart')).toBe(false);
  });

  it('records a thrown error, rethrows it and still exports', async () => {
    const { sent, fn } = exportMock();
    const worker = withShield360(
      {
        async fetch(): Promise<Response> {
          throw new Error('boom');
        },
      },
      { fetch: fn }
    );
    const ctx = ctxStub();
    await expect(worker.fetch!(new Request('https://w.example.com/'), env, ctx)).rejects.toThrow('boom');
    await Promise.all(ctx.pending);
    const [root] = spansOf(sent[0]);
    expect(root.status).toEqual({ code: STATUS_CODE.ERROR, message: 'boom' });
    expect(root.events[0].name).toBe('exception');
  });

  it('propagates trace context on tracedFetch and records the client span', async () => {
    const { sent, fn } = exportMock();
    let seenTraceparent: string | null = null;
    globalThis.fetch = jest.fn(async (input: any) => {
      seenTraceparent = (input as Request).headers.get('traceparent');
      return new Response('upstream', { status: 502 });
    }) as unknown as typeof fetch;
    const worker = withShield360(
      {
        async fetch(_r: Request, _e: unknown, ctx: any) {
          const up = await tracedFetch(ctx, 'https://api.example.com/v1/chat?key=abc', { method: 'POST', body: '{}' });
          return new Response(await up.text());
        },
      },
      { fetch: fn }
    );
    const ctx = ctxStub();
    await worker.fetch!(new Request('https://w.example.com/'), env, ctx);
    await Promise.all(ctx.pending);
    const spans = spansOf(sent[0]);
    const client = spans.find((s) => s.kind === 3);
    expect(seenTraceparent).toBe(`00-${client.traceId}-${client.spanId}-01`);
    expect(attr(client, 'server.address')).toBe('api.example.com');
    expect(attr(client, 'http.response.status_code')).toBe('502');
    expect(client.status.code).toBe(STATUS_CODE.ERROR);
    expect(JSON.stringify(client)).not.toContain('key=abc');
  });

  it('traces scheduled and queue invocations', async () => {
    const { sent, fn } = exportMock();
    const worker = withShield360(
      { async scheduled() {}, async queue() {} },
      { fetch: fn }
    );
    const c1 = ctxStub();
    await worker.scheduled!({ cron: '*/5 * * * *', scheduledTime: Date.now() }, env, c1);
    const c2 = ctxStub();
    await worker.queue!({ queue: 'jobs', messages: [{}, {}] }, env, c2);
    await Promise.all([...c1.pending, ...c2.pending]);
    const [cron] = spansOf(sent[0]);
    expect(cron.name).toBe('scheduled */5 * * * *');
    expect(attr(cron, 'faas.trigger')).toBe('timer');
    const [q] = spansOf(sent[1]);
    expect(q.kind).toBe(5);
    expect(attr(q, 'messaging.destination.name')).toBe('jobs');
    expect(attr(q, 'messaging.batch.message_count')).toBe('2');
  });

  it('sends nothing without a destination and never fails the request', async () => {
    const { sent, fn } = exportMock();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const worker = withShield360({ fetch: async () => new Response('ok') }, { fetch: fn });
    const ctx = ctxStub();
    await expect(worker.fetch!(new Request('https://w.example.com/'), {}, ctx)).resolves.toBeInstanceOf(Response);
    await Promise.all(ctx.pending);
    expect(sent).toHaveLength(0);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('swallows export failures', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const failing = jest.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;
    const worker = withShield360({ fetch: async () => new Response('ok') }, { fetch: failing });
    const ctx = ctxStub();
    await worker.fetch!(new Request('https://w.example.com/'), env, ctx);
    await expect(Promise.all(ctx.pending)).resolves.toBeDefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('network down'));
    warn.mockRestore();
  });
});

describe('encodeSpans', () => {
  it('produces OTLP JSON attribute values', () => {
    const body = JSON.parse(encodeSpans([], { serviceName: 's', environment: 'prod', resourceAttributes: { n: 1.5, ok: true } }));
    const attrs = body.resourceSpans[0].resource.attributes;
    expect(attrs).toContainEqual({ key: 'n', value: { doubleValue: 1.5 } });
    expect(attrs).toContainEqual({ key: 'ok', value: { boolValue: true } });
    expect(attrs).toContainEqual({ key: 'deployment.environment', value: { stringValue: 'prod' } });
  });
});

describe('Workers bundle', () => {
  it('imports nothing: no Node.js modules, no packages', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.ts'), 'utf8');
    expect(src).not.toMatch(/^\s*import\s.+from\s/m);
    expect(src).not.toMatch(/require\(/);
  });
});

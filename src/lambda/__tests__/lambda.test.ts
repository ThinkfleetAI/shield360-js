import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { context as otelContext, propagation, trace, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { W3CTraceContextPropagator } from '@opentelemetry/core';
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import {
  detectTrigger,
  flushBudget,
  flushTelemetry,
  invocationAttributes,
  resetColdStartForTesting,
  wrapHandler,
} from '../index';
import { loadOriginalHandler, parseHandlerSpec } from '../handler';

const exporter = new InMemorySpanExporter();
const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });

const lambdaContext = (overrides: Record<string, unknown> = {}) => ({
  awsRequestId: 'req-1',
  functionName: 'checkout',
  functionVersion: '$LATEST',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:checkout:prod',
  memoryLimitInMB: '512',
  getRemainingTimeInMillis: () => 30000,
  ...overrides,
});

beforeAll(() => {
  otelContext.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  propagation.setGlobalPropagator(new W3CTraceContextPropagator());
  trace.setGlobalTracerProvider(provider);
});

beforeEach(() => {
  exporter.reset();
  resetColdStartForTesting();
  process.env.AWS_REGION = 'us-east-1';
  delete process.env.AWS_LAMBDA_INITIALIZATION_TYPE;
  delete process.env.SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS;
});

describe('detectTrigger', () => {
  it.each([
    [{ httpMethod: 'GET', headers: {}, requestContext: {} }, 'http'],
    [{ requestContext: { http: { method: 'POST' } }, rawPath: '/x' }, 'http'],
    [{ Records: [{ eventSource: 'aws:sqs' }] }, 'pubsub'],
    [{ Records: [{ EventSource: 'aws:sns' }] }, 'pubsub'],
    [{ Records: [{ eventSource: 'aws:s3' }] }, 'datasource'],
    [{ source: 'aws.events', 'detail-type': 'Scheduled Event' }, 'timer'],
    [{ hello: 'world' }, 'other'],
    [null, 'other'],
  ])('classifies %j as %s', (event, expected) => {
    expect(detectTrigger(event)).toBe(expected);
  });
});

describe('invocationAttributes', () => {
  it('sets the FaaS and cloud semantic conventions', () => {
    const attrs = invocationAttributes({ Records: [{ eventSource: 'aws:sqs' }] }, lambdaContext(), true);
    expect(attrs).toMatchObject({
      'faas.trigger': 'pubsub',
      'faas.coldstart': true,
      'faas.name': 'checkout',
      'faas.version': '$LATEST',
      'faas.invocation_id': 'req-1',
      'faas.max_memory': 512 * 1024 * 1024,
      'cloud.provider': 'aws',
      'cloud.platform': 'aws_lambda',
      'cloud.region': 'us-east-1',
      'cloud.account.id': '123456789012',
      'cloud.resource_id': 'arn:aws:lambda:us-east-1:123456789012:function:checkout',
      'aws.lambda.invoked_arn': 'arn:aws:lambda:us-east-1:123456789012:function:checkout:prod',
    });
  });
});

describe('wrapHandler', () => {
  it('traces an async handler, marks only the first invocation cold and returns its result', async () => {
    const wrapped = wrapHandler(async (event: { n: number }) => ({ doubled: event.n * 2 }), { autoInit: false });
    await expect(wrapped({ n: 2 }, lambdaContext())).resolves.toEqual({ doubled: 4 });
    await wrapped({ n: 3 }, lambdaContext({ awsRequestId: 'req-2' }));

    const spans = exporter.getFinishedSpans();
    expect(spans).toHaveLength(2);
    expect(spans[0].name).toBe('checkout');
    expect(spans[0].attributes['faas.coldstart']).toBe(true);
    expect(spans[1].attributes['faas.coldstart']).toBe(false);
    expect(spans[1].attributes['faas.invocation_id']).toBe('req-2');
  });

  it('treats a provisioned-concurrency environment as warm', async () => {
    process.env.AWS_LAMBDA_INITIALIZATION_TYPE = 'provisioned-concurrency';
    await wrapHandler(async () => 'ok', { autoInit: false })({}, lambdaContext());
    expect(exporter.getFinishedSpans()[0].attributes['faas.coldstart']).toBe(false);
  });

  it('supports callback-style handlers', async () => {
    const wrapped = wrapHandler((_e: unknown, _c: unknown, cb?: (err?: unknown, r?: unknown) => void) => {
      setTimeout(() => cb!(null, 'done'), 1);
    }, { autoInit: false });
    await expect(wrapped({}, lambdaContext())).resolves.toBe('done');
  });

  it('records the error and rethrows it', async () => {
    const wrapped = wrapHandler(async () => {
      throw new Error('boom');
    }, { autoInit: false });
    await expect(wrapped({}, lambdaContext())).rejects.toThrow('boom');
    const [span] = exporter.getFinishedSpans();
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
    expect(span.events.some((e) => e.name === 'exception')).toBe(true);
  });

  it('continues an incoming trace and records HTTP attributes for API Gateway events', async () => {
    const event = {
      version: '2.0',
      routeKey: 'POST /orders',
      rawPath: '/orders',
      headers: { traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' },
      requestContext: { http: { method: 'POST', path: '/orders' } },
    };
    let inner: string | undefined;
    await wrapHandler(async () => {
      inner = trace.getActiveSpan()?.spanContext().traceId;
      return { statusCode: 503 };
    }, { autoInit: false })(event, lambdaContext());

    const [span] = exporter.getFinishedSpans();
    expect(span.name).toBe('POST /orders');
    expect(span.kind).toBe(SpanKind.SERVER);
    expect(span.spanContext().traceId).toBe('0af7651916cd43dd8448eb211c80319c');
    expect(inner).toBe('0af7651916cd43dd8448eb211c80319c');
    expect(span.attributes['http.response.status_code']).toBe(503);
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
  });

  it('flushes before returning and does not wait past the flush timeout', async () => {
    const forceFlush = jest.spyOn(provider, 'forceFlush').mockImplementation(() => new Promise(() => undefined));
    try {
      const started = Date.now();
      await wrapHandler(async () => 'ok', { autoInit: false, flushTimeoutMs: 50 })({}, lambdaContext());
      expect(forceFlush).toHaveBeenCalled();
      expect(Date.now() - started).toBeLessThan(1000);
    } finally {
      forceFlush.mockRestore();
    }
  });

  it('rejects a non-function', () => {
    expect(() => wrapHandler(undefined as never)).toThrow(TypeError);
  });
});

describe('flush helpers', () => {
  it('caps the flush budget at the invocation deadline', () => {
    expect(flushBudget(lambdaContext({ getRemainingTimeInMillis: () => 600 }), 2000)).toBe(500);
    expect(flushBudget(lambdaContext({ getRemainingTimeInMillis: () => 50 }), 2000)).toBe(0);
    process.env.SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS = '750';
    expect(flushBudget(lambdaContext())).toBe(750);
  });

  it('resolves true when the providers flush in time', async () => {
    await expect(flushTelemetry(1000)).resolves.toBe(true);
  });
});

describe('layer handler loading', () => {
  it('parses handler settings like the Node.js runtime', () => {
    expect(parseHandlerSpec('index.handler')).toEqual({ module: 'index', exportPath: ['handler'] });
    expect(parseHandlerSpec('src/api/app.handlers.get')).toEqual({ module: 'src/api/app', exportPath: ['handlers', 'get'] });
    expect(() => parseHandlerSpec('')).toThrow(/SHIELD360_LAMBDA_HANDLER/);
    expect(() => parseHandlerSpec('index')).toThrow(/file.export/);
  });

  it('loads the function handler from the task root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shield360-lambda-'));
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src', 'app.js'), 'exports.handlers = { get: async () => "from-task-root" };');
    const h = await loadOriginalHandler('src/app.handlers.get', root);
    await expect(Promise.resolve(h({}, {}))).resolves.toBe('from-task-root');
    await expect(loadOriginalHandler('src/missing.handler', root)).rejects.toThrow(/cannot find/);
    await expect(loadOriginalHandler('src/app.nothing', root)).rejects.toThrow(/not a function/);
  });
});

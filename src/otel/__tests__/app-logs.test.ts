import { context, trace } from '@opentelemetry/api';
import { SeverityNumber } from '@opentelemetry/api-logs';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  InMemoryLogRecordExporter,
  LoggerProvider,
  SimpleLogRecordProcessor,
} from '@opentelemetry/sdk-logs';
import { BasicTracerProvider } from '@opentelemetry/sdk-trace-base';
import {
  createLogger,
  disableAppLogs,
  enableAppLogs,
  resolveCaptureLogs,
  resolveLogLevel,
} from '../app-logs';

/**
 * Application logs reach Shield360 only when asked for, through the SDK's own
 * LoggerProvider, and linked to the span that was active when they were written.
 */
function memoryProvider() {
  const exporter = new InMemoryLogRecordExporter();
  const provider = new LoggerProvider({
    processors: [new SimpleLogRecordProcessor({ exporter })],
  });
  return { exporter, provider };
}

describe('application logs', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SHIELD360_CAPTURE_LOGS;
    delete process.env.SHIELD360_LOG_LEVEL;
    disableAppLogs();
  });

  afterEach(() => {
    process.env = originalEnv;
    disableAppLogs();
  });

  describe('opt-in', () => {
    it('is off by default', () => {
      expect(resolveCaptureLogs()).toBe(false);
      expect(resolveCaptureLogs(undefined)).toBe(false);
    });

    it('turns on with the option or SHIELD360_CAPTURE_LOGS', () => {
      expect(resolveCaptureLogs(true)).toBe(true);
      process.env.SHIELD360_CAPTURE_LOGS = 'true';
      expect(resolveCaptureLogs()).toBe(true);
    });

    it('lets an explicit false win over the environment', () => {
      process.env.SHIELD360_CAPTURE_LOGS = 'true';
      expect(resolveCaptureLogs(false)).toBe(false);
    });

    it('sends nothing while off, even with a provider about', () => {
      const { exporter } = memoryProvider();
      createLogger('svc').error('nobody asked');
      expect(exporter.getFinishedLogRecords()).toHaveLength(0);
    });
  });

  describe('level', () => {
    it('defaults to info and reads SHIELD360_LOG_LEVEL', () => {
      expect(resolveLogLevel()).toBe('info');
      process.env.SHIELD360_LOG_LEVEL = 'WARNING';
      expect(resolveLogLevel()).toBe('warn');
      expect(resolveLogLevel('error')).toBe('error');
      expect(resolveLogLevel('critical')).toBe('fatal');
      expect(resolveLogLevel('loud')).toBe('info');
    });

    it('drops records below the minimum and keeps the rest', () => {
      const { exporter, provider } = memoryProvider();
      enableAppLogs(provider, 'warn');
      const log = createLogger('svc');
      log.debug('d');
      log.info('i');
      log.warn('w');
      log.error('e');
      log.fatal('f');
      const records = exporter.getFinishedLogRecords();
      expect(records.map((r) => r.body)).toEqual(['w', 'e', 'f']);
      expect(records.map((r) => r.severityNumber)).toEqual([
        SeverityNumber.WARN,
        SeverityNumber.ERROR,
        SeverityNumber.FATAL,
      ]);
      expect(records.map((r) => r.severityText)).toEqual(['WARN', 'ERROR', 'FATAL']);
    });
  });

  it('writes the message as the body, the attributes as given and the scope name', () => {
    const { exporter, provider } = memoryProvider();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger('checkout').info('order placed', { 'order.id': 'o-1', items: 3 });
    const [record] = exporter.getFinishedLogRecords();
    expect(record.body).toBe('order placed');
    expect(record.severityNumber).toBe(SeverityNumber.INFO);
    expect(record.severityText).toBe('INFO');
    expect(record.attributes).toEqual({ 'order.id': 'o-1', items: 3 });
    expect(record.instrumentationScope.name).toBe('checkout');
  });

  it('records an Error as exception attributes', () => {
    const { exporter, provider } = memoryProvider();
    enableAppLogs(provider);
    createLogger().error(new TypeError('bad input'));
    const [record] = exporter.getFinishedLogRecords();
    expect(record.body).toBe('bad input');
    expect(record.attributes['exception.type']).toBe('TypeError');
    expect(record.attributes['exception.message']).toBe('bad input');
    expect(String(record.attributes['exception.stacktrace'])).toContain('TypeError');
    expect(record.instrumentationScope.name).toBe('app');
  });

  it('stops sending once turned off again', () => {
    const { exporter, provider } = memoryProvider();
    enableAppLogs(provider);
    const log = createLogger();
    disableAppLogs();
    log.error('after');
    expect(exporter.getFinishedLogRecords()).toHaveLength(0);
  });

  it('links a record to the active span', () => {
    const contextManager = new AsyncLocalStorageContextManager().enable();
    context.setGlobalContextManager(contextManager);
    try {
      const { exporter, provider } = memoryProvider();
      enableAppLogs(provider);
      const tracer = new BasicTracerProvider().getTracer('test');
      let traceId = '';
      let spanId = '';
      tracer.startActiveSpan('work', (span) => {
        traceId = span.spanContext().traceId;
        spanId = span.spanContext().spanId;
        createLogger().info('inside');
        span.end();
      });
      createLogger().info('outside');

      const [inside, outside] = exporter.getFinishedLogRecords();
      expect(inside.spanContext?.traceId).toBe(traceId);
      expect(inside.spanContext?.spanId).toBe(spanId);
      expect(outside.spanContext).toBeUndefined();
      expect(trace.getActiveSpan()).toBeUndefined();
    } finally {
      context.disable();
    }
  });
});

describe('Shield360.init and application logs', () => {
  const originalEnv = process.env;
  let exporterArgs: jest.Mock;

  beforeEach(() => {
    jest.resetModules();
    exporterArgs = jest.fn();
    process.env = { ...originalEnv };
    for (const name of [
      'SHIELD360_CAPTURE_LOGS',
      'SHIELD360_CAPTURE_STDIO',
      'SHIELD360_LOG_LEVEL',
      'OTEL_EXPORTER_OTLP_ENDPOINT',
      'OTEL_EXPORTER_OTLP_HEADERS',
      'OTEL_LOGS_EXPORTER',
      'SHIELD360_URL',
      'SHIELD360_API_KEY',
    ]) {
      delete process.env[name];
    }
    // Tracing is covered elsewhere; here it would only load instrumentations.
    jest.doMock('../tracing', () => ({ __esModule: true, default: { setup: jest.fn() } }));
    jest.doMock('@opentelemetry/exporter-logs-otlp-http', () => ({
      OTLPLogExporter: class {
        constructor(config: unknown) {
          exporterArgs(config);
        }
        export(_records: unknown, done: (r: { code: number }) => void) {
          done({ code: 0 });
        }
        shutdown() {
          return Promise.resolve();
        }
        forceFlush() {
          return Promise.resolve();
        }
      },
    }));
  });

  afterEach(async () => {
    // init() with captureLogs copies console output; put console back.
    const bridges = await import('../log-bridges');
    bridges.releaseConsole();
    bridges.releaseStdio();
    process.env = originalEnv;
    jest.dontMock('../tracing');
    jest.dontMock('@opentelemetry/exporter-logs-otlp-http');
  });

  async function load() {
    const { logs } = await import('@opentelemetry/api-logs');
    logs.disable();
    const { default: Shield360 } = await import('../../index');
    const { appLogsEnabled } = await import('../app-logs');
    return { Shield360, appLogsEnabled };
  }

  it('leaves application logs off by default', async () => {
    const { Shield360, appLogsEnabled } = await load();
    Shield360.init({ disableMetrics: true, disableEvents: true });
    expect(appLogsEnabled()).toBe(false);
    expect(exporterArgs).not.toHaveBeenCalled();
  });

  it('sends to <SHIELD360_URL>/api/ingest/otlp/v1/logs with the key as bearer, as traces do', async () => {
    const { Shield360, appLogsEnabled } = await load();
    Shield360.init({
      shield360Url: 'https://app.shield360.ai/',
      shield360ApiKey: 'k-1',
      captureLogs: true,
      disableMetrics: true,
      disableEvents: true,
    });
    expect(appLogsEnabled()).toBe(true);
    expect(exporterArgs).toHaveBeenCalledWith({
      url: 'https://app.shield360.ai/api/ingest/otlp/v1/logs',
      headers: { Authorization: 'Bearer k-1' },
    });
    expect(Shield360.options.otlpEndpoint).toBe('https://app.shield360.ai/api/ingest/otlp');
  });

  it('turns on from SHIELD360_CAPTURE_LOGS', async () => {
    process.env.SHIELD360_CAPTURE_LOGS = 'true';
    process.env.SHIELD360_URL = 'https://app.shield360.ai';
    process.env.SHIELD360_API_KEY = 'k-2';
    const { Shield360, appLogsEnabled } = await load();
    Shield360.init({ disableMetrics: true });
    expect(appLogsEnabled()).toBe(true);
    // One provider, shared by GenAI events and application logs.
    expect(exporterArgs).toHaveBeenCalledTimes(1);
  });

  it('with SHIELD360_CAPTURE_STDIO takes stdout and stderr instead of console, so a line is sent once', async () => {
    process.env.SHIELD360_CAPTURE_LOGS = 'true';
    process.env.SHIELD360_CAPTURE_STDIO = 'true';
    const consoleLog = console.log;
    const stdoutWrite = process.stdout.write;
    const { Shield360 } = await load();
    Shield360.init({ disableMetrics: true, disableEvents: true });
    expect(console.log).toBe(consoleLog);
    expect(process.stdout.write).not.toBe(stdoutWrite);
    (await import('../log-bridges')).releaseStdio();
    expect(process.stdout.write).toBe(stdoutWrite);
  });
});

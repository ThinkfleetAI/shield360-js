import { SeverityNumber } from '@opentelemetry/api-logs';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { disableAppLogs, enableAppLogs } from '../app-logs';
import { captureConsole, captureStdio, createLimiter, pinoLevel, pinoStream, releaseConsole, releaseStdio, winstonLevel, winstonTransport } from '../log-bridges';

/**
 * pino, winston and console reach Shield360 only when application logs are
 * on, with their levels mapped, errors as exception attributes, and never
 * feeding back into themselves.
 */
function memory() {
  const exporter = new InMemoryLogRecordExporter();
  const provider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter })] });
  return { exporter, provider };
}

describe('logger bridges', () => {
  let exporter: InMemoryLogRecordExporter;
  beforeEach(() => {
    const m = memory();
    exporter = m.exporter;
    enableAppLogs(m.provider, 'debug', { captureCodeLocation: false });
  });
  afterEach(() => {
    releaseConsole();
    releaseStdio();
    disableAppLogs();
  });

  describe('stdout and stderr', () => {
    // Fake streams, so the test runner's own output is never part of the test.
    function fakeStream() {
      const written: string[] = [];
      const stream = {
        write(chunk: string | Uint8Array, encoding?: unknown, callback?: unknown): boolean {
          written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
          if (typeof encoding === 'function') (encoding as () => void)();
          else if (typeof callback === 'function') (callback as () => void)();
          return true;
        },
      };
      return { stream, written };
    }

    it('turns JSON log lines into records with their level, message, fields and error, still writing them', () => {
      const out = fakeStream();
      const err = fakeStream();
      captureStdio({ stdout: out.stream as never, stderr: err.stream as never });
      const line = JSON.stringify({ time: '2026-10-30T00:00:00Z', level: 'info', msg: 'request', service: 'api', requestId: 'r-1', status: 200 });
      expect(out.stream.write(line + '\n')).toBe(true);
      err.stream.write(JSON.stringify({ level: 'error', msg: 'tick failed', err: { name: 'TypeError', message: 'boom', stack: 'TypeError: boom\n at x' } }) + '\n');
      const records = exporter.getFinishedLogRecords();
      expect(records.map((r) => [r.body, r.severityNumber])).toEqual([
        ['request', SeverityNumber.INFO],
        ['tick failed', SeverityNumber.ERROR],
      ]);
      expect(records[0].attributes).toEqual({ service: 'api', requestId: 'r-1', status: 200 });
      expect(records[1].attributes).toMatchObject({ 'exception.type': 'TypeError', 'exception.message': 'boom' });
      expect(records[0].instrumentationScope.name).toBe('stdout');
      expect(records[1].instrumentationScope.name).toBe('stderr');
      expect(out.written).toEqual([line + '\n']);
    });

    it('joins lines split across writes, takes plain lines as text, and passes callbacks through', () => {
      const out = fakeStream();
      const err = fakeStream();
      captureStdio({ stdout: out.stream as never, stderr: err.stream as never });
      out.stream.write('{"level":"warn","message":"slow ');
      out.stream.write('query"}\nplain text line\n');
      err.stream.write(Buffer.from('something broke\n'));
      const done = jest.fn();
      out.stream.write('', done);
      expect(done).toHaveBeenCalledTimes(1);
      expect(exporter.getFinishedLogRecords().map((r) => [r.body, r.severityNumber])).toEqual([
        ['slow query', SeverityNumber.WARN],
        ['plain text line', SeverityNumber.INFO],
        ['something broke', SeverityNumber.ERROR],
      ]);
    });

    it('masks credentials, never captures the pipeline\'s own output, and puts the streams back on release', () => {
      const out = fakeStream();
      const err = fakeStream();
      const write = out.stream.write;
      captureStdio({ stdout: out.stream as never, stderr: err.stream as never });
      out.stream.write(JSON.stringify({ level: 'info', msg: 'login', password: 'hunter2-secret' }) + '\n');
      err.stream.write('OTLPExporterError: Bad Request\n');
      const records = exporter.getFinishedLogRecords();
      expect(records).toHaveLength(1);
      expect(JSON.stringify(records[0].attributes)).not.toContain('hunter2-secret');
      releaseStdio();
      expect(out.stream.write).toBe(write);
      out.stream.write('after release\n');
      expect(exporter.getFinishedLogRecords()).toHaveLength(1);
    });
  });

  it('turns pino JSON lines into records, with levels, attributes and errors', () => {
    const stream = pinoStream();
    stream.write(JSON.stringify({ level: 30, time: 1, msg: 'order placed', orderId: 'o-1', pid: 1, hostname: 'h' }) + '\n');
    stream.write(JSON.stringify({ level: 50, msg: 'payment failed', err: { type: 'TypeError', message: 'boom', stack: 'TypeError: boom\n at x' } }) + '\n');
    const records = exporter.getFinishedLogRecords();
    expect(records.map((r) => [r.body, r.severityNumber])).toEqual([
      ['order placed', SeverityNumber.INFO],
      ['payment failed', SeverityNumber.ERROR],
    ]);
    expect(records[0].attributes).toEqual({ orderId: 'o-1' });
    expect(records[1].attributes).toMatchObject({ 'exception.type': 'TypeError', 'exception.message': 'boom' });
    expect(records[0].instrumentationScope.name).toBe('pino');
    expect(pinoLevel(60)).toBe('fatal');
    expect(pinoLevel(10)).toBe('debug');
  });

  it('builds a winston transport on the app\'s own Transport class', () => {
    class FakeTransport {
      emitted: string[] = [];
      constructor(public options?: Record<string, unknown>) {}
      emit(event: string) {
        this.emitted.push(event);
        return true;
      }
    }
    const Transport = winstonTransport(FakeTransport);
    const t = new Transport();
    const done = jest.fn();
    t.log({ level: 'warn', message: 'disk slow', [Symbol.for('level')]: 'warn', route: '/checkout' }, done);
    expect(done).toHaveBeenCalled();
    const record = exporter.getFinishedLogRecords()[0];
    expect(record.body).toBe('disk slow');
    expect(record.severityNumber).toBe(SeverityNumber.WARN);
    expect(record.attributes).toEqual({ route: '/checkout' });
    expect(winstonLevel('emerg')).toBe('fatal');
  });

  it('copies console output, still printing it, and stops on release', () => {
    const printed: unknown[][] = [];
    const real = console.warn;
    console.warn = (...args: unknown[]) => void printed.push(args);
    try {
      captureConsole();
      console.warn('cache miss', { key: 'k' });
      console.warn(new Error('kaput'));
      releaseConsole();
      console.warn('after release');
    } finally {
      console.warn = real;
    }
    expect(printed).toHaveLength(3);
    const records = exporter.getFinishedLogRecords();
    expect(records.map((r) => r.body)).toEqual(['cache miss {"key":"k"}', 'kaput']);
    expect(records[1].attributes).toMatchObject({ 'exception.message': 'kaput' });
  });

  it('never captures the telemetry pipeline\'s own messages, and caps records per second', () => {
    const stream = pinoStream({ maxPerSecond: 2 });
    stream.write(JSON.stringify({ level: 50, msg: 'OTLPExporterError: Bad Request' }));
    stream.write(JSON.stringify({ level: 30, msg: '@opentelemetry/api: Registered a global' }));
    for (let i = 0; i < 5; i++) stream.write(JSON.stringify({ level: 30, msg: `m${i}` }));
    expect(exporter.getFinishedLogRecords().map((r) => r.body)).toEqual(['m0', 'm1']);
    let t = 0;
    const allow = createLimiter(1, () => t);
    expect([allow(), allow()]).toEqual([true, false]);
    t = 1000;
    expect(allow()).toBe(true);
  });

  it('sends nothing while application logs are off', () => {
    disableAppLogs();
    pinoStream().write(JSON.stringify({ level: 30, msg: 'x' }));
    expect(exporter.getFinishedLogRecords()).toHaveLength(0);
  });
});

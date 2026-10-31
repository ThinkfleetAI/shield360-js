import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { maskSnippet } from '../../rasp/engine';
import {
  createLogger,
  disableAppLogs,
  enableAppLogs,
  isOwnScope,
  MAX_ATTRIBUTE_LENGTH,
  MAX_BODY_LENGTH,
} from '../app-logs';

/**
 * What leaves the process: credentials and long tokens masked with the RASP
 * snippet rules, long values cut, the SDK's own scopes never sent, a storm
 * capped per logger, the call site recorded, and nothing thrown into the app.
 * The Python SDK carries the same tests.
 */
function memory() {
  const exporter = new InMemoryLogRecordExporter();
  const provider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter })] });
  return { exporter, provider };
}

describe('application log safety', () => {
  afterEach(() => disableAppLogs());

  it('masks credentials and long tokens in the body', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider);
    const log = createLogger('auth');
    log.info('login password=hunter2 for ann');
    log.info('key k3j4h5g6f7d8s9a0q1w2e3r4 used');
    expect(exporter.getFinishedLogRecords().map((r) => r.body)).toEqual(['login password=*** for ann', 'key *** used']);
  });

  it('masks string attributes, but not the code location or exception type', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider);
    const err = new TypeError('token=abc123 rejected');
    createLogger().error(err, { header: 'Authorization: xyz', count: 3 });
    const [record] = exporter.getFinishedLogRecords();
    expect(record.attributes.header).toBe('Authorization: ***');
    expect(record.attributes.count).toBe(3);
    expect(record.attributes['exception.type']).toBe('TypeError');
    expect(record.attributes['exception.message']).toBe('token=*** rejected');
    expect(String(record.attributes['exception.stacktrace'])).not.toContain('token=abc123');
    expect(record.body).toBe('token=*** rejected');
    expect(String(record.attributes['code.file.path'])).toContain('app-logs-safety.test.ts');
    expect(typeof record.attributes['code.line.number']).toBe('number');
  });

  it('leaves the code location out when captureCodeLocation is off', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger().info('plain');
    expect(exporter.getFinishedLogRecords()[0].attributes).toEqual({});
  });

  it('cuts long bodies and attributes', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider);
    createLogger().info('a '.repeat(20000), { note: 'b '.repeat(5000) });
    const [record] = exporter.getFinishedLogRecords();
    expect(String(record.body)).toHaveLength(MAX_BODY_LENGTH);
    expect(String(record.attributes.note)).toHaveLength(MAX_ATTRIBUTE_LENGTH);
  });

  it('never sends the SDK\'s own scopes', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider);
    createLogger('shield360').warn('sdk');
    createLogger('shield360.flags').warn('sdk');
    createLogger('opentelemetry').warn('otel');
    createLogger('@opentelemetry/exporter').warn('otel');
    createLogger('shield360_app').warn('not ours');
    expect(exporter.getFinishedLogRecords().map((r) => r.body)).toEqual(['not ours']);
    expect(isOwnScope('Shield360')).toBe(true);
    expect(isOwnScope('app')).toBe(false);
  });

  it('sends at most maxPerSecond records a second per logger (500 by default)', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider);
    const capped = createLogger('storm', { maxPerSecond: 3 });
    for (let i = 0; i < 10; i++) capped.info(`m${i}`);
    expect(exporter.getFinishedLogRecords().map((r) => r.body)).toEqual(['m0', 'm1', 'm2']);
    const unbounded = createLogger('default');
    for (let i = 0; i < 600; i++) unbounded.info('x');
    expect(exporter.getFinishedLogRecords()).toHaveLength(3 + 500);
  });

  it('never throws into the application when the pipeline fails', () => {
    const throwing = {
      getLogger: () => ({
        emit: () => {
          throw new Error('endpoint down');
        },
      }),
    };
    enableAppLogs(throwing);
    expect(() => createLogger().error('still fine')).not.toThrow();
  });

  it('keeps RASP snippets as they were', () => {
    expect(maskSnippet('password=hunter2&x=1')).toBe('password=***&x=1');
    expect(maskSnippet('t k3j4h5g6f7d8s9a0q1w2e3r4')).toBe('t ***');
    expect(maskSnippet('a '.repeat(100))).toHaveLength(64);
  });
});

describe('application log masking by the shared contract', () => {
  afterEach(() => disableAppLogs());

  it('masks a whole value under a credential name, and lists item by item', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger().info('sign-in', { password: 'pw1', 'x-api-key': 'short', sessionId: 42, tags: ['token=abc', 'ok'], user: 'ann' });
    const [record] = exporter.getFinishedLogRecords();
    expect(record.attributes).toEqual({ password: '***', 'x-api-key': '***', sessionId: '***', tags: ['token=***', 'ok'], user: 'ann' });
  });

  it('masks quoted credentials and the credential after Bearer', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger().info('{"password":"pw1","user":"ann"} Authorization: Bearer abc sent Bearer xyz');
    expect(exporter.getFinishedLogRecords()[0].body).toBe('{"password":"***","user":"ann"} Authorization: *** sent Bearer ***');
  });

  it('masks a token that crosses the cut instead of leaving its start', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger().info('a'.repeat(MAX_BODY_LENGTH - 10) + ' 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b');
    const body = String(exporter.getFinishedLogRecords()[0].body);
    expect(body.endsWith(' ***')).toBe(true);
    expect(body).not.toContain('9f86');
  });

  it('keeps exception class names and file paths readable', () => {
    const { exporter, provider } = memory();
    enableAppLogs(provider, 'info', { captureCodeLocation: false });
    createLogger().error(Object.assign(new Error('java.lang.ArrayIndexOutOfBoundsException at /srv/app/orders/OrderService.ts'), { name: 'ArrayIndexOutOfBoundsError' }));
    const [record] = exporter.getFinishedLogRecords();
    expect(record.body).toBe('java.lang.ArrayIndexOutOfBoundsException at /srv/app/orders/OrderService.ts');
    expect(String(record.attributes['exception.stacktrace'])).toContain('app-logs-safety.test.ts');
  });
});

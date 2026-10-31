import { Writable } from 'stream';
import { SeverityNumber } from '@opentelemetry/api-logs';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { disableAppLogs, enableAppLogs } from '../app-logs';
import { bridgePinoArgs, patchPino, patchWinston, unpatchWinston } from '../log-auto';

/**
 * With application logs on, winston and pino loggers the app creates also
 * write to Shield360, through the real libraries, without changing their own
 * output; with them off, loggers are created exactly as before.
 */
function memory() {
  const exporter = new InMemoryLogRecordExporter();
  const provider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter })] });
  return { exporter, provider };
}

function sink() {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, done) {
      lines.push(String(chunk));
      done();
    },
  });
  return { lines, stream };
}

describe('winston and pino auto bridges', () => {
  let exporter: InMemoryLogRecordExporter;
  beforeEach(() => {
    const m = memory();
    exporter = m.exporter;
    enableAppLogs(m.provider, 'info', { captureCodeLocation: false });
  });
  afterEach(() => disableAppLogs());

  it('adds the Shield360 transport to winston loggers and keeps their own transports', () => {
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const winston = patchWinston(require('winston'));
      try {
        const own = sink();
        const logger = winston.createLogger({
          level: 'info',
          transports: [new winston.transports.Stream({ stream: own.stream })],
        });
        logger.info('order placed', { orderId: 'o-1' });
        logger.warn('api key=k3j4h5g6f7d8s9a0q1w2e3r4 used');
        logger.debug('below the level');
        expect(logger.transports).toHaveLength(2);
        expect(own.lines).toHaveLength(2);
        const records = exporter.getFinishedLogRecords();
        expect(records.map((r) => r.body)).toEqual(['order placed', 'api *** used']);
        expect(records[0].attributes).toEqual({ orderId: 'o-1' });
        expect(records[1].severityNumber).toBe(SeverityNumber.WARN);
        expect(records[0].instrumentationScope.name).toBe('winston');
        // Patching twice is a no-op; unpatching restores createLogger.
        expect(patchWinston(winston).createLogger).toBe(winston.createLogger);
      } finally {
        unpatchWinston(winston);
      }
      const plain = winston.createLogger({ transports: [new winston.transports.Stream({ stream: sink().stream })] });
      expect(plain.transports).toHaveLength(1);
    });
  });

  it('creates winston loggers unchanged while application logs are off', () => {
    disableAppLogs();
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const winston = patchWinston(require('winston'));
      const logger = winston.createLogger({ transports: [new winston.transports.Stream({ stream: sink().stream })] });
      expect(logger.transports).toHaveLength(1);
      unpatchWinston(winston);
    });
  });

  it('writes pino records to the destination and to Shield360', () => {
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const pino = patchPino(require('pino'));
      expect(pino.default).toBe(pino);
      expect(typeof pino.destination).toBe('function');
      const own = sink();
      const logger = pino({ level: 'info' }, own.stream);
      logger.info({ orderId: 'o-1' }, 'order placed');
      logger.error(new Error('session=xyz expired'));
      logger.debug('below the level');
      expect(own.lines).toHaveLength(2);
      expect(JSON.parse(own.lines[0]).msg).toBe('order placed');
      const records = exporter.getFinishedLogRecords();
      expect(records.map((r) => r.body)).toEqual(['order placed', 'session=*** expired']);
      expect(records[0].attributes).toEqual({ orderId: 'o-1' });
      expect(records[1].severityNumber).toBe(SeverityNumber.ERROR);
      expect(records[1].attributes['exception.message']).toBe('session=*** expired');
      // pino(stream) works too.
      const second = sink();
      pino(second.stream).warn('disk slow');
      expect(second.lines).toHaveLength(1);
      expect(exporter.getFinishedLogRecords().map((r) => r.body)).toContain('disk slow');
    });
  });

  it('creates pino loggers unchanged while application logs are off', () => {
    disableAppLogs();
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const pino = patchPino(require('pino'));
      const own = sink();
      pino(own.stream).info('x');
      expect(own.lines).toHaveLength(1);
      expect(exporter.getFinishedLogRecords()).toHaveLength(0);
    });
  });

  it('leaves pino arguments it cannot bridge alone', () => {
    const fake = Object.assign(() => undefined, { multistream: () => ({ write: () => true }), destination: () => ({ write: () => true }) });
    expect(bridgePinoArgs(fake, [{}, { write: () => true }, 'extra'])).toBeNull();
    expect(bridgePinoArgs(fake, ['/var/log/app.log'])).not.toBeNull(); // pino('path'): a file destination
    expect(bridgePinoArgs(fake, [{ transport: { target: 'x' } }, { write: () => true }])).toBeNull();
    expect(bridgePinoArgs(fake, [[1, 2]])).toBeNull();
  });

  it('never throws from a broken module', () => {
    expect(patchWinston(undefined)).toBeUndefined();
    expect(patchWinston({ createLogger: 'nope' })).toEqual({ createLogger: 'nope' });
    expect(patchPino({})).toEqual({});
  });
});

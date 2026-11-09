/**
 * Bridges from the loggers apps already use to Shield360 application logs.
 *
 * Each one writes through the same logger as Shield360.logger() (app-logs.ts),
 * so nothing is sent unless application logs are on (`captureLogs: true` or
 * SHIELD360_CAPTURE_LOGS=true), records go to the same destination with the
 * same key as the spans, and they carry the active span's trace and span ids.
 * None of them adds a dependency: pass in what the bridge needs.
 *
 *   pino     Shield360.pinoStream(): a stream for pino.multistream (or as the
 *            destination) that turns pino's JSON lines into log records.
 *   winston  Shield360.winstonTransport(Transport): a transport class built on
 *            the app's own `winston-transport`.
 *   console  Shield360.captureConsole(): console.debug/log/info/warn/error
 *            also become log records, until releaseConsole().
 *   stdio    Shield360.captureStdio(): every line written to process.stdout
 *            and process.stderr also becomes a record, for apps whose logger
 *            writes JSON lines itself (`SHIELD360_CAPTURE_STDIO=true`), until
 *            releaseStdio().
 *
 * Loop protection: a record written while another is being written is
 * dropped (the exporter's own logging cannot feed itself); OpenTelemetry's
 * and Shield360's own messages are never captured; and each bridge sends at
 * most `maxPerSecond` records a second (default 500), dropping the rest, so a
 * logger that logs about logging cannot run away.
 */
import type { LogAttributes } from '@opentelemetry/api-logs';
import { maskValue } from '../masking';
import { createLimiter, createLogger, type LogLevel, type Shield360Logger } from './app-logs';

export { createLimiter };

export type BridgeOptions = {
  /** The instrumentation scope; defaults to the bridge's name (pino, winston, console). */
  name?: string;
  /** Records per second at most (default 500). */
  maxPerSecond?: number;
};

let writing = false;

/** Messages from the telemetry pipeline itself, which must never be exported back into it. */
const OWN_MESSAGE = /^(@opentelemetry|OTLPExporterError|Shield360[\s:]|\[shield360\]|\{"stack":"OTLPExporterError)/i;
/**
 * A whole written line from the pipeline itself: an exporter error the app's logger (or the OTel
 * diag logger) printed as JSON, whose message alone ("Request timed out") says nothing about where
 * it came from, but whose stack runs through the exporter or the SDK. Exporting it would report
 * every failed export as an application error (SKUFlow, 2026-11-02) and feed the next one.
 */
const OWN_LINE = /OTLPExporterError|[\\/]@opentelemetry[\\/](otlp-|exporter-|sdk-)|[\\/]node_modules[\\/]shield360[\\/]/;
/**
 * Node's own process warnings on stderr ("(node:7) Warning: …", "(node:7) [DEP0040]
 * DeprecationWarning: …"), written as one block with their follow-on lines ("(Use `node
 * --trace-warnings ...`"): warnings, not errors.
 */
const NODE_WARNING = /^\(node:\d+\) (\[[A-Z0-9_]+\] )?[A-Za-z]*Warning:/;

/** The bridge's logger: its own scope and its own rate limit. */
function bridgeLogger(fallbackName: string, options: BridgeOptions): Shield360Logger {
  return createLogger(options.name || fallbackName, { maxPerSecond: options.maxPerSecond });
}

function guarded(logger: Shield360Logger) {
  return (level: LogLevel, message: string | Error, attributes?: LogAttributes) => {
    if (writing) return;
    const text = message instanceof Error ? message.message : message;
    if (OWN_MESSAGE.test(text)) return;
    writing = true;
    try {
      logger[level](message, attributes);
    } finally {
      writing = false;
    }
  };
}

// ------------------------------------------------------------------- pino

const PINO_LEVELS: [number, LogLevel][] = [
  [60, 'fatal'],
  [50, 'error'],
  [40, 'warn'],
  [30, 'info'],
  [0, 'debug'],
];

export function pinoLevel(level: unknown): LogLevel {
  if (typeof level === 'number') return PINO_LEVELS.find(([n]) => level >= n)?.[1] ?? 'info';
  const name = String(level || '').toLowerCase();
  if (name === 'trace' || name === 'debug') return 'debug';
  if (name === 'warn' || name === 'warning') return 'warn';
  if (name === 'error' || name === 'fatal' || name === 'info') return name as LogLevel;
  return 'info';
}

const PINO_FIELDS = new Set(['level', 'time', 'msg', 'pid', 'hostname', 'v', 'err']);

function flatAttributes(record: Record<string, unknown>, skip: Set<string>): LogAttributes {
  const out: LogAttributes = {};
  for (const [key, value] of Object.entries(record)) {
    if (skip.has(key) || value === undefined || value === null) continue;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') out[key] = value;
    else {
      try {
        // Masked before it becomes text, so nested credential names are masked by name.
        out[key] = JSON.stringify(maskValue(key, value, 4096)).slice(0, 4096);
      } catch {
        // Not serialisable: left out.
      }
    }
  }
  return out;
}

/**
 * A pino destination: `pino({}, pino.multistream([{ stream: process.stdout }, { stream: Shield360.pinoStream() }]))`.
 * Each line pino writes is one JSON record; `msg` becomes the body, `level`
 * the severity, `err` the exception attributes, the rest attributes.
 */
export function pinoStream(options: BridgeOptions = {}): { write(line: string): boolean } {
  const emit = guarded(bridgeLogger('pino', options));
  return {
    write(line: string) {
      for (const chunk of String(line).split('\n')) {
        if (!chunk.trim()) continue;
        let record: Record<string, unknown>;
        try {
          record = JSON.parse(chunk);
        } catch {
          emit('info', chunk);
          continue;
        }
        const level = pinoLevel(record.level);
        const attributes = flatAttributes(record, PINO_FIELDS);
        const err = record.err as { type?: string; message?: string; stack?: string } | undefined;
        if (err && typeof err === 'object') {
          if (err.type) attributes['exception.type'] = String(err.type);
          if (err.message) attributes['exception.message'] = String(err.message);
          if (err.stack) attributes['exception.stacktrace'] = String(err.stack).slice(0, 16384);
        }
        emit(level, typeof record.msg === 'string' ? record.msg : err?.message ? String(err.message) : '', attributes);
      }
      return true;
    },
  };
}

// ---------------------------------------------------------------- winston

type TransportBase = new (options?: Record<string, unknown>) => { emit?(event: string, ...args: unknown[]): boolean };

const WINSTON_FIELDS = new Set(['level', 'message', 'timestamp', 'stack']);
const LEVEL_SYMBOL = Symbol.for('level');

export function winstonLevel(level: unknown): LogLevel {
  const name = String(level || '').toLowerCase();
  if (name === 'error' || name === 'crit' || name === 'alert' || name === 'emerg') return name === 'error' ? 'error' : 'fatal';
  if (name === 'warn' || name === 'warning') return 'warn';
  if (name === 'debug' || name === 'verbose' || name === 'silly') return 'debug';
  return 'info';
}

/**
 * A winston transport class on the app's own `winston-transport`:
 *
 *   import Transport from 'winston-transport';
 *   const Shield360Transport = Shield360.winstonTransport(Transport);
 *   winston.createLogger({ transports: [new winston.transports.Console(), new Shield360Transport()] });
 */
export function winstonTransport(Transport: TransportBase, options: BridgeOptions = {}) {
  const emit = guarded(bridgeLogger('winston', options));
  return class Shield360WinstonTransport extends Transport {
    log(info: Record<string | symbol, unknown>, callback?: () => void) {
      try {
        const level = winstonLevel(info[LEVEL_SYMBOL] ?? info.level);
        const attributes = flatAttributes(info as Record<string, unknown>, WINSTON_FIELDS);
        if (typeof info.stack === 'string') attributes['exception.stacktrace'] = info.stack.slice(0, 16384);
        const message = info.message instanceof Error ? info.message : String(info.message ?? '');
        emit(level, message, attributes);
      } finally {
        this.emit?.('logged', info);
        callback?.();
      }
    }
  };
}

// ---------------------------------------------------------------- console

const CONSOLE_METHODS: [keyof Console, LogLevel][] = [
  ['debug', 'debug'],
  ['log', 'info'],
  ['info', 'info'],
  ['warn', 'warn'],
  ['error', 'error'],
];

let original: Partial<Record<keyof Console, (...args: unknown[]) => void>> | null = null;

function formatArgs(args: unknown[]): { message: string | Error; attributes?: LogAttributes } {
  const error = args.find((a): a is Error => a instanceof Error);
  const text = args
    .map((a) => {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return a.message;
      try {
        return JSON.stringify(a);
      } catch {
        return String(a);
      }
    })
    .join(' ')
    .slice(0, 16384);
  if (error) return { message: Object.assign(new Error(text), { name: error.name, stack: error.stack }) };
  return { message: text };
}

/** Copies console output to Shield360 application logs (still printed as before). Call releaseConsole() to stop. */
export function captureConsole(options: BridgeOptions = {}): void {
  if (original) return;
  const emit = guarded(bridgeLogger('console', options));
  original = {};
  for (const [method, level] of CONSOLE_METHODS) {
    const previous = console[method] as (...args: unknown[]) => void;
    original[method] = previous;
    (console as unknown as Record<string, unknown>)[method] = (...args: unknown[]) => {
      previous.apply(console, args);
      if (writing) return;
      try {
        const { message } = formatArgs(args);
        emit(level, message);
      } catch {
        // Logging never throws into the application.
      }
    };
  }
}

/** Puts console back as it was. */
export function releaseConsole(): void {
  if (!original) return;
  for (const [method, fn] of Object.entries(original)) {
    if (fn) (console as unknown as Record<string, unknown>)[method] = fn;
  }
  original = null;
}

// ------------------------------------------------------------ stdout/stderr

type WritableLike = { write: (...args: any[]) => boolean };

export type StdioOptions = BridgeOptions & {
  /** The streams to copy; process.stdout and process.stderr by default (tests pass their own). */
  stdout?: WritableLike;
  stderr?: WritableLike;
};

const LINE_FIELDS = new Set(['level', 'time', 'timestamp', 'msg', 'message', 'pid', 'hostname', 'v', 'err', 'error']);
/** A line longer than this without a newline is sent as it is. */
const MAX_PENDING = 65536;

let stdioOriginal: { stream: WritableLike; write: WritableLike['write']; own: boolean }[] | null = null;

/** One written line as a record: JSON log lines (pino, bunyan and most JSON loggers) by their fields, other lines as text. */
function emitLine(emit: ReturnType<typeof guarded>, line: string, plainLevel: LogLevel): void {
  if (!line.trim() || OWN_LINE.test(line)) return;
  let record: unknown;
  try {
    record = line.trimStart().startsWith('{') ? JSON.parse(line) : undefined;
  } catch {
    record = undefined;
  }
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    emit(plainLevel, line);
    return;
  }
  const fields = record as Record<string, unknown>;
  const attributes = flatAttributes(fields, LINE_FIELDS);
  const err = (fields.err ?? fields.error) as { type?: string; name?: string; message?: string; stack?: string } | undefined;
  if (err && typeof err === 'object') {
    const type = err.type ?? err.name;
    if (type) attributes['exception.type'] = String(type);
    if (err.message) attributes['exception.message'] = String(err.message);
    if (err.stack) attributes['exception.stacktrace'] = String(err.stack).slice(0, 16384);
  }
  const message = typeof fields.msg === 'string' ? fields.msg : typeof fields.message === 'string' ? fields.message : err?.message ? String(err.message) : '';
  emit(fields.level === undefined ? plainLevel : pinoLevel(fields.level), message, attributes);
}

/** A line that continues the one before it: indented, or closing a bracket that is still open. */
const CONTINUATION = /^\s+\S|^[}\])]/;

/** Brackets a line leaves open; quoted text is skipped. */
function openBrackets(text: string): number {
  let depth = 0;
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
    } else if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '{' || c === '[' || c === '(') depth++;
    else if (c === '}' || c === ']' || c === ')') depth--;
  }
  return depth;
}

/**
 * The lines of one write as records: a line that continues the one before it
 * (a console.log of an object, a stack trace) joins it, so one call is one
 * record rather than one record per line, all with the same timestamp.
 * Bounded by MAX_PENDING characters per record.
 */
export function joinContinuations(lines: string[]): string[] {
  const blocks: string[] = [];
  let open = 0;
  for (const line of lines) {
    const last = blocks.length - 1;
    const continues =
      last >= 0 &&
      blocks[last].trim() !== '' &&
      CONTINUATION.test(line) &&
      (/^\s/.test(line) || open > 0) &&
      blocks[last].length + 1 + line.length <= MAX_PENDING;
    if (continues) {
      blocks[last] += `\n${line}`;
      open += openBrackets(line);
    } else {
      blocks.push(line);
      open = Math.max(0, openBrackets(line));
    }
  }
  return blocks;
}

/**
 * Copies every line written to stdout and stderr to Shield360 application logs; the output itself
 * is unchanged. JSON lines keep their level, message, fields and error; plain lines are info on
 * stdout and error on stderr, except Node's process warnings, which are warn. Lines split across
 * writes are joined. Lines from the telemetry pipeline itself are left out. Call releaseStdio() to stop.
 */
export function captureStdio(options: StdioOptions = {}): void {
  if (stdioOriginal) return;
  stdioOriginal = [];
  const streams: [WritableLike | undefined, string, LogLevel][] = [
    [options.stdout ?? process.stdout, 'stdout', 'info'],
    [options.stderr ?? process.stderr, 'stderr', 'error'],
  ];
  for (const [stream, name, plainLevel] of streams) {
    if (!stream || typeof stream.write !== 'function') continue;
    const emit = guarded(bridgeLogger(options.name || name, options));
    const previous = stream.write;
    let pending = '';
    stdioOriginal.push({ stream, write: previous, own: Object.prototype.hasOwnProperty.call(stream, 'write') });
    stream.write = function (this: unknown, chunk: unknown, ...rest: unknown[]): boolean {
      const result = previous.call(this, chunk, ...rest);
      if (writing) return result;
      try {
        const text = typeof chunk === 'string' ? chunk : chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8') : '';
        if (text) {
          pending += text;
          const lines = pending.split('\n');
          pending = lines.pop() ?? '';
          if (pending.length > MAX_PENDING) {
            lines.push(pending);
            pending = '';
          }
          // A Node warning and the lines written with it are one block, all warn.
          let level = plainLevel;
          for (const block of joinContinuations(lines.map((raw) => raw.replace(/\r$/, '')))) {
            if (plainLevel === 'error' && NODE_WARNING.test(block)) level = 'warn';
            emitLine(emit, block, level);
          }
        }
      } catch {
        // Logging never throws into the application.
      }
      return result;
    };
  }
}

/** Puts stdout and stderr back as they were. */
export function releaseStdio(): void {
  if (!stdioOriginal) return;
  for (const { stream, write, own } of stdioOriginal) {
    if (own) stream.write = write;
    else delete (stream as Partial<WritableLike>).write;
  }
  stdioOriginal = null;
}

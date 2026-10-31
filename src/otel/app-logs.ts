/**
 * Application logs to Shield360, when asked for.
 *
 * Shield360 ingests OTLP logs on the same per-API-key route as traces. The
 * logger here writes OpenTelemetry log records through the SDK's own
 * LoggerProvider (otel/events.ts), so they go to the same destination with the
 * same Authorization header as the spans, and carry the trace and span ids of
 * whatever span is active when they are written.
 *
 * Nothing is sent unless it is turned on: `captureLogs: true` in init(), or
 * SHIELD360_CAPTURE_LOGS=true. Until then every logger is a no-op, so a
 * library can create one at import time without deciding for the application.
 *
 * Every record, from Shield360.logger() or a bridge (log-bridges.ts), passes
 * the same checks as the Python SDK's handler: the level; never the SDK's own
 * scopes (`shield360`, `opentelemetry`); at most `maxPerSecond` records a
 * second per logger (500 by default); masking by the contract every SDK
 * shares (sdk/rasp/README.md, "Masking"): credential pairs, bearer
 * credentials and opaque tokens in the body and attributes, the whole value of
 * an attribute named like a credential, lists and maps item by item, readable
 * identifiers kept (not `code.*` or `exception.type`); the body and stack
 * trace cut to 16,384 characters after masking, other strings to 4,096; and
 * the application call site as `code.function.name`,
 * `code.file.path` and `code.line.number` unless captureCodeLocation is off.
 */
import { LogAttributes, SeverityNumber } from '@opentelemetry/api-logs';
import { maskText, maskValue } from '../masking';
import { CodeLocationSpanProcessor, ATTR_CODE_FILE_PATH, ATTR_CODE_FUNCTION_NAME, ATTR_CODE_LINE_NUMBER } from './code-location';
import { parseBoolEnv } from './utils';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface Shield360Logger {
  debug(message: string | Error, attributes?: LogAttributes): void;
  info(message: string | Error, attributes?: LogAttributes): void;
  warn(message: string | Error, attributes?: LogAttributes): void;
  error(message: string | Error, attributes?: LogAttributes): void;
  fatal(message: string | Error, attributes?: LogAttributes): void;
}

interface ProviderLike {
  getLogger(name: string): { emit(record: Record<string, unknown>): void };
}

// The OpenTelemetry log data model's severity numbers and short names.
const SEVERITY: Record<LogLevel, SeverityNumber> = {
  debug: SeverityNumber.DEBUG,
  info: SeverityNumber.INFO,
  warn: SeverityNumber.WARN,
  error: SeverityNumber.ERROR,
  fatal: SeverityNumber.FATAL,
};
const SEVERITY_TEXT: Record<LogLevel, string> = {
  debug: 'DEBUG',
  info: 'INFO',
  warn: 'WARN',
  error: 'ERROR',
  fatal: 'FATAL',
};
const LEVEL_ALIASES: Record<string, LogLevel> = { warning: 'warn', critical: 'fatal' };

export const DEFAULT_LOG_LEVEL: LogLevel = 'info';
export const DEFAULT_LOGGER_NAME = 'app';
export const DEFAULT_MAX_PER_SECOND = 500;
export const MAX_BODY_LENGTH = 16384;
export const MAX_ATTRIBUTE_LENGTH = 4096;

const OWN_SCOPES = ['shield360', 'opentelemetry', '@opentelemetry'];
const LONG_ATTRIBUTES = new Set(['exception.stacktrace']);
const UNMASKED_ATTRIBUTES = new Set(['exception.type']);
const STACK_LIMIT = 64;

export type AppLogsOptions = {
  /** Record the application call site (code.*). Default true. */
  captureCodeLocation?: boolean;
  /** Directory code.file.path is made relative to (init()'s codeRoot). */
  codeRoot?: string;
};

export type LoggerOptions = {
  /** Records per second at most (default 500); the rest are dropped. */
  maxPerSecond?: number;
};

let provider: ProviderLike | null = null;
let minSeverity: SeverityNumber = SEVERITY[DEFAULT_LOG_LEVEL];
let locator: CodeLocationSpanProcessor | null = null;

/** A fixed-window limiter: true for at most `maxPerSecond` calls in each second. */
export function createLimiter(maxPerSecond = DEFAULT_MAX_PER_SECOND, now: () => number = Date.now): () => boolean {
  let windowStart = 0;
  let count = 0;
  return () => {
    const t = now();
    if (t - windowStart >= 1000) {
      windowStart = t;
      count = 0;
    }
    count += 1;
    return count <= maxPerSecond;
  };
}

/** Whether a scope is the SDK's own (`shield360`, `opentelemetry`, or below them). */
export function isOwnScope(name: string): boolean {
  const lower = name.toLowerCase();
  return OWN_SCOPES.some((own) => lower === own || lower.startsWith(own + '.') || lower.startsWith(own + '/'));
}

/**
 * An attribute value as it may leave the process (sdk/rasp/README.md, Masking):
 * the whole value under a credential name, strings masked then cut, lists and
 * maps item by item; code.* and exception.type as they are.
 */
export function maskAttribute(key: string, value: unknown): unknown {
  if (key.startsWith('code.') || UNMASKED_ATTRIBUTES.has(key)) return value;
  return maskValue(key, value, LONG_ATTRIBUTES.has(key) ? MAX_BODY_LENGTH : MAX_ATTRIBUTE_LENGTH);
}

function captureStack(): string | undefined {
  const previous = Error.stackTraceLimit;
  try {
    Error.stackTraceLimit = STACK_LIMIT;
    return new Error().stack;
  } finally {
    Error.stackTraceLimit = previous;
  }
}

/** The option, else SHIELD360_CAPTURE_LOGS, else off. */
export function resolveCaptureLogs(option?: boolean): boolean {
  return option ?? parseBoolEnv('SHIELD360_CAPTURE_LOGS') ?? false;
}

/** The option, else SHIELD360_LOG_LEVEL, else `info`. Unknown names fall back to `info`. */
export function resolveLogLevel(option?: string): LogLevel {
  const raw = (option ?? process.env.SHIELD360_LOG_LEVEL ?? DEFAULT_LOG_LEVEL).trim().toLowerCase();
  const name = LEVEL_ALIASES[raw] ?? raw;
  return name in SEVERITY ? (name as LogLevel) : DEFAULT_LOG_LEVEL;
}

/** Start sending: records at `level` and above go through `logProvider`. */
export function enableAppLogs(logProvider: ProviderLike, level: LogLevel = DEFAULT_LOG_LEVEL, options: AppLogsOptions = {}): void {
  provider = logProvider;
  minSeverity = SEVERITY[level];
  locator = options.captureCodeLocation === false ? null : new CodeLocationSpanProcessor({ codeRoot: options.codeRoot });
}

/** Stop sending; every logger goes back to a no-op. */
export function disableAppLogs(): void {
  provider = null;
  minSeverity = SEVERITY[DEFAULT_LOG_LEVEL];
  locator = null;
}

export function appLogsEnabled(): boolean {
  return provider !== null;
}

function emit(scope: string, level: LogLevel, allow: () => boolean, message: string | Error, attributes?: LogAttributes): void {
  const current = provider;
  if (!current || SEVERITY[level] < minSeverity || isOwnScope(scope)) return;
  try {
    if (!allow()) return;
    const given: LogAttributes = { ...(attributes ?? {}) };
    let body: string;
    if (message instanceof Error) {
      body = message.message;
      given['exception.type'] = message.name;
      given['exception.message'] = message.message;
      if (message.stack) given['exception.stacktrace'] = message.stack;
    } else {
      body = String(message);
    }
    const where = locator;
    if (where && given[ATTR_CODE_FILE_PATH] === undefined) {
      const frame = where.findApplicationFrame(captureStack());
      if (frame) {
        if (frame.functionName) given[ATTR_CODE_FUNCTION_NAME] = frame.functionName;
        given[ATTR_CODE_FILE_PATH] = frame.filePath;
        given[ATTR_CODE_LINE_NUMBER] = frame.lineNumber;
      }
    }
    const attrs: LogAttributes = {};
    for (const [key, value] of Object.entries(given)) attrs[key] = maskAttribute(key, value) as LogAttributes[string];
    // No context is passed: the logs SDK takes the active one, which links the
    // record to the active span's trace and span ids.
    current.getLogger(scope).emit({
      severityNumber: SEVERITY[level],
      severityText: SEVERITY_TEXT[level],
      body: maskText(body, MAX_BODY_LENGTH),
      attributes: attrs,
    });
  } catch {
    // Logging never throws into the application.
  }
}

/**
 * A logger whose records go to Shield360 when application logs are on
 * (`captureLogs: true` or SHIELD360_CAPTURE_LOGS=true), and nowhere otherwise.
 * `name` becomes the record's instrumentation scope; it defaults to `app`.
 */
export function createLogger(name: string = DEFAULT_LOGGER_NAME, options: LoggerOptions = {}): Shield360Logger {
  const scope = name || DEFAULT_LOGGER_NAME;
  const allow = createLimiter(options.maxPerSecond);
  return {
    debug: (message, attributes) => emit(scope, 'debug', allow, message, attributes),
    info: (message, attributes) => emit(scope, 'info', allow, message, attributes),
    warn: (message, attributes) => emit(scope, 'warn', allow, message, attributes),
    error: (message, attributes) => emit(scope, 'error', allow, message, attributes),
    fatal: (message, attributes) => emit(scope, 'fatal', allow, message, attributes),
  };
}

/**
 * winston and pino, bridged without code changes when application logs are on.
 *
 * With `captureLogs: true` (or SHIELD360_CAPTURE_LOGS=true), init() hooks the
 * loggers an app already uses, through OpenTelemetry's module hooks
 * (@opentelemetry/instrumentation), the way OpenTelemetry's own winston and
 * pino instrumentations do:
 *
 *   winston  every winston.createLogger() also gets the Shield360 transport
 *            (log-bridges.ts), built on the app's own winston.Transport. A
 *            winston already loaded before init() is patched in place.
 *   pino     every pino() logger writes to its destination and to the
 *            Shield360 stream (pino.multistream), so output is unchanged.
 *            Loggers created before init() are not changed: create them after
 *            init(), or add Shield360.pinoStream() yourself.
 *
 * The hooks are inert while application logs are off, so turning them off
 * later stops new loggers being bridged. Nothing here throws into the app: if
 * a logger cannot be bridged it is created exactly as it would have been.
 */
import { InstrumentationBase, InstrumentationNodeModuleDefinition } from '@opentelemetry/instrumentation';
import { INSTRUMENTATION_PREFIX } from '../constant';
import { appLogsEnabled } from './app-logs';
import { pinoStream, winstonTransport } from './log-bridges';

const ORIGINAL = Symbol.for('shield360.logBridge.original');
const BRIDGED = Symbol.for('shield360.logBridge.transport');

type AnyFunction = ((...args: any[]) => any) & { [ORIGINAL]?: AnyFunction; [key: string | symbol]: any };

// ---------------------------------------------------------------- winston

/** Makes winston.createLogger() add the Shield360 transport. Returns the module. */
export function patchWinston(winston: any): any {
  try {
    if (!winston || typeof winston.createLogger !== 'function' || winston.createLogger[ORIGINAL]) return winston;
    if (typeof winston.Transport !== 'function') return winston;
    const Shield360Transport = winstonTransport(winston.Transport);
    const original: AnyFunction = winston.createLogger;
    const patched: AnyFunction = function (this: unknown, ...args: unknown[]) {
      const logger = original.apply(this, args);
      if (!appLogsEnabled()) return logger;
      try {
        const transports: unknown[] = Array.isArray(logger?.transports) ? logger.transports : [];
        if (!transports.some((t) => (t as Record<symbol, unknown>)?.[BRIDGED])) {
          const transport = new Shield360Transport() as unknown as Record<symbol, unknown>;
          transport[BRIDGED] = true;
          logger.add(transport);
        }
      } catch {
        // The logger works as created.
      }
      return logger;
    };
    patched[ORIGINAL] = original;
    winston.createLogger = patched;
  } catch {
    // Left unpatched.
  }
  return winston;
}

export function unpatchWinston(winston: any): void {
  try {
    const original = winston?.createLogger?.[ORIGINAL];
    if (original) winston.createLogger = original;
  } catch {
    // Nothing to undo.
  }
}

// ------------------------------------------------------------------- pino

function isStream(value: unknown): value is { write: (...args: unknown[]) => unknown } {
  return !!value && typeof (value as { write?: unknown }).write === 'function';
}

/**
 * pino's arguments with the Shield360 stream added, or null to call pino
 * unchanged: pino(), pino(opts), pino(stream), pino(opts, stream),
 * pino(opts, 'path'), and opts.transport.
 */
export function bridgePinoArgs(pino: AnyFunction, args: unknown[]): unknown[] | null {
  let [opts, stream] = args as [unknown, unknown];
  if (args.length > 2) return null;
  if (stream === undefined && (isStream(opts) || typeof opts === 'string')) {
    stream = opts;
    opts = {};
  }
  if (opts === undefined || opts === null) opts = {};
  if (typeof opts !== 'object' || Array.isArray(opts)) return null;
  let options = opts as Record<string, unknown>;
  if (typeof pino.multistream !== 'function' || typeof pino.destination !== 'function') return null;

  if (options.transport) {
    if (stream !== undefined) return null; // pino refuses both; let it say so
    if (typeof pino.transport !== 'function') return null;
    stream = pino.transport(options.transport);
    options = { ...options };
    delete options.transport;
  }
  if (stream === undefined) stream = pino.destination((process.stdout && (process.stdout as { fd?: number }).fd) || 1);
  else if (typeof stream === 'string' || typeof stream === 'number') stream = pino.destination(stream);
  if (!isStream(stream)) return null;

  // levelVal 0: both streams see every record the logger itself lets through.
  const streams = pino.multistream([
    { levelVal: 0, stream },
    { levelVal: 0, stream: pinoStream() },
  ]);
  return [options, streams];
}

/** A pino function whose loggers also write to Shield360. Returns the module to use. */
export function patchPino(pino: any): any {
  try {
    if (typeof pino !== 'function' || pino[ORIGINAL]) return pino;
    const original = pino as AnyFunction;
    const patched: AnyFunction = function (this: unknown, ...args: unknown[]) {
      if (appLogsEnabled()) {
        let bridged: unknown[] | null = null;
        try {
          bridged = bridgePinoArgs(original, args);
        } catch {
          bridged = null;
        }
        if (bridged) return original.apply(this, bridged);
      }
      return original.apply(this, args);
    };
    Object.assign(patched, original);
    patched[ORIGINAL] = original;
    patched.default = patched;
    patched.pino = patched;
    return patched;
  } catch {
    return pino;
  }
}

// -------------------------------------------------------------- the hooks

export class Shield360LogBridgeInstrumentation extends InstrumentationBase {
  constructor() {
    super(`${INSTRUMENTATION_PREFIX}/instrumentation-log-bridges`, '1.0.0', {});
  }

  protected init() {
    return [
      new InstrumentationNodeModuleDefinition(
        'winston',
        ['>=3 <4'],
        (moduleExports) => patchWinston(moduleExports),
        (moduleExports) => unpatchWinston(moduleExports)
      ),
      new InstrumentationNodeModuleDefinition(
        'pino',
        ['>=7 <11'],
        (moduleExports) => patchPino(moduleExports),
        // The patched function is inert while application logs are off.
        (moduleExports) => moduleExports
      ),
    ];
  }
}

let instrumentation: Shield360LogBridgeInstrumentation | null = null;

/** winston loaded before init(): patched in place, since its createLogger is read at call time. */
function patchLoadedWinston(): void {
  try {
    const cache = typeof require !== 'undefined' ? require.cache : undefined;
    if (!cache) return;
    for (const [file, mod] of Object.entries(cache)) {
      if (mod && /[\\/]node_modules[\\/]winston[\\/]lib[\\/]winston\.js$/.test(file)) patchWinston(mod.exports);
    }
  } catch {
    // Nothing loaded, or nothing to patch.
  }
}

/** Hooks winston and pino (once). Called by init() when application logs are on. */
export function enableLogBridges(): void {
  try {
    if (!instrumentation) instrumentation = new Shield360LogBridgeInstrumentation();
    else instrumentation.enable();
    patchLoadedWinston();
  } catch {
    // Application logs still work through Shield360.logger() and the explicit bridges.
  }
}

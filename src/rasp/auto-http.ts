/**
 * Zero-code request capture for RASP: every `http` and `https` server's
 * `request` event runs inside a RASP request context, so sinks see the
 * request's input without any framework middleware. `shield360/register`
 * installs it when RASP is on.
 *
 * It patches `Server.prototype.emit` once, which covers Express, Fastify,
 * Koa, Nest and raw `http` alike (they all serve through `http.Server`).
 * A body a parser sets later on `req.body` is picked up when a sink first
 * reads the inputs. Framework middleware added on top (`raspExpress()` and
 * the others) replaces this context with its richer one and does not judge
 * a phase this capture already judged (a custom rule matches at most once).
 * A request with no body (no `Content-Length` or `Transfer-Encoding`) has a
 * known, empty body here, so the body phase runs at once.
 *
 * Deception (deception.ts) runs here only for plain listeners, where the
 * socket's peer is the client address and a plain `404 Not Found` is the
 * normal answer: a decoy gets that 404 before the listener, and middleware
 * added on top does not run deception again. When the listener is a framework
 * app (Express 4/5, Koa, Fastify, and Nest on them), this capture never
 * marks, judges or answers for deception: the framework knows the trusted
 * client address (`trust proxy`) and has its own not-found, so its adapter
 * (`raspExpress()`, `raspKoa()`, `raspFastify`) runs deception, and without
 * the adapter such an app gets none.
 *
 * Fail open: when capture fails the request is served as before. A block
 * thrown from a `request` listener, synchronously or as the rejection of an
 * async listener (`http.createServer(async (req, res) => ...)`), becomes the
 * contract's 403 instead of an unhandled rejection. Frameworks catch errors
 * from their own route handlers, so a block raised there is the framework's to
 * map (Express without `raspExpressErrorHandler()` answers a 500).
 */
import { EventEmitter } from 'events';
import http = require('http');
import https = require('https');
import type { IncomingMessage, ServerResponse } from 'http';
import { bodyAbsent, captureBody, captureLater, captureNoBody, captureRequest, runVirtualPatches } from './capture';
import { storage, type RaspContext } from './context';
import { isActive } from './engine';
import { checkDeception } from './deception';
import { frameworkServes, sendBlocked, sendNotFound } from './middleware';
import { RaspBlockedError } from './types';

const PATCHED = Symbol.for('shield360.rasp.autoHttp');

type Emit = (this: unknown, event: string | symbol, ...args: unknown[]) => boolean;
type Patched = { proto: Record<string | symbol, unknown>; own: boolean; original: Emit };

let patched: Patched[] = [];

const contentTypeOf = (req: IncomingMessage): string | undefined => {
  const v = req.headers?.['content-type'];
  return typeof v === 'string' ? v : undefined;
};

/** The client address `request.ip` uses: the socket's peer (no framework is in the picture yet). */
const peerOf = (req: IncomingMessage): string | undefined => {
  const v = req.socket?.remoteAddress;
  return typeof v === 'string' && v ? v : undefined;
};

/** The request's context, or `blocked` when a virtual patch blocks, or nothing when capture failed. */
function capture(req: IncomingMessage, deceptionDone: boolean): { ctx?: RaspContext; blocked?: RaspBlockedError } {
  try {
    const ctx = captureRequest({ framework: 'http', method: req.method || 'GET', url: req.url || '/', headers: req.headers, ip: peerOf(req) });
    ctx.auto = true;
    if (deceptionDone) ctx.deception = true;
    const withBody = req as IncomingMessage & { body?: unknown; files?: unknown; file?: unknown };
    const read = () => {
      const files = withBody.files ?? withBody.file;
      if (withBody.body === undefined && files === undefined) return undefined;
      return { body: withBody.body ?? {}, contentType: contentTypeOf(req), files };
    };
    const now = read();
    if (now) captureBody(ctx, now);
    else {
      captureLater(ctx, read);
      if (bodyAbsent(req.headers, req.httpVersionMajor)) captureNoBody(ctx);
    }
    runVirtualPatches(ctx);
    return { ctx };
  } catch (e) {
    if (e instanceof RaspBlockedError) return { blocked: e };
    return {};
  }
}

const CAPTURE_REJECTION = EventEmitter.captureRejectionSymbol;

/** What a rejected async listener's error would have met without the capture: the server's rejection handler, or an unhandled rejection. */
function passOn(server: unknown, e: unknown, req: IncomingMessage, res: ServerResponse): void {
  const s = server as Record<string | symbol, unknown>;
  const kCapture = Object.getOwnPropertySymbols(s).find((k) => k.description === 'kCapture');
  const handler = s[CAPTURE_REJECTION];
  if (kCapture && s[kCapture] === true && typeof handler === 'function') {
    (handler as (err: unknown, event: string, ...args: unknown[]) => void).call(server, e, 'request', req, res);
    return;
  }
  void Promise.reject(e);
}

/** Calls the `request` listeners as `emit` would, and maps a block from any of them, sync or async, to the 403. */
function serve(server: { rawListeners(event: string): unknown[] }, req: IncomingMessage, res: ServerResponse): boolean {
  const listeners = server.rawListeners('request') as ((this: unknown, ...a: unknown[]) => unknown)[];
  if (listeners.length === 0) return false;
  for (const listener of listeners) {
    let out: unknown;
    try {
      out = listener.call(server, req, res);
    } catch (e) {
      if (e instanceof RaspBlockedError) {
        sendBlocked(res, e);
        return true;
      }
      throw e;
    }
    if (out && typeof (out as Promise<unknown>).then === 'function') {
      (out as Promise<unknown>).then(undefined, (e: unknown) => {
        if (e instanceof RaspBlockedError) sendBlocked(res, e);
        else passOn(server, e, req, res);
      });
    }
  }
  return true;
}

function wrap(original: Emit): Emit {
  return function shield360Emit(this: unknown, event: string | symbol, ...args: unknown[]): boolean {
    if (event !== 'request' || !isActive()) return original.call(this, event, ...args);
    const req = args[0] as IncomingMessage;
    const res = args[1] as ServerResponse;
    // A framework app's adapter runs deception with its own client address and not-found.
    const plain = !frameworkServes(this);
    if (plain) {
      const d = checkDeception({ framework: 'http', method: req.method || 'GET', url: req.url || '/', ip: peerOf(req) });
      if (d.notFound) {
        sendNotFound(res);
        return true;
      }
      if (d.blocked) {
        sendBlocked(res, d.blocked);
        return true;
      }
    }
    const r = capture(req, plain);
    if (r.blocked) {
      sendBlocked(res, r.blocked);
      return true;
    }
    if (!r.ctx) return original.call(this, event, ...args);
    return storage.run(r.ctx, () => serve(this as { rawListeners(event: string): unknown[] }, req, res));
  };
}

/** Installs the capture on `http.Server` and `https.Server`. Idempotent; returns whether it is in place. */
export function installAutoHttpCapture(): boolean {
  try {
    for (const S of [http.Server, https.Server]) {
      const proto = S.prototype as unknown as Record<string | symbol, unknown>;
      if (proto[PATCHED]) continue;
      const own = Object.prototype.hasOwnProperty.call(proto, 'emit');
      const original = proto.emit as Emit;
      if (typeof original !== 'function') continue;
      proto.emit = wrap(original);
      Object.defineProperty(proto, PATCHED, { value: true, configurable: true });
      patched.push({ proto, own, original });
    }
    return true;
  } catch {
    return false;
  }
}

/** Removes the capture (tests). */
export function uninstallAutoHttpCapture(): void {
  for (const p of patched) {
    if (p.own) p.proto.emit = p.original;
    else delete p.proto.emit;
    delete p.proto[PATCHED];
  }
  patched = [];
}

/** Whether the capture is installed. */
export function autoHttpCaptureInstalled(): boolean {
  return Boolean((http.Server.prototype as unknown as Record<symbol, unknown>)[PATCHED]);
}

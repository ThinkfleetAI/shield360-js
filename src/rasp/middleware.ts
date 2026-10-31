/**
 * Framework middleware: Express, Fastify, Koa, raw `http` and Next.js route
 * handlers. Each runs deception first (deception.ts), then records the request's inputs (query, params, body, cookies,
 * the contract's input headers) in the request's AsyncLocalStorage context,
 * runs the virtual patches, and maps the block error to the contract's 403.
 *
 * None of these needs the framework installed: they are typed structurally.
 * While RASP is not active each passes the request straight through.
 */
import type { IncomingMessage, ServerResponse } from 'http';
import { bodyAbsent, captureBody, captureLater, captureNoBody, captureRequest, lowerHeaders, runVirtualPatches, type BodyShape } from './capture';
import { currentContext, storage, type RaspContext } from './context';
import { checkDeception, type DeceptionOutcome, type DeceptionRequest } from './deception';
import { isActive } from './engine';
import { blockBody, RaspBlockedError } from './types';

export function isRaspBlocked(e: unknown): e is RaspBlockedError {
  return e instanceof RaspBlockedError;
}

const BLOCK_HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };

/** Writes the 403 on a Node response (no-op once the headers are out). */
export function sendBlocked(res: ServerResponse, e: RaspBlockedError): void {
  try {
    if (res.headersSent || res.writableEnded) {
      if (!res.writableEnded) res.end();
      return;
    }
    res.statusCode = 403;
    for (const [k, v] of Object.entries(BLOCK_HEADERS)) res.setHeader(k, v);
    res.end(JSON.stringify(blockBody(e)));
  } catch {
    // the response is already gone
  }
}

/** The 403 as a fetch Response (Next.js and other fetch-style handlers). */
export function blockedResponse(e: RaspBlockedError): Response {
  return new Response(JSON.stringify(blockBody(e)), { status: 403, headers: BLOCK_HEADERS });
}

/** The client address: the framework's own (Express `req.ip` honors `trust proxy`), else the socket's peer. */
const ipOf = (own: unknown, req?: { socket?: { remoteAddress?: unknown } }): string | undefined => {
  const v = typeof own === 'string' && own ? own : req?.socket?.remoteAddress;
  return typeof v === 'string' && v ? v : undefined;
};

/** Deception, unless the zero-code capture already ran it for this request (it answers decoys itself). */
function deceive(r: DeceptionRequest): DeceptionOutcome {
  return currentContext()?.deception ? {} : checkDeception(r);
}

/**
 * The 404 where a framework has no not-found of its own (raw `http`, the
 * zero-code capture): `404 Not Found` as plain text.
 */
export function sendNotFound(res: ServerResponse): void {
  try {
    if (res.headersSent || res.writableEnded) {
      if (!res.writableEnded) res.end();
      return;
    }
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Length', '9');
    res.end('Not Found');
  } catch {
    // the response is already gone
  }
}

const FRAMEWORK_SERVER = Symbol.for('shield360.rasp.frameworkServer');

/** Notes that a framework adapter serves this server, so the zero-code capture leaves deception to it. */
function markFrameworkServer(server: unknown): void {
  try {
    if (server && typeof server === 'object' && !(server as Record<symbol, unknown>)[FRAMEWORK_SERVER]) {
      Object.defineProperty(server, FRAMEWORK_SERVER, { value: true, configurable: true });
    }
  } catch {
    // best effort
  }
}

const socketServer = (req: { socket?: unknown } | undefined): unknown => (req?.socket as { server?: unknown } | undefined)?.server;

/**
 * Whether a server's `request` listener is a framework app, which resolves the
 * client address itself (`trust proxy`) and has its own not-found: an Express
 * 4/5 app (the app function, with `handle`, `use`, `set` and `settings`), Koa's
 * `callback()` (`handleRequest`) or Fastify's router entry (`preRouting`); the
 * last two are bare closures, so only their names tell. A server an adapter
 * already served (`raspFastify` notes its server when registered, the others
 * on their first request) counts too, which covers a renamed or wrapped app.
 */
export function frameworkServes(server: unknown): boolean {
  try {
    const s = server as { rawListeners?(event: string): unknown[] } & Record<symbol, unknown>;
    if (!s) return false;
    if (s[FRAMEWORK_SERVER]) return true;
    for (const raw of s.rawListeners?.('request') ?? []) {
      // once() listeners are wrapped; the app is the wrapper's `listener`.
      const l = (raw as { listener?: unknown }).listener ?? raw;
      if (typeof l !== 'function') continue;
      const o = l as unknown as Record<string, unknown>;
      if (typeof o.handle === 'function' && typeof o.use === 'function' && typeof o.set === 'function' && o.settings && typeof o.settings === 'object') return true;
      if (l.name === 'handleRequest' || l.name === 'preRouting') return true;
    }
  } catch {
    // unknown: treat as plain
  }
  return false;
}

const contentTypeOf = (h: Record<string, unknown> | undefined): string | undefined => {
  const v = h?.['content-type'];
  return typeof v === 'string' ? v : undefined;
};

/**
 * Starts a request context. Returns the context, `blocked` with the error
 * when a virtual patch blocks, or undefined when capture failed (fail open).
 * `noBody` says the request has no body at all (its body is known, empty).
 */
function begin(make: () => RaspContext, body: () => BodyShape | undefined, noBody?: () => boolean): { ctx?: RaspContext; blocked?: RaspBlockedError } {
  let ctx: RaspContext | undefined;
  try {
    ctx = make();
    const b = body();
    if (b && b.body !== undefined && b.body !== null) captureBody(ctx, b);
    else {
      // A body that shows up anyway (an adapter that sent no length) is still captured late.
      captureLater(ctx, body);
      if (noBody?.()) captureNoBody(ctx);
    }
    runVirtualPatches(ctx);
    return { ctx };
  } catch (e) {
    if (e instanceof RaspBlockedError) return { blocked: e };
    return { ctx: undefined };
  }
}

// ---- Express ---------------------------------------------------------------

type ExpressReq = IncomingMessage & { originalUrl?: string; query?: unknown; params?: unknown; body?: unknown; route?: { path?: unknown }; ip?: unknown };
type Next = (err?: unknown) => void;

const URL_UNSAFE = /(?:[^\x21\x23-\x3B\x3D\x3F-\x5F\x61-\x7A\x7C\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
const SURROGATE = /([\uD800-\uDBFF][\uDC00-\uDFFF])|[\uD800-\uDFFF]/g;
const HTML_ESCAPES: Record<string, string> = { '"': '&quot;', '&': '&amp;', "'": '&#39;', '<': '&lt;', '>': '&gt;' };

/**
 * Express's own answer to an unknown path, byte for byte: finalhandler's 404
 * (`Cannot GET /path` in its HTML page, with its security headers), which
 * Express 4 and 5 send when no route matches. It is written here rather than
 * reached with `next('router')`: that only leaves the router the middleware
 * is mounted on, so mounted on a sub-router it would go on to the parent's
 * handlers, and at the app level it skips the app's own 404 middleware just
 * the same. An app with its own 404 page passes `raspExpress({ notFound })`.
 */
export function sendExpressNotFound(req: IncomingMessage & { originalUrl?: string }, res: ServerResponse): void {
  try {
    if (res.headersSent || res.writableEnded) {
      if (!res.writableEnded) res.end();
      return;
    }
    // finalhandler: 'Cannot ' + method + ' ' + encodeUrl(pathname of the original URL), HTML-escaped.
    const target = req.originalUrl || req.url || '/';
    const end = target.search(/[?#]/);
    const path = (end >= 0 ? target.slice(0, end) : target).replace(SURROGATE, (_, pair: string | undefined) => pair || '\uFFFD').replace(URL_UNSAFE, encodeURI);
    const message = `Cannot ${req.method} ${path}`
      .replace(/["&'<>]/g, (c) => HTML_ESCAPES[c])
      .replace(/\n/g, '<br>')
      .replace(/ {2}/g, ' &nbsp;');
    const body = `<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n<body>\n<pre>${message}</pre>\n</body>\n</html>\n`;
    res.statusCode = 404;
    if (req.httpVersionMajor < 2) res.statusMessage = 'Not Found';
    res.removeHeader('Content-Encoding');
    res.removeHeader('Content-Language');
    res.removeHeader('Content-Range');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Length', Buffer.byteLength(body, 'utf8'));
    if (req.method === 'HEAD') res.end();
    else res.end(body, 'utf8');
  } catch {
    // the response is already gone
  }
}

export type RaspExpressOptions = {
  /**
   * Answers a decoy path ("Deception") instead of Express's default 404, for
   * an app with its own not-found page. Must send the response; the route
   * handlers are never called either way.
   */
  notFound?: (req: IncomingMessage, res: ServerResponse) => void;
};

/**
 * Express (4 and 5). Register it after the body parsers so the body is seen
 * before the handler; registered earlier, the body is still captured when a
 * sink first reads the inputs.
 *
 *   app.use(express.json());
 *   app.use(raspExpress());
 *   ...routes...
 *   app.use(raspExpressErrorHandler());
 */
export function raspExpress(options: RaspExpressOptions = {}) {
  return function shield360Rasp(req: ExpressReq, res: ServerResponse, next: Next): void {
    if (!isActive()) return next();
    markFrameworkServer(socketServer(req));
    // The full target the client sent (`originalUrl`: a router mount does not strip it).
    const d = deceive({ framework: 'express', method: req.method || 'GET', url: req.originalUrl || req.url || '/', ip: ipOf(req.ip, req) });
    if (d.notFound) {
      try {
        if (options.notFound) return options.notFound(req, res);
      } catch {
        // the app's page failed: Express's own 404 below
      }
      return sendExpressNotFound(req, res);
    }
    if (d.blocked) return sendBlocked(res, d.blocked);
    const r = begin(
      () =>
        captureRequest({
          framework: 'express',
          method: req.method || 'GET',
          url: req.originalUrl || req.url || '/',
          headers: req.headers,
          query: req.query,
          params: req.params,
          ip: ipOf(req.ip, req),
        }),
      () => {
        const files = (req as { file?: unknown; files?: unknown }).files ?? (req as { file?: unknown }).file;
        return req.body === undefined && files === undefined ? undefined : { body: req.body ?? {}, contentType: contentTypeOf(req.headers), files };
      },
      () => bodyAbsent(req.headers, req.httpVersionMajor),
    );
    if (r.blocked) return sendBlocked(res, r.blocked);
    if (!r.ctx) return next();
    storage.run(r.ctx, () => next());
  };
}

/** Maps the block error from a handler to the 403; passes every other error on. */
export function raspExpressErrorHandler() {
  return function shield360RaspErrors(err: unknown, _req: IncomingMessage, res: ServerResponse, next: Next): void {
    if (isRaspBlocked(err)) return sendBlocked(res, err);
    next(err);
  };
}

// ---- Fastify ---------------------------------------------------------------

type FastifyRequest = {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  query?: unknown;
  params?: unknown;
  body?: unknown;
  routeOptions?: { url?: string };
  routerPath?: string;
  ip?: unknown;
  /** True while Fastify serves the request with its not-found handler (no route matched). */
  is404?: boolean;
  [k: symbol]: unknown;
};
type FastifyReply = { code(n: number): FastifyReply; header(k: string, v: string): FastifyReply; send(body: unknown): unknown; callNotFound?(): unknown };
type FastifyLike = { server?: unknown; addHook(name: string, fn: (request: FastifyRequest, reply: FastifyReply, done: Next) => void): unknown };

const FASTIFY_CTX = Symbol('shield360.rasp.context');

function fastifyBlocked(reply: FastifyReply, e: RaspBlockedError): void {
  try {
    let r = reply.code(403);
    for (const [k, v] of Object.entries(BLOCK_HEADERS)) r = r.header(k, v);
    r.send(JSON.stringify(blockBody(e)));
  } catch {
    // the reply is already gone
  }
}

/**
 * A decoy gets Fastify's not-found: `reply.callNotFound()` (the app's
 * `setNotFoundHandler`, else Fastify's JSON 404). A decoy that matches no
 * route is already on its way to that handler, so the request just goes on
 * (callNotFound from there would send a bare 404 instead).
 */
function fastifyNotFound(request: FastifyRequest, reply: FastifyReply, next: Next): void {
  if (request.is404) return next();
  try {
    if (typeof reply.callNotFound === 'function') {
      reply.callNotFound();
      return;
    }
    reply.code(404).send({ message: `Route ${request.method}:${request.url} not found`, error: 'Not Found', statusCode: 404 });
  } catch {
    // the reply is already gone
  }
}

function fastifyNoBody(method: string, headers: Record<string, string | string[] | undefined>): boolean {
  const m = method.toUpperCase();
  if (m === 'GET' || m === 'HEAD') return true;
  if (!bodyAbsent(headers)) return false;
  const len = headers['content-length'];
  return headers['content-type'] === undefined || (typeof len === 'string' && len.trim() === '0');
}

/**
 * Fastify plugin: `fastify.register(raspFastify)`. Applies to every route
 * (it skips encapsulation, as fastify-plugin would). Inputs are captured in
 * `onRequest`, the body in `preHandler`. A handler that lets the block error
 * through gets a 403 from Fastify's default error handler (`statusCode`).
 */
export function raspFastify(fastify: FastifyLike, _opts: unknown, done: Next): void {
  markFrameworkServer(fastify.server);
  fastify.addHook('onRequest', (request, reply, next) => {
    if (!isActive()) return next();
    const d = deceive({ framework: 'fastify', method: request.method, url: request.url, ip: ipOf(request.ip) });
    if (d.notFound) return fastifyNotFound(request, reply, next);
    if (d.blocked) return fastifyBlocked(reply, d.blocked);
    const route = request.routeOptions?.url ?? request.routerPath;
    const r = begin(
      () =>
        captureRequest({
          framework: 'fastify',
          method: request.method,
          url: request.url,
          headers: request.headers,
          query: request.query,
          params: request.params,
          route: typeof route === 'string' ? route : undefined,
          ip: ipOf(request.ip),
        }),
      () => undefined,
      // No body as Fastify judges it: it never parses a GET or HEAD body, an explicit
      // Content-Length: 0 carries none whatever the content type, and without a content type
      // it parses nothing when there is neither a length nor chunks.
      () => fastifyNoBody(request.method, request.headers),
    );
    if (r.blocked) return fastifyBlocked(reply, r.blocked);
    if (!r.ctx) return next();
    r.ctx.late = undefined;
    request[FASTIFY_CTX] = r.ctx;
    storage.run(r.ctx, () => next());
  });
  fastify.addHook('preHandler', (request, reply, next) => {
    const ctx = request[FASTIFY_CTX] as RaspContext | undefined;
    if (!ctx || !isActive()) return next();
    try {
      if (request.body !== undefined && request.body !== null) captureBody(ctx, { body: request.body, contentType: contentTypeOf(request.headers) });
      runVirtualPatches(ctx);
    } catch (e) {
      if (e instanceof RaspBlockedError) return fastifyBlocked(reply, e);
    }
    storage.run(ctx, () => next());
  });
  done();
}
(raspFastify as unknown as Record<symbol, unknown>)[Symbol.for('skip-override')] = true;
(raspFastify as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] = 'shield360-rasp';

// ---- Koa ---------------------------------------------------------------------

type KoaContext = {
  method: string;
  url: string;
  originalUrl?: string;
  headers?: Record<string, string | string[] | undefined>;
  query?: unknown;
  params?: unknown;
  _matchedRoute?: unknown;
  ip?: unknown;
  request?: { body?: unknown; headers?: Record<string, string | string[] | undefined> };
  req?: { httpVersionMajor?: number };
  status?: number;
  body?: unknown;
  set?(k: string, v: string): void;
};

function koaBlocked(k: KoaContext, e: RaspBlockedError): void {
  k.status = 403;
  try {
    for (const [h, v] of Object.entries(BLOCK_HEADERS)) k.set?.(h, v);
  } catch {
    // headers are best effort
  }
  k.body = blockBody(e);
}

/** Koa middleware: `app.use(raspKoa())`, ideally after the body parser. */
export function raspKoa() {
  return async function shield360Rasp(k: KoaContext, next: () => Promise<unknown>): Promise<void> {
    if (!isActive()) {
      await next();
      return;
    }
    markFrameworkServer(socketServer(k.req as { socket?: unknown } | undefined));
    const d = deceive({ framework: 'koa', method: k.method, url: k.originalUrl || k.url || '/', ip: ipOf(k.ip) });
    if (d.notFound) {
      // What Koa does with a path nothing answers: status 404 and no body, so Koa sends "Not Found" as text/plain.
      k.status = 404;
      return;
    }
    if (d.blocked) return koaBlocked(k, d.blocked);
    const headers = k.headers ?? k.request?.headers ?? {};
    const r = begin(
      () =>
        captureRequest({
          framework: 'koa',
          method: k.method,
          url: k.originalUrl || k.url || '/',
          headers,
          query: k.query,
          params: k.params,
          route: typeof k._matchedRoute === 'string' ? k._matchedRoute : undefined,
          ip: ipOf(k.ip),
        }),
      () => (k.request?.body === undefined ? undefined : { body: k.request.body, contentType: contentTypeOf(headers) }),
      () => bodyAbsent(headers, k.req?.httpVersionMajor),
    );
    if (r.blocked) return koaBlocked(k, r.blocked);
    if (!r.ctx) {
      await next();
      return;
    }
    try {
      await storage.run(r.ctx, () => next());
    } catch (e) {
      if (e instanceof RaspBlockedError) return koaBlocked(k, e);
      throw e;
    }
  };
}

// ---- raw http ------------------------------------------------------------------

type HttpHandler = (req: IncomingMessage, res: ServerResponse) => unknown;

/**
 * Wraps a raw `http` request handler: `http.createServer(raspHttp(handler))`.
 * The body is the handler's to read; once it has, `recordRequestBody(body)`
 * adds it (and runs the virtual patches that read the body). A `req.body`
 * set by a parser is picked up when a sink first reads the inputs.
 */
export function raspHttp<H extends HttpHandler>(handler: H): H {
  const wrapped = function (this: unknown, req: IncomingMessage, res: ServerResponse): unknown {
    if (!isActive()) return handler.call(this, req, res);
    const d = deceive({ framework: 'http', method: req.method || 'GET', url: req.url || '/', ip: ipOf(undefined, req) });
    if (d.notFound) return sendNotFound(res);
    if (d.blocked) return sendBlocked(res, d.blocked);
    const withBody = req as IncomingMessage & { body?: unknown };
    const r = begin(
      () => captureRequest({ framework: 'http', method: req.method || 'GET', url: req.url || '/', headers: req.headers, ip: ipOf(undefined, req) }),
      () => (withBody.body === undefined ? undefined : { body: withBody.body, contentType: contentTypeOf(req.headers) }),
      () => bodyAbsent(req.headers, req.httpVersionMajor),
    );
    if (r.blocked) return sendBlocked(res, r.blocked);
    if (!r.ctx) return handler.call(this, req, res);
    return storage.run(r.ctx, () => {
      try {
        const out = handler.call(this, req, res) as unknown;
        if (out && typeof (out as Promise<unknown>).then === 'function') {
          return (out as Promise<unknown>).then(undefined, (e: unknown) => {
            if (e instanceof RaspBlockedError) return sendBlocked(res, e);
            throw e;
          });
        }
        return out;
      } catch (e) {
        if (e instanceof RaspBlockedError) return sendBlocked(res, e);
        throw e;
      }
    });
  };
  return wrapped as unknown as H;
}

/**
 * Adds a body the app read itself to the current request's inputs and runs
 * the virtual patches that read the body. Throws the block error when one
 * blocks; otherwise never throws.
 */
export function recordRequestBody(body: unknown, contentType?: string): void {
  if (!isActive()) return;
  const ctx = currentContext();
  // Once a body was captured; a body the SDK took to be absent is still added.
  if (!ctx?.inRequest || ctx.headInputs !== undefined) return;
  try {
    ctx.late = undefined;
    captureBody(ctx, { body, contentType });
    runVirtualPatches(ctx);
  } catch (e) {
    if (e instanceof RaspBlockedError) throw e;
  }
}

// ---- Next.js route handlers ------------------------------------------------------

const MAX_READ = 1024 * 1024;
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Reads at most `max` bytes of a cloned request body as text. */
async function readCapped(req: Request, max: number): Promise<string | undefined> {
  if (!req.body) return undefined;
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, max).toString('utf8');
}

type RouteHandler<C> = (request: Request, context: C) => Response | Promise<Response>;

/**
 * Wraps a Next.js App Router route handler (Node.js runtime):
 *
 *   export const POST = withRasp(async (request) => { ... });
 *
 * The body is read from a clone (up to 1 MiB), so the handler can still read it.
 */
export function withRasp<C = unknown>(handler: RouteHandler<C>): RouteHandler<C> {
  return async function shield360Rasp(request: Request, context: C): Promise<Response> {
    if (!isActive()) return handler(request, context);
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return handler(request, context);
    }
    // Next.js gives only the parsed URL (dot segments already resolved) and no client address, so a hit marks nothing.
    const d = deceive({ framework: 'nextjs', method: request.method, url: url.pathname + url.search });
    // What `notFound()` gives in a route handler: an empty 404.
    if (d.notFound) return new Response(null, { status: 404 });
    if (d.blocked) return blockedResponse(d.blocked);
    let ctx: RaspContext | undefined;
    try {
      const headers: Record<string, string> = {};
      request.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      let params: unknown;
      try {
        const p = (context as { params?: unknown } | undefined)?.params;
        params = p && typeof (p as Promise<unknown>).then === 'function' ? await p : p;
      } catch {
        params = undefined;
      }
      ctx = captureRequest({ framework: 'nextjs', method: request.method, url: url.pathname + url.search, headers, params });
      runVirtualPatches(ctx);
      if (!request.body) {
        // No body at all (a GET, an empty POST): the body is known and empty.
        captureNoBody(ctx);
        runVirtualPatches(ctx);
      } else if (BODY_METHODS.has(request.method.toUpperCase()) && !request.bodyUsed) {
        const text = await readCapped(request.clone(), MAX_READ);
        if (text !== undefined) captureBody(ctx, { body: text, contentType: headers['content-type'] });
        runVirtualPatches(ctx);
      }
    } catch (e) {
      if (e instanceof RaspBlockedError) return blockedResponse(e);
      ctx = undefined;
    }
    if (!ctx) return handler(request, context);
    try {
      return await storage.run(ctx, () => handler(request, context));
    } catch (e) {
      if (e instanceof RaspBlockedError) return blockedResponse(e);
      throw e;
    }
  };
}

export { lowerHeaders };

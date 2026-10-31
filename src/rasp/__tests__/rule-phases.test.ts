/**
 * When request rules run (README "Custom rules: when rules run"), on every
 * entry point:
 * - at head, `input.*` sees only the inputs known before the body, even when
 *   the framework hands over an already-parsed body;
 * - a request with no body (or an empty one) has a known, empty body, so the
 *   body phase still runs; a body the SDK cannot read yet stays unknown;
 * - findings raised during capture are judged with the request current;
 * - a rule matches at most once per request, also when framework middleware
 *   replaces the zero-code capture's context.
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server } from 'http';
import type { AddressInfo } from 'net';
import { installAutoHttpCapture, uninstallAutoHttpCapture } from '../auto-http';
import { captureBody, captureRequest, runVirtualPatches } from '../capture';
import { currentContext } from '../context';
import { resetCustomRuleWarnings } from '../custom-rules';
import { configureEngine, setEventSink, setRemoteConfig, type RemoteConfig } from '../engine';
import { raspExpress, raspFastify, raspHttp, raspKoa, recordRequestBody, withRasp } from '../middleware';
import { RaspBlockedError } from '../types';

type Event = { name: string; time: string; attrs: Record<string, string> };
let events: Event[] = [];

function remote(customRules: unknown[], attacks: RemoteConfig['attacks'] = {}): RemoteConfig {
  return { version: 'v1', exp: Math.floor(Date.now() / 1000) + 3600, killSwitch: false, snippets: false, mode: 'monitor', attacks, rules: [], customRules };
}
const rule = (id: string, expression: string, action = 'monitor') => ({ id, name: id, expression, action, enabled: true });

beforeEach(() => {
  resetCustomRuleWarnings();
  events = [];
  configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
  setEventSink({ add: (e) => events.push(e) });
});
afterEach(() => {
  setEventSink(undefined);
  setRemoteConfig(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

const fired = () => events.filter((e) => e.attrs['shield360.rasp.attack'] === 'custom_rule').map((e) => e.attrs['shield360.rasp.rule']);

function res() {
  const r: any = { statusCode: 0, headersSent: false, writableEnded: false, body: '', setHeader: () => undefined };
  r.end = (b: string) => ((r.body = b), (r.writableEnded = true));
  return r;
}

function fastify() {
  const hooks: Record<string, any> = {};
  raspFastify({ addHook: (name: string, fn: any) => (hooks[name] = fn) } as any, {}, () => undefined);
  const reply: any = { status: 0, code: (n: number) => ((reply.status = n), reply), header: () => reply, send: (b: unknown) => (reply.sent = b) };
  return { hooks, reply };
}

const JSON_POST = { 'content-type': 'application/json', 'content-length': '13' };

describe('head rules see only the inputs known before the body', () => {
  // In list order: a body rule, then an input rule that only a body input matches.
  // Judged at head, the input rule would match first; judged at body, it follows the body rule.
  beforeEach(() =>
    setRemoteConfig(remote([rule('body-rule', 'request.body["role"] != null'), rule('input-rule', 'input.key == "body.role"')])),
  );
  const atBody = ['custom.body-rule', 'custom.input-rule'];

  it('capture core: a body captured before the head is judged', () => {
    const ctx = captureRequest({ framework: 'test', method: 'POST', url: '/a', headers: JSON_POST });
    captureBody(ctx, { body: { role: 'admin' }, contentType: 'application/json' });
    runVirtualPatches(ctx);
    expect(fired()).toEqual(atBody);
  });

  it('raspExpress with an already-parsed body', () => {
    const next = jest.fn();
    raspExpress()({ method: 'POST', url: '/a', originalUrl: '/a', headers: JSON_POST, query: {}, params: {}, body: { role: 'admin' } } as any, res(), next);
    expect(next).toHaveBeenCalled();
    expect(fired()).toEqual(atBody);
  });

  it('raspKoa with an already-parsed body', async () => {
    const k: any = { method: 'POST', url: '/a', headers: JSON_POST, query: {}, request: { body: { role: 'admin' } }, set: jest.fn() };
    await raspKoa()(k, jest.fn(async () => undefined));
    expect(fired()).toEqual(atBody);
  });

  it('raspHttp with a body a parser set', () => {
    const handler = jest.fn();
    raspHttp(handler)({ method: 'POST', url: '/a', headers: JSON_POST, body: { role: 'admin' }, socket: {} } as any, res());
    expect(handler).toHaveBeenCalled();
    expect(fired()).toEqual(atBody);
  });

  it('raspFastify (body arrives in preHandler)', () => {
    const { hooks, reply } = fastify();
    const request: any = { method: 'POST', url: '/a', headers: JSON_POST, query: {}, params: {} };
    hooks.onRequest(request, reply, jest.fn());
    request.body = { role: 'admin' };
    const next = jest.fn();
    hooks.preHandler(request, reply, next);
    expect(next).toHaveBeenCalled();
    expect(fired()).toEqual(atBody);
  });

  it('withRasp (body read from a clone)', async () => {
    const out = await withRasp(async () => new Response('ran'))(
      new Request('http://localhost/a', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"role":"admin"}' }),
      {},
    );
    expect(await out.text()).toBe('ran');
    expect(fired()).toEqual(atBody);
  });

  it('upload file names join at body too', () => {
    setRemoteConfig(remote([rule('body-rule', 'request.method == "POST" && request.body["x"] == null'), rule('upload-name', 'input.key == "body.doc.filename"')]));
    const next = jest.fn();
    raspExpress()(
      { method: 'POST', url: '/up', originalUrl: '/up', headers: { 'content-length': '10' }, query: {}, params: {}, body: {}, files: [{ fieldname: 'doc', originalname: 'a.txt' }] } as any,
      res(),
      next,
    );
    expect(fired()).toEqual(['custom.body-rule', 'custom.upload-name']);
  });

  it('a head input rule still matches at head', () => {
    setRemoteConfig(remote([rule('body-rule', 'request.body["role"] != null'), rule('q', 'input.key == "query.a"')]));
    const ctx = captureRequest({ framework: 'test', method: 'POST', url: '/a?a=1', headers: JSON_POST });
    captureBody(ctx, { body: { role: 'admin' }, contentType: 'application/json' });
    runVirtualPatches(ctx);
    expect(fired()).toEqual(['custom.q', 'custom.body-rule']);
  });
});

describe('a request with no body has a known, empty body', () => {
  beforeEach(() => setRemoteConfig(remote([rule('no-role', 'request.body["role"] == null')])));

  it('raspHttp GET', () => {
    raspHttp(jest.fn())({ method: 'GET', url: '/a', headers: {}, httpVersionMajor: 1, socket: {} } as any, res());
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspHttp empty POST (content-length 0)', () => {
    raspHttp(jest.fn())({ method: 'POST', url: '/a', headers: { 'content-length': '0' }, httpVersionMajor: 1, socket: {} } as any, res());
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspHttp POST with a body the handler has not read stays unknown until recordRequestBody', () => {
    const handler = jest.fn((_q: unknown, _r: unknown) => {
      expect(fired()).toEqual([]);
      recordRequestBody('{}', 'application/json');
    });
    raspHttp(handler)({ method: 'POST', url: '/a', headers: JSON_POST, httpVersionMajor: 1, socket: {} } as any, res());
    expect(handler).toHaveBeenCalled();
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('a body that arrives anyway (no length sent) is still captured as input', () => {
    let keys: string[] = [];
    const handler = jest.fn((_q: unknown, _r: unknown) => {
      recordRequestBody({ file: '../../etc/passwd' });
      keys = (currentContext()?.inputs ?? []).map((i) => i.key);
    });
    raspHttp(handler)({ method: 'POST', url: '/a', headers: {}, httpVersionMajor: 1, socket: {} } as any, res());
    expect(fired()).toEqual(['custom.no-role']);
    expect(keys).toContain('body.file');
  });

  it('raspExpress GET without a body parser', () => {
    raspExpress()({ method: 'GET', url: '/a', originalUrl: '/a', headers: {}, httpVersionMajor: 1, query: {}, params: {} } as any, res(), jest.fn());
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspExpress empty JSON body', () => {
    raspExpress()({ method: 'POST', url: '/a', originalUrl: '/a', headers: JSON_POST, query: {}, params: {}, body: {} } as any, res(), jest.fn());
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspKoa GET', async () => {
    const k: any = { method: 'GET', url: '/a', headers: {}, query: {}, request: {}, req: { httpVersionMajor: 1 }, set: jest.fn() };
    await raspKoa()(k, jest.fn(async () => undefined));
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspFastify GET', () => {
    const { hooks, reply } = fastify();
    const request: any = { method: 'GET', url: '/a', headers: {}, query: {}, params: {} };
    hooks.onRequest(request, reply, jest.fn());
    const next = jest.fn();
    hooks.preHandler(request, reply, next);
    expect(next).toHaveBeenCalled();
    expect(fired()).toEqual(['custom.no-role']);
  });

  it.each([
    ['GET with Content-Length: 0 and a content type', 'GET', { 'content-type': 'application/json', 'content-length': '0' }],
    ['GET with a content type and no length', 'GET', { 'content-type': 'application/json' }],
    ['POST with Content-Length: 0 and a content type the parser leaves unset', 'POST', { 'content-type': 'application/json', 'content-length': '0' }],
  ])('raspFastify %s', (_name, method, headers) => {
    const { hooks, reply } = fastify();
    const request: any = { method, url: '/a', headers, query: {}, params: {} };
    hooks.onRequest(request, reply, jest.fn());
    hooks.preHandler(request, reply, jest.fn());
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('raspFastify multipart left unparsed stays unknown', () => {
    const { hooks, reply } = fastify();
    const request: any = { method: 'POST', url: '/a', headers: { 'content-type': 'multipart/form-data; boundary=x', 'content-length': '99' }, query: {}, params: {} };
    hooks.onRequest(request, reply, jest.fn());
    hooks.preHandler(request, reply, jest.fn());
    expect(fired()).toEqual([]);
  });

  it('withRasp GET', async () => {
    const out = await withRasp(async () => new Response('ran'))(new Request('http://localhost/a'), {});
    expect(await out.text()).toBe('ran');
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('withRasp empty POST', async () => {
    await withRasp(async () => new Response('ran'))(new Request('http://localhost/a', { method: 'POST' }), {});
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('a body-phase rule can block a body-less request', () => {
    setRemoteConfig(remote([rule('no-role', 'request.method == "GET" && request.body["role"] == null', 'block')], { custom_rule: 'block' }));
    const handler = jest.fn();
    const r = res();
    raspHttp(handler)({ method: 'GET', url: '/a', headers: {}, httpVersionMajor: 1, socket: {} } as any, r);
    expect(handler).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(403);
  });
});

async function serve(listener: (req: IncomingMessage, r: any) => void, path: string, opts: { method?: string; body?: string; headers?: Record<string, string> } = {}): Promise<number> {
  installAutoHttpCapture();
  const server: Server = createServer(listener);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', () => ok()));
  try {
    const { port } = server.address() as AddressInfo;
    return await new Promise<number>((ok, fail) => {
      const rq = httpRequest(`http://127.0.0.1:${port}${path}`, { method: opts.method ?? 'GET', headers: opts.headers }, (r) => {
        r.resume();
        r.on('end', () => ok(r.statusCode || 0));
      }).on('error', fail);
      rq.end(opts.body);
    });
  } finally {
    server.closeAllConnections();
    await new Promise((ok) => server.close(ok));
    uninstallAutoHttpCapture();
  }
}

describe('the zero-code http capture', () => {
  it('runs the body phase for a GET', async () => {
    setRemoteConfig(remote([rule('no-role', 'request.body["role"] == null')]));
    expect(await serve((_q, r) => r.end('ran'), '/a')).toBe(200);
    expect(fired()).toEqual(['custom.no-role']);
  });

  it('a rule matches once when framework middleware replaces its context (GET)', async () => {
    setRemoteConfig(remote([rule('q', 'input.key == "query.a"'), rule('no-role', 'request.body["role"] == null')]));
    const status = await serve((req, r) => {
      const q = req as any;
      q.originalUrl = req.url;
      q.query = { a: '1' };
      q.params = {};
      raspExpress()(q, r, () => r.end('ran'));
    }, '/a?a=1');
    expect(status).toBe(200);
    expect(fired()).toEqual(['custom.q', 'custom.no-role']);
  });

  it('a rule matches once when framework middleware replaces its context (POST body)', async () => {
    setRemoteConfig(remote([rule('q', 'input.key == "query.a"')]));
    const status = await serve(
      (req, r) => {
        const q = req as any;
        q.originalUrl = req.url;
        q.query = { a: '1' };
        q.params = {};
        q.body = { role: 'admin' };
        raspExpress()(q, r, () => r.end('ran'));
      },
      '/a?a=1',
      { method: 'POST', body: '{"role":"admin"}', headers: { 'content-type': 'application/json' } },
    );
    expect(status).toBe(200);
    expect(fired()).toEqual(['custom.q']);
  });
});

describe('findings raised during capture are judged with the request current', () => {
  it('an upload finding rule sees request.ip and the inputs (raspExpress)', () => {
    setRemoteConfig(
      remote([rule('upload', 'attack.type == "file_write" && request.ip == "10.0.0.9" && input.key == "body.f.filename"', 'block')], { custom_rule: 'block' }),
    );
    const next = jest.fn();
    const r = res();
    raspExpress()(
      { method: 'POST', url: '/up', originalUrl: '/up', headers: {}, ip: '10.0.0.9', query: {}, params: {}, body: {}, files: [{ fieldname: 'f', originalname: 'shell.php' }] } as any,
      r,
      next,
    );
    expect(next).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(403);
    expect(JSON.parse(r.body)).toMatchObject({ rule: 'custom.upload' });
  });

  it('a late upload check blocks through recordRequestBody', () => {
    setRemoteConfig(remote([rule('upload', 'attack.type == "file_write" && request.path == "/up"', 'block')], { custom_rule: 'block' }));
    let thrown: unknown;
    raspHttp((_q: unknown, _r: unknown) => {
      try {
        recordRequestBody('--x\r\ncontent-disposition: form-data; name="f"; filename="shell.php"\r\n\r\n<?php\r\n--x--', 'multipart/form-data; boundary=x');
      } catch (e) {
        thrown = e;
      }
    })({ method: 'POST', url: '/up', headers: { 'content-length': '80' }, httpVersionMajor: 1, socket: {} } as any, res());
    expect(thrown).toBeInstanceOf(RaspBlockedError);
  });
});

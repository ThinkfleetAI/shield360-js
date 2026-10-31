/**
 * Middleware per framework: inputs recorded in the request's context (query,
 * params, body, cookies, the input headers), virtual patches run before the
 * handler, the block error mapped to the contract's 403. The frameworks are
 * not dependencies of the SDK, so Express, Fastify and Koa are driven through
 * their middleware signatures; raw http and Next.js use the real runtime.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import { currentContext, inputsOf, storage } from '../context';
import { captureRequest } from '../capture';
import { configureEngine, setEventSink } from '../engine';
import { raspExpress, raspExpressErrorHandler, raspFastify, raspHttp, raspKoa, recordRequestBody, withRasp } from '../middleware';
import { recordModelResponse } from '../model-output';
import { BLOCK_MESSAGE, RaspBlockedError, type AttackType, type RaspMode } from '../types';
import { BUILT_IN_RULES, type VpRequest } from '../vpatch';
import { requestFor } from './corpus';

const exampleRule = BUILT_IN_RULES.find((r) => r.example)!;
const bodyRule = BUILT_IN_RULES.find((r) => r.id === 'vp.react2shell')!;
const exampleHeaders = requestFor(exampleRule).headers as Record<string, string>;
const bodyShape: VpRequest = requestFor(bodyRule);

const events: any[] = [];
function setMode(vp: RaspMode, extra: Partial<Record<AttackType, RaspMode>> = {}) {
  configureEngine({ enabled: true, applicationName: 'orders-api', attacks: { virtual_patch: vp, ...extra }, env: {} });
  setEventSink({ add: (e) => events.push(e) });
}
const keys = () => {
  const ctx = currentContext();
  return ctx ? Object.fromEntries(inputsOf(ctx).map((i) => [i.key, i.value])) : null;
};

beforeEach(() => {
  events.length = 0;
  setMode('monitor');
});
afterAll(() => {
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler as any);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) };
}

async function readBody(req: IncomingMessage): Promise<string> {
  let s = '';
  for await (const chunk of req) s += chunk;
  return s;
}

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
};

describe('raw http', () => {
  it('records query, cookies and the input headers in the request context only', async () => {
    const s = await serve(raspHttp((_req, res) => json(res, 200, keys())));
    const res = await fetch(`${s.url}/items/42?q=${encodeURIComponent('hello world')}`, { headers: { cookie: 'sid=abc123; theme=dark', 'user-agent': 'test-agent/1', 'x-other': 'skip' } });
    const got = await res.json();
    await s.close();
    expect(got['query.q']).toBe('hello world');
    expect(got['cookie.sid']).toBe('abc123');
    expect(got['header.user-agent']).toBe('test-agent/1');
    expect(got['header.x-other']).toBeUndefined();
    expect(currentContext()).toBeUndefined();
  });

  it('a virtual patch in block mode answers 403 with the contract body; monitor lets it through', async () => {
    setMode('block');
    const s = await serve(raspHttp((_req, res) => json(res, 200, { ok: true })));
    const blocked = await fetch(`${s.url}/`, { headers: exampleHeaders });
    expect(blocked.status).toBe(403);
    expect(blocked.headers.get('content-type')).toBe('application/json');
    const body = await blocked.json();
    expect(body).toEqual({ error: BLOCK_MESSAGE, attack: 'virtual_patch', rule: exampleRule.id, event: events[0].attrs['shield360.rasp.event_id'] });
    expect(events[0].attrs).toMatchObject({ 'shield360.rasp.decision': 'blocked', 'shield360.rasp.framework': 'http', 'shield360.rasp.sink': 'server.request' });
    setMode('monitor');
    const passed = await fetch(`${s.url}/`, { headers: exampleHeaders });
    expect(passed.status).toBe(200);
    expect(events[1].attrs['shield360.rasp.decision']).toBe('monitored');
    await s.close();
  });

  it('recordRequestBody adds the body and runs the body rules (async handler)', async () => {
    setMode('block');
    const s = await serve(
      raspHttp(async (req, res) => {
        const text = await readBody(req);
        recordRequestBody(text, req.headers['content-type']);
        json(res, 200, keys());
      }),
    );
    const ok = await fetch(`${s.url}/form`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'name=Ana&city=Lisbon' });
    expect((await ok.json())['body.city']).toBe('Lisbon');
    const blocked = await fetch(`${s.url}/action`, { method: bodyShape.method, headers: bodyShape.headers as Record<string, string>, body: bodyShape.body });
    expect(blocked.status).toBe(403);
    expect((await blocked.json()).rule).toBe(bodyRule.id);
    await s.close();
  });

  it('inactive: the handler runs with no context', async () => {
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    const s = await serve(raspHttp((_req, res) => json(res, 200, { ctx: keys() })));
    expect(await (await fetch(`${s.url}/?q=x`, { headers: exampleHeaders })).json()).toEqual({ ctx: null });
    await s.close();
  });
});

describe('Express', () => {
  type Req = IncomingMessage & { originalUrl?: string; query?: unknown; body?: unknown; params?: unknown };
  type Route = (req: Req, res: ServerResponse) => void;

  // Express's order: query parser, then app.use() middleware, then routes, then error handlers.
  function app(route: Route, opts: { parseBodyBefore: boolean }) {
    const mw = raspExpress();
    const onError = raspExpressErrorHandler();
    return async (req: Req, res: ServerResponse) => {
      req.originalUrl = req.url;
      req.query = Object.fromEntries(new URL(req.url || '/', 'http://x').searchParams);
      req.params = {};
      const raw = await readBody(req);
      if (opts.parseBodyBefore && raw) req.body = JSON.parse(raw);
      mw(req, res, (err?: unknown) => {
        if (err) return json(res, 500, {});
        if (!opts.parseBodyBefore && raw) req.body = JSON.parse(raw);
        try {
          route(req, res);
        } catch (e) {
          onError(e, req, res, () => json(res, 500, {}));
        }
      });
    };
  }

  it('records the parsed query and body leaves (body parser first)', async () => {
    const s = await serve(app((_req, res) => json(res, 200, keys()), { parseBodyBefore: true }));
    const got = await (await fetch(`${s.url}/orders?sort=name`, { method: 'POST', body: JSON.stringify({ user: { name: "O'Brien" }, tags: ['a1', 'b2'] }) })).json();
    await s.close();
    expect(got).toMatchObject({ 'query.sort': 'name', 'body.user.name': "O'Brien", 'body.tags.0': 'a1' });
  });

  it('captures a body parsed after the middleware when a sink first reads the inputs', async () => {
    const s = await serve(app((_req, res) => json(res, 200, keys()), { parseBodyBefore: false }));
    const got = await (await fetch(`${s.url}/late`, { method: 'POST', body: JSON.stringify({ note: 'later' }) })).json();
    await s.close();
    expect(got['body.note']).toBe('later');
  });

  it('maps a block error from a route to 403 through the error handler', async () => {
    const s = await serve(
      app(
        () => {
          throw new RaspBlockedError('sql_injection', 'sqli.userinput', 'e'.repeat(32));
        },
        { parseBodyBefore: true },
      ),
    );
    const res = await fetch(`${s.url}/x`);
    await s.close();
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: BLOCK_MESSAGE, attack: 'sql_injection', rule: 'sqli.userinput', event: 'e'.repeat(32) });
  });

  it('blocks a matching virtual patch before the route', async () => {
    setMode('block');
    let ran = false;
    const s = await serve(app(() => (ran = true), { parseBodyBefore: true }));
    const res = await fetch(`${s.url}/x`, { headers: exampleHeaders });
    await s.close();
    expect(res.status).toBe(403);
    expect(ran).toBe(false);
  });
});

describe('Fastify', () => {
  type Hook = (request: any, reply: any, done: (err?: unknown) => void) => void;

  function fastify() {
    const hooks: Record<string, Hook> = {};
    raspFastify({ addHook: (name: string, fn: Hook) => (hooks[name] = fn) }, {}, () => undefined);
    return hooks;
  }
  function reply() {
    const r: any = { status: 0, headers: {} as Record<string, string>, sent: undefined as unknown };
    r.code = (n: number) => ((r.status = n), r);
    r.header = (k: string, v: string) => ((r.headers[k] = v), r);
    r.send = (b: unknown) => (r.sent = b);
    return r;
  }

  it('is global (skip-override), captures in onRequest and preHandler, and the handler sees the context', async () => {
    expect((raspFastify as any)[Symbol.for('skip-override')]).toBe(true);
    const hooks = fastify();
    const request: any = { method: 'POST', url: '/users/7?expand=roles', headers: { 'user-agent': 'ua/1' }, query: { expand: 'roles' }, params: { id: '7' }, routeOptions: { url: '/users/:id' } };
    const got = await new Promise<any>((resolve) => {
      hooks.onRequest(request, reply(), () => {
        // Fastify parses the body between onRequest and preHandler.
        setImmediate(() => {
          request.body = { profile: { bio: 'hello there' } };
          hooks.preHandler(request, reply(), () => resolve({ keys: keys(), route: currentContext()?.route }));
        });
      });
    });
    expect(got.keys).toMatchObject({ 'query.expand': 'roles', 'params.id': '7', 'header.user-agent': 'ua/1', 'body.profile.bio': 'hello there' });
    expect(got.route).toBe('/users/:id');
  });

  it('answers 403 from onRequest for a blocking virtual patch, and from preHandler for a body rule', () => {
    setMode('block');
    const hooks = fastify();
    const r1 = reply();
    const next1 = jest.fn();
    hooks.onRequest({ method: 'GET', url: '/', headers: exampleHeaders }, r1, next1);
    expect(next1).not.toHaveBeenCalled();
    expect(r1.status).toBe(403);
    expect(JSON.parse(r1.sent).rule).toBe(exampleRule.id);

    // A request with a body carries its length (without one, Fastify parses no body).
    const request: any = { method: bodyShape.method, url: '/a', headers: { ...bodyShape.headers, 'content-length': String(Buffer.byteLength(bodyShape.body)) } };
    hooks.onRequest(request, reply(), () => undefined);
    request.body = bodyShape.body;
    const r2 = reply();
    const next2 = jest.fn();
    hooks.preHandler(request, r2, next2);
    expect(next2).not.toHaveBeenCalled();
    expect(r2.status).toBe(403);
  });

  it('the block error carries statusCode 403 for the default error handler', () => {
    expect(new RaspBlockedError('xxe', 'xxe.file', 'e').statusCode).toBe(403);
  });
});

describe('Koa', () => {
  const kctx = (over: any = {}) => ({ method: 'GET', url: '/', headers: {}, query: {}, request: {}, set: jest.fn(), ...over });

  it('records inputs and runs downstream in the context, whatever the body parser order', async () => {
    const mw = raspKoa();
    const k = kctx({ method: 'POST', url: '/c?x=1', originalUrl: '/c?x=1', query: { x: '1' }, headers: { cookie: 'sid=s1' } });
    let got: any;
    await mw(k, async () => {
      await new Promise((r) => setImmediate(r));
      k.request.body = { comment: 'first!' };
      got = keys();
    });
    expect(got).toMatchObject({ 'query.x': '1', 'cookie.sid': 's1', 'body.comment': 'first!' });
  });

  it('maps a virtual patch block and a downstream block error to 403', async () => {
    setMode('block');
    const mw = raspKoa();
    const a = kctx({ headers: exampleHeaders });
    const next = jest.fn(async () => undefined);
    await mw(a, next);
    expect(next).not.toHaveBeenCalled();
    expect(a.status).toBe(403);
    expect((a.body as any).rule).toBe(exampleRule.id);

    const b = kctx();
    await mw(b, async () => {
      throw new RaspBlockedError('ssrf', 'ssrf.internal', 'f'.repeat(32));
    });
    expect(b.status).toBe(403);
    await expect(
      mw(kctx(), async () => {
        throw new Error('app error');
      }),
    ).rejects.toThrow('app error');
  });
});

describe('Next.js route handlers', () => {
  it('records query, params and the JSON body; the handler can still read the body', async () => {
    const handler = withRasp(async (request: Request, context: { params: Promise<{ id: string }> }) => {
      const body = await request.json();
      return Response.json({ body, keys: keys(), id: (await context.params).id });
    });
    const res = await handler(
      new Request('http://localhost/api/orders/7?view=full', { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'next-test' }, body: JSON.stringify({ item: { sku: 'SKU-1' } }) }),
      { params: Promise.resolve({ id: '7' }) },
    );
    const got = await res.json();
    expect(got.body).toEqual({ item: { sku: 'SKU-1' } });
    expect(got.keys).toMatchObject({ 'query.view': 'full', 'params.id': '7', 'body.item.sku': 'SKU-1', 'header.user-agent': 'next-test' });
  });

  it('blocks the documented request shape of a body rule with a 403 Response', async () => {
    setMode('block');
    const handler = withRasp(async () => new Response('ran'));
    const res = await handler(new Request('http://localhost/checkout', { method: bodyShape.method, headers: bodyShape.headers as Record<string, string>, body: bodyShape.body }), {});
    expect(res.status).toBe(403);
    expect((await res.json()).rule).toBe(bodyRule.id);
  });

  it('maps a block error thrown by the handler; other errors propagate', async () => {
    const blocked = withRasp(async () => {
      throw new RaspBlockedError('code_injection', 'code.eval', 'a'.repeat(32));
    });
    expect((await blocked(new Request('http://localhost/x'), {})).status).toBe(403);
    const broken = withRasp(async () => {
      throw new Error('app error');
    });
    await expect(broken(new Request('http://localhost/x'), {})).rejects.toThrow('app error');
  });
});

describe('model output as input (instrumentation hook point)', () => {
  const inRequest = <T>(fn: () => T) => storage.run(captureRequest({ framework: 'http', method: 'POST', url: '/chat', headers: {} }), fn);

  it('records completion fragments and tool-call argument leaves (OpenAI shape)', () => {
    const got = inRequest(() => {
      recordModelResponse({ choices: [{ message: { content: 'first line\nsecond line', tool_calls: [{ function: { name: 'run_query', arguments: JSON.stringify({ sql: 'select 1' }) } }] } }] });
      return inputsOf(currentContext()!);
    });
    expect(got.filter((i) => i.source === 'model_output').map((i) => [i.key, i.value])).toEqual([
      ['model.completion', 'first line'],
      ['model.completion', 'second line'],
      ['model.tool.run_query.sql', 'select 1'],
    ]);
  });

  it('records Anthropic text and tool_use input', () => {
    const got = inRequest(() => {
      recordModelResponse({ content: [{ type: 'text', text: 'hello' }, { type: 'tool_use', name: 'fetch_page', input: { url: 'https://example.com' } }] });
      return inputsOf(currentContext()!).map((i) => i.key);
    });
    expect(got).toEqual(['model.completion', 'model.tool.fetch_page.url']);
  });

  it('records nothing when RASP is off or modelOutput is false', () => {
    configureEngine({ enabled: true, applicationName: 'a', modelOutput: false, env: {} });
    expect(inRequest(() => (recordModelResponse({ content: [{ type: 'text', text: 'x' }] }), currentContext()!.inputs.length))).toBe(0);
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    expect(inRequest(() => (recordModelResponse({ content: [{ type: 'text', text: 'x' }] }), currentContext()!.inputs.length))).toBe(0);
  });
});

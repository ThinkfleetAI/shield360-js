/**
 * Deception (sdk/rasp/README.md "Deception"): the shared conformance cases
 * (testdata/deception.json), the suspicious-address table, the decision, and
 * every adapter answering a decoy with its not-found without calling the
 * handler.
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import { installAutoHttpCapture, uninstallAutoHttpCapture } from '../auto-http';
import { checkDeception, matchDecoy, parseDeception, setSuspiciousTable, SuspiciousTable, suspiciousTable } from '../deception';
import { configureEngine, setEventSink, setRemoteConfig, setRuntimeDisabled } from '../engine';
import { toRemote } from '../index';
import { raspExpress, raspFastify, raspHttp, raspKoa, sendExpressNotFound, withRasp } from '../middleware';
import type { RaspClaims } from '../config-client';
import type { RaspMode } from '../types';
import { loadJson } from './corpus';

const corpus = loadJson('testdata/deception.json');

const events: any[] = [];
let now = 1_000_000;

function claims(deception: unknown, over: Partial<RaspClaims> = {}): RaspClaims {
  return { v: 1, app: 'orders-api', exp: 4_000_000_000, version: 'v-dec', ...over, deception } as RaspClaims;
}

/** RASP on with a signed config carrying `deception`, a fresh table on a fake clock. */
function setup(deception: unknown, opts: { attacks?: Record<string, RaspMode>; local?: Record<string, RaspMode>; monitorOnly?: boolean; killSwitch?: boolean; cap?: number } = {}) {
  configureEngine({ enabled: true, applicationName: 'orders-api', attacks: opts.local as any, monitorOnly: opts.monitorOnly, env: {} });
  setEventSink({ add: (e) => events.push(e) });
  setRemoteConfig(toRemote(claims(deception, { attacks: opts.attacks as any, killSwitch: opts.killSwitch })));
  setSuspiciousTable(new SuspiciousTable(opts.cap ?? 10_000, () => now));
}

const attrs = () => events.map((e) => e.attrs);
const BLOCK = { paths: ['/wp-admin', '/.env'], action: 'block', ttlSeconds: 60 };
const MONITOR = { ...BLOCK, action: 'monitor' };
const req = (url: string, ip: string | null = '203.0.113.7', method = 'GET') => ({ framework: 'test', method, url, ip: ip ?? undefined });

beforeEach(() => {
  events.length = 0;
  now = 1_000_000;
});
afterAll(() => {
  setEventSink(undefined);
  setRemoteConfig(undefined);
  setRuntimeDisabled(false);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
  setSuspiciousTable(new SuspiciousTable());
});

describe('conformance (testdata/deception.json)', () => {
  it.each(corpus.config as any[])('config: $name', (c: any) => {
    // Through the claims reader the SDK uses (index.ts toRemote), key missing = absent.
    const cl = claims(undefined);
    if ('deception' in c) cl.deception = c.deception;
    else delete cl.deception;
    expect(toRemote(cl).deception).toEqual(c.expect);
  });

  const decoysOf = (c: any) => parseDeception({ paths: c.decoys ?? corpus.decoys })!.paths;

  it.each(corpus.match as any[])('match: $target', (c: any) => {
    expect(matchDecoy(c.target, decoysOf(c))).toBe(c.expect);
  });

  it('every match case through the middleware path (signed config -> checkDeception)', () => {
    for (const c of corpus.match) {
      setup({ paths: c.decoys ?? corpus.decoys });
      events.length = 0;
      const out = checkDeception(req(c.target, null));
      expect([c.target, Boolean(out.notFound)]).toEqual([c.target, c.expect !== null]);
      if (c.expect !== null) expect(attrs()[0]['shield360.rasp.route']).toBe(c.expect.replace(/[^\x21-\x7e]/g, '_'));
    }
  });

  it('a raw UTF-8 target as Node reads it (latin1) matches a non-ASCII decoy', () => {
    const raw = Buffer.from('/café/menu', 'utf8').toString('latin1');
    expect(matchDecoy(raw, ['/café'])).toBe('/café');
  });
});

describe('suspicious-address table', () => {
  it('holds at most its cap, evicts the mark closest to expiring, and a new mark refreshes the order', () => {
    const t = new SuspiciousTable(3, () => now);
    for (const ip of ['a', 'b', 'c']) t.mark(ip, 60);
    t.mark('a', 60); // a is now the newest
    t.mark('d', 60);
    t.mark('e', 60);
    expect(t.size).toBe(3);
    expect(t.keys()).toEqual(['a', 'd', 'e']);
  });

  it('drops expired marks from the front before evicting a live one', () => {
    const t = new SuspiciousTable(3, () => now);
    t.mark('old', 1);
    t.mark('b', 600);
    t.mark('c', 600);
    now += 2000;
    t.mark('d', 600);
    expect(t.keys()).toEqual(['b', 'c', 'd']);
  });

  it('keeps marks in expiry order: after a TTL change an insert at the cap drops the expired mark, not a live one', () => {
    const t = new SuspiciousTable(3, () => now);
    t.mark('a', 3600);
    t.mark('b', 3600);
    t.mark('c', 1);
    now += 2000;
    t.mark('d', 3600);
    expect(t.size).toBe(3);
    expect(['a', 'b', 'c', 'd'].map((ip) => t.isMarked(ip))).toEqual([true, true, false, true]);
  });

  it('at the cap with nothing expired, evicts the mark closest to expiring', () => {
    const t = new SuspiciousTable(2, () => now);
    t.mark('a', 3600);
    t.mark('b', 10);
    t.mark('c', 3600);
    expect(['a', 'b', 'c'].map((ip) => t.isMarked(ip))).toEqual([true, false, true]);
  });

  it('expires marks on lookup; a lookup never extends a mark', () => {
    const t = new SuspiciousTable(10, () => now);
    t.mark('a', 10);
    now += 9000;
    expect(t.isMarked('a')).toBe(true);
    now += 1000;
    expect(t.isMarked('a')).toBe(false);
    expect(t.size).toBe(0);
    expect(t.isMarked('missing')).toBe(false);
  });
});

describe('decision', () => {
  it('a hit answers not-found, marks the address and reports deception.hit; a later request is deception.suspicious', () => {
    setup(MONITOR);
    expect(checkDeception(req('/wp-admin/setup.php?x=1', '203.0.113.7', 'POST'))).toEqual({ notFound: true });
    expect(suspiciousTable().isMarked('203.0.113.7')).toBe(true);
    expect(attrs()[0]).toMatchObject({
      'shield360.rasp.attack': 'deception',
      'shield360.rasp.rule': 'deception.hit',
      'shield360.rasp.sink': 'http.deception',
      'shield360.rasp.decision': 'monitored',
      'shield360.rasp.mode': 'monitor',
      'shield360.rasp.route': '/wp-admin',
      'shield360.rasp.method': 'POST',
      'shield360.rasp.framework': 'test',
      'shield360.rasp.config_version': 'v-dec',
    });
    expect(attrs()[0]['shield360.rasp.input_key']).toBeUndefined();
    expect(attrs()[0]['shield360.rasp.snippet']).toBeUndefined();

    expect(checkDeception(req('/orders/12345?token=abc'))).toEqual({});
    expect(attrs()[1]).toMatchObject({ 'shield360.rasp.rule': 'deception.suspicious', 'shield360.rasp.route': '/orders/:id', 'shield360.rasp.decision': 'monitored' });
    // Another address is not suspicious.
    expect(checkDeception(req('/orders', '198.51.100.1'))).toEqual({});
    expect(events).toHaveLength(2);
  });

  it('block: a suspicious request gets the block error with attack deception', () => {
    setup(BLOCK);
    checkDeception(req('/.env'));
    expect(attrs()[0]).toMatchObject({ 'shield360.rasp.decision': 'blocked', 'shield360.rasp.mode': 'block' });
    const out = checkDeception(req('/'));
    expect(out.blocked).toMatchObject({ attack: 'deception', rule: 'deception.suspicious', eventId: attrs()[1]['shield360.rasp.event_id'] });
  });

  it('the mark expires after ttlSeconds', () => {
    setup(BLOCK);
    checkDeception(req('/wp-admin'));
    now += 59_000;
    expect(checkDeception(req('/')).blocked).toBeDefined();
    now += 1000;
    expect(checkDeception(req('/'))).toEqual({});
  });

  it('hitting a decoy again restarts the time; a config change keeps marks', () => {
    setup(BLOCK);
    checkDeception(req('/wp-admin'));
    now += 50_000;
    checkDeception(req('/wp-admin'));
    setRemoteConfig(toRemote(claims({ ...BLOCK, ttlSeconds: 5 })));
    now += 50_000;
    expect(checkDeception(req('/')).blocked).toBeDefined();
  });

  it('attacks.deception off (signed or local) turns deception off entirely', () => {
    setup(BLOCK, { attacks: { deception: 'off' } });
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    setup(BLOCK, { local: { deception: 'off' }, attacks: { deception: 'block' } });
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    expect(events).toHaveLength(0);
    expect(suspiciousTable().size).toBe(0);
  });

  it('attacks.deception monitor caps a block action; block or unset leaves the action to decide', () => {
    setup(BLOCK, { attacks: { deception: 'monitor' } });
    checkDeception(req('/wp-admin'));
    expect(checkDeception(req('/'))).toEqual({});
    expect(attrs().map((a) => a['shield360.rasp.decision'])).toEqual(['monitored', 'monitored']);

    setup(MONITOR, { attacks: { deception: 'block' } });
    checkDeception(req('/wp-admin'));
    expect(checkDeception(req('/'))).toEqual({});

    // The default mode never applies to deception: a signed mode of monitor does not cap it.
    events.length = 0;
    setup(BLOCK);
    setRemoteConfig(toRemote(claims(BLOCK, { mode: 'monitor' })));
    checkDeception(req('/wp-admin'));
    expect(checkDeception(req('/')).blocked).toBeDefined();
  });

  it('monitor only (no pinned key) lowers block to monitor', () => {
    setup(BLOCK, { monitorOnly: true });
    expect(checkDeception(req('/wp-admin'))).toEqual({ notFound: true });
    expect(checkDeception(req('/'))).toEqual({});
    expect(attrs().map((a) => a['shield360.rasp.decision'])).toEqual(['monitored', 'monitored']);
  });

  it('kill switch, runtime disable or no signed config: requests pass untouched', () => {
    setup(BLOCK, { killSwitch: true });
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    setup(BLOCK);
    setRuntimeDisabled(true);
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    setRuntimeDisabled(false);
    setRemoteConfig(undefined);
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    expect(events).toHaveLength(0);
  });

  it('no client address: the decoy still gets not-found, nothing is marked', () => {
    setup(BLOCK);
    expect(checkDeception(req('/wp-admin', null))).toEqual({ notFound: true });
    expect(suspiciousTable().size).toBe(0);
  });

  it('a flood of decoy hits from new addresses never grows the table past its cap', () => {
    setup(MONITOR, { cap: 5 });
    for (let i = 0; i < 12; i++) checkDeception(req('/wp-admin', `10.0.0.${i}`));
    expect(suspiciousTable().size).toBe(5);
    expect(suspiciousTable().keys()).toEqual(['10.0.0.7', '10.0.0.8', '10.0.0.9', '10.0.0.10', '10.0.0.11']);
  });

  it('fails open: a throwing clock lets the request through as if deception were off', () => {
    setup(BLOCK);
    setSuspiciousTable(
      new SuspiciousTable(10, () => {
        throw new Error('clock');
      }),
    );
    expect(checkDeception(req('/wp-admin'))).toEqual({});
    // A failing event sink never changes the answer.
    setup(BLOCK);
    setEventSink({
      add: () => {
        throw new Error('sink');
      },
    });
    expect(checkDeception(req('/wp-admin'))).toEqual({ notFound: true });
  });
});

// ---- adapters ----------------------------------------------------------------

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler as any);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

type Got = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
function get(url: string, method = 'GET', headers: Record<string, string> = {}): Promise<Got> {
  return new Promise((ok, fail) => {
    httpRequest(url, { method, headers, timeout: 3000 }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => ok({ status: res.statusCode || 0, headers: res.headers, body }));
    })
      .on('error', fail)
      .end();
  });
}

/**
 * What Express 4 (finalhandler 1.3) and 5 (finalhandler 2.1) send for a path no
 * route matches, captured from a real app: `app.get('/x', ...)`, then
 * `GET /wp-admin/a%20b?x=1`.
 */
const EXPRESS_404_BODY =
  '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot GET /wp-admin/a%20b</pre>\n</body>\n</html>\n';

describe('Express', () => {
  // A minimal Express: query, app.use() middleware, one route at /orders, finalhandler-style 404 for anything else.
  function app(called: { n: number }, mw = raspExpress(), mount = '') {
    return (req: IncomingMessage & { originalUrl?: string; ip?: string }, res: ServerResponse) => {
      req.originalUrl = req.url;
      // A router mounted at `mount` sees req.url without the mount.
      if (mount && req.url?.startsWith(mount)) req.url = req.url.slice(mount.length) || '/';
      mw(req as any, res, () => {
        if ((req.url || '').split('?')[0] === '/orders') {
          called.n++;
          res.end('orders');
        } else sendExpressNotFound(req, res);
      });
    };
  }

  it("a decoy never reaches the handler and gets Express's own 404, the same as an unknown path", async () => {
    setup(MONITOR);
    const called = { n: 0 };
    const s = await serve(app(called));
    const hit = await get(`${s.url}/wp-admin/a%20b?x=1`);
    setRemoteConfig(undefined);
    const unknown = await get(`${s.url}/wp-admin/a%20b?x=1`);
    const head = await get(`${s.url}/orders`, 'HEAD');
    await s.close();
    expect(called.n).toBe(1); // only the HEAD /orders request
    expect(head.status).toBe(200);
    expect(hit.status).toBe(404);
    expect(hit.body).toBe(EXPRESS_404_BODY);
    expect(unknown.body).toBe(EXPRESS_404_BODY);
    for (const h of ['content-type', 'content-length', 'content-security-policy', 'x-content-type-options']) expect(hit.headers[h]).toBe(unknown.headers[h]);
    expect(attrs()[0]).toMatchObject({ 'shield360.rasp.framework': 'express', 'shield360.rasp.rule': 'deception.hit' });
  });

  it('matches the full target under a router mount (originalUrl), and blocks a suspicious client with the 403', async () => {
    setup(BLOCK);
    const called = { n: 0 };
    const s = await serve(app(called, raspExpress(), '/wp-admin'));
    const hit = await get(`${s.url}/wp-admin/orders`);
    const later = await get(`${s.url}/orders`);
    await s.close();
    expect(hit.status).toBe(404);
    expect(later.status).toBe(403);
    expect(JSON.parse(later.body)).toMatchObject({ attack: 'deception', rule: 'deception.suspicious' });
    expect(called.n).toBe(0);
  });

  it('monitor: a suspicious client reaches the handler and is reported', async () => {
    setup(MONITOR);
    const called = { n: 0 };
    const s = await serve(app(called));
    await get(`${s.url}/.env`);
    const later = await get(`${s.url}/orders`);
    await s.close();
    expect(later.body).toBe('orders');
    expect(called.n).toBe(1);
    expect(attrs()[1]).toMatchObject({ 'shield360.rasp.rule': 'deception.suspicious', 'shield360.rasp.decision': 'monitored' });
  });

  it('a notFound option answers decoys; if it throws, the default 404 is sent', async () => {
    setup(MONITOR);
    const called = { n: 0 };
    const own = await serve(app(called, raspExpress({ notFound: (_q, res) => ((res.statusCode = 404), res.end('nothing here')) })));
    const a = await get(`${own.url}/wp-admin`);
    await own.close();
    const broken = await serve(
      app(
        called,
        raspExpress({
          notFound: () => {
            throw new Error('page');
          },
        }),
      ),
    );
    const b = await get(`${broken.url}/wp-admin`);
    await broken.close();
    expect([a.status, a.body]).toEqual([404, 'nothing here']);
    expect(b.status).toBe(404);
    expect(b.body).toContain('Cannot GET /wp-admin');
    expect(called.n).toBe(0);
  });

  it('fails open: a throwing table lets the request reach the handler', async () => {
    setup(BLOCK);
    setSuspiciousTable({
      mark: () => {
        throw new Error('table');
      },
      isMarked: () => {
        throw new Error('table');
      },
    } as unknown as SuspiciousTable);
    const called = { n: 0 };
    const s = await serve(app(called));
    const r = await get(`${s.url}/orders`);
    await s.close();
    expect(r.body).toBe('orders');
  });
});

describe('Fastify', () => {
  type Hook = (request: any, reply: any, done: (e?: unknown) => void) => void;
  function hooks() {
    const h: Record<string, Hook> = {};
    raspFastify({ addHook: (name: string, fn: Hook) => (h[name] = fn) }, {}, () => undefined);
    return h;
  }
  const reply = () => {
    const r: any = { status: 0, headers: {}, sent: undefined, notFound: 0 };
    r.code = (n: number) => ((r.status = n), r);
    r.header = (k: string, v: string) => ((r.headers[k] = v), r);
    r.send = (b: unknown) => (r.sent = b);
    r.callNotFound = () => r.notFound++;
    return r;
  };

  it('a decoy on a real route calls reply.callNotFound(); the route handler never runs', () => {
    setup(MONITOR);
    const r = reply();
    const next = jest.fn();
    hooks().onRequest({ method: 'GET', url: '/wp-admin/login', headers: {}, ip: '203.0.113.7' }, r, next);
    expect(r.notFound).toBe(1);
    expect(next).not.toHaveBeenCalled();
    expect(attrs()[0]).toMatchObject({ 'shield360.rasp.framework': 'fastify', 'shield360.rasp.route': '/wp-admin' });
    expect(suspiciousTable().isMarked('203.0.113.7')).toBe(true);
  });

  it("a decoy no route matches goes on to Fastify's own not-found handler", () => {
    setup(MONITOR);
    const r = reply();
    const next = jest.fn();
    hooks().onRequest({ method: 'GET', url: '/.env', headers: {}, ip: '203.0.113.7', is404: true }, r, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(r.notFound).toBe(0);
    expect(r.status).toBe(0);
  });

  it("without callNotFound it sends Fastify's default 404 body; a suspicious client in block gets 403", () => {
    setup(BLOCK);
    const r = reply();
    delete r.callNotFound;
    hooks().onRequest({ method: 'GET', url: '/wp-admin', headers: {}, ip: '203.0.113.7' }, r, jest.fn());
    expect([r.status, r.sent]).toEqual([404, { message: 'Route GET:/wp-admin not found', error: 'Not Found', statusCode: 404 }]);
    const r2 = reply();
    const next = jest.fn();
    hooks().onRequest({ method: 'GET', url: '/orders', headers: {}, ip: '203.0.113.7' }, r2, next);
    expect(next).not.toHaveBeenCalled();
    expect(r2.status).toBe(403);
    expect(JSON.parse(r2.sent).rule).toBe('deception.suspicious');
  });
});

describe('Koa', () => {
  it('a decoy gets status 404 with no body (Koa answers "Not Found"), and downstream never runs', async () => {
    setup(BLOCK);
    const next = jest.fn(async () => undefined);
    const k: any = { method: 'GET', url: '/wp-admin', originalUrl: '/wp-admin', headers: {}, request: {}, ip: '203.0.113.7', set: jest.fn() };
    await raspKoa()(k, next);
    expect(next).not.toHaveBeenCalled();
    expect(k.status).toBe(404);
    expect(k.body).toBeUndefined();
    const later: any = { method: 'GET', url: '/', headers: {}, request: {}, ip: '203.0.113.7', set: jest.fn() };
    await raspKoa()(later, next);
    expect(later.status).toBe(403);
    expect(later.body.rule).toBe('deception.suspicious');
    expect(next).not.toHaveBeenCalled();
  });
});

describe('raw http', () => {
  it('a decoy gets a plain 404 Not Found and the handler never runs; the client is marked by its socket address', async () => {
    setup(BLOCK);
    let called = 0;
    const s = await serve(raspHttp((_req, res) => (called++, res.end('ok'))));
    const hit = await get(`${s.url}/wp-admin`);
    const later = await get(`${s.url}/`);
    await s.close();
    expect([hit.status, hit.headers['content-type'], hit.body]).toEqual([404, 'text/plain; charset=utf-8', 'Not Found']);
    expect(later.status).toBe(403);
    expect(called).toBe(0);
    expect(suspiciousTable().isMarked('127.0.0.1')).toBe(true);
  });

  it('kill switch: the decoy reaches the handler untouched', async () => {
    setup(BLOCK, { killSwitch: true });
    const s = await serve(raspHttp((_req, res) => res.end('ok')));
    const r = await get(`${s.url}/wp-admin`);
    await s.close();
    expect(r.body).toBe('ok');
    expect(events).toHaveLength(0);
  });
});

describe('Next.js route handlers', () => {
  it('a decoy gets an empty 404 (what notFound() gives) and the handler never runs; nothing is marked', async () => {
    setup(BLOCK);
    const handler = jest.fn(async () => new Response('ran'));
    const res = await withRasp(handler)(new Request('http://localhost/wp-admin/x?y=1'), {});
    expect(res.status).toBe(404);
    expect(await res.text()).toBe('');
    expect(handler).not.toHaveBeenCalled();
    expect(suspiciousTable().size).toBe(0);
    expect(attrs()[0]).toMatchObject({ 'shield360.rasp.framework': 'nextjs', 'shield360.rasp.route': '/wp-admin' });
  });
});

describe('zero-code capture', () => {
  beforeAll(() => installAutoHttpCapture());
  afterAll(() => uninstallAutoHttpCapture());

  it('answers a decoy with a plain 404 before any listener; middleware on top does not run deception again', async () => {
    setup(MONITOR);
    let called = 0;
    const mw = raspExpress();
    const s = await serve((req, res) => {
      (req as any).originalUrl = req.url;
      mw(req as any, res, () => (called++, res.end('ok')));
    });
    const hit = await get(`${s.url}/.env`);
    const later = await get(`${s.url}/orders`);
    await s.close();
    expect([hit.status, hit.body]).toEqual([404, 'Not Found']);
    expect(later.body).toBe('ok');
    expect(called).toBe(1);
    expect(attrs().map((a) => [a['shield360.rasp.rule'], a['shield360.rasp.framework']])).toEqual([
      ['deception.hit', 'http'],
      ['deception.suspicious', 'http'],
    ]);
  });
});

describe('zero-code capture with a framework app as the listener', () => {
  beforeAll(() => installAutoHttpCapture());
  afterAll(() => uninstallAutoHttpCapture());

  /** An Express-shaped app with `trust proxy` (req.ip from X-Forwarded-For), one route, finalhandler's 404 otherwise. */
  function expressApp(called: { n: number }) {
    const mw = raspExpress();
    const app: any = (req: any, res: ServerResponse) => app.handle(req, res);
    app.settings = { 'trust proxy': true };
    app.set = () => app;
    app.use = () => app;
    app.handle = (req: any, res: ServerResponse) => {
      req.originalUrl = req.url;
      const xff = req.headers['x-forwarded-for'];
      req.ip = typeof xff === 'string' ? xff.split(',')[0].trim() : req.socket.remoteAddress;
      mw(req, res, () => {
        if ((req.url || '').split('?')[0] === '/orders') {
          called.n++;
          res.end('orders');
        } else sendExpressNotFound(req, res);
      });
    };
    return app;
  }

  /** Koa's callback: a function named handleRequest; status 404 with no body answers "Not Found". */
  function koaApp(called: { n: number }) {
    const mw = raspKoa();
    const handleRequest = (req: IncomingMessage, res: ServerResponse) => {
      const k: any = { method: req.method, url: req.url, originalUrl: req.url, headers: req.headers, request: {}, ip: req.socket.remoteAddress, status: 404, set: () => undefined };
      void mw(k, async () => {
        if (k.url === '/orders') {
          called.n++;
          k.status = 200;
          k.body = 'orders';
        }
      }).then(() => {
        const body = k.body === undefined ? 'Not Found' : typeof k.body === 'string' ? k.body : JSON.stringify(k.body);
        res.statusCode = k.status;
        res.setHeader('Content-Type', k.body === undefined || typeof k.body === 'string' ? 'text/plain; charset=utf-8' : 'application/json');
        res.end(body);
      });
    };
    return handleRequest;
  }

  it('Express behind a shared proxy: a decoy marks the forwarded client, not the proxy', async () => {
    setup(BLOCK);
    const called = { n: 0 };
    const s = await serve(expressApp(called));
    const hit = await get(`${s.url}/wp-admin`, 'GET', { 'x-forwarded-for': '1.1.1.1' });
    const other = await get(`${s.url}/orders`, 'GET', { 'x-forwarded-for': '2.2.2.2' });
    const again = await get(`${s.url}/orders`, 'GET', { 'x-forwarded-for': '1.1.1.1' });
    await s.close();
    expect(hit.status).toBe(404);
    expect(other.status).toBe(200);
    expect(again.status).toBe(403);
    expect(called.n).toBe(1);
    expect(suspiciousTable().isMarked('127.0.0.1')).toBe(false);
    expect(attrs()[0]['shield360.rasp.framework']).toBe('express');
  });

  it("a decoy gets the framework's ordinary 404 (Express, Koa)", async () => {
    for (const make of [expressApp, koaApp]) {
      setup(MONITOR);
      const called = { n: 0 };
      const s = await serve(make(called) as any);
      const hit = await get(`${s.url}/wp-admin`);
      setRemoteConfig(undefined);
      const unknown = await get(`${s.url}/wp-admin`);
      await s.close();
      expect(called.n).toBe(0);
      expect([hit.status, hit.headers['content-type'], hit.body]).toEqual([unknown.status, unknown.headers['content-type'], unknown.body]);
      expect(hit.body).not.toBe('');
    }
  });

  it('a plain listener still gets deception from the zero-code capture', async () => {
    setup(BLOCK);
    let called = 0;
    const s = await serve((_req, res) => (called++, res.end('ok')));
    const hit = await get(`${s.url}/wp-admin`);
    const later = await get(`${s.url}/`);
    await s.close();
    expect([hit.status, hit.body]).toEqual([404, 'Not Found']);
    expect(later.status).toBe(403);
    expect(called).toBe(0);
  });
});

/**
 * The zero-code request capture (`shield360/register` with RASP on): every
 * `http` server request runs in a RASP context without middleware. A block
 * raised after an `await` in an async handler answers 403 (it must not become
 * an unhandled rejection), and middleware added on top does not run the head
 * virtual patches a second time.
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import { installAutoHttpCapture, uninstallAutoHttpCapture } from '../auto-http';
import { currentContext } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { raspExpress, withRasp } from '../middleware';
import { RaspBlockedError } from '../types';
import { BUILT_IN_RULES } from '../vpatch';
import { requestFor } from './corpus';

const exampleRule = BUILT_IN_RULES.find((r) => r.example)!;
const exampleHeaders = requestFor(exampleRule).headers as Record<string, string>;

const events: any[] = [];

beforeAll(() => {
  configureEngine({ enabled: true, applicationName: 'orders-api', attacks: { virtual_patch: 'monitor' }, env: {} });
  setEventSink({ add: (e) => events.push(e) });
  installAutoHttpCapture();
});
beforeEach(() => {
  events.length = 0;
});
afterAll(() => {
  uninstallAutoHttpCapture();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown, once = false): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer();
  if (once) server.once('request', handler as any);
  else server.on('request', handler as any);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

function get(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((ok, fail) => {
    httpRequest(url, { headers, timeout: 3000 }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => ok({ status: res.statusCode || 0, body }));
    })
      .on('timeout', function (this: { destroy: (e: Error) => void }) {
        this.destroy(new Error('no response'));
      })
      .on('error', fail)
      .end();
  });
}

const vpFindings = () => events.filter((e) => JSON.stringify(e).includes(exampleRule.id));

describe('zero-code http capture', () => {
  it('runs a plain handler inside a request context', async () => {
    let inRequest: boolean | undefined;
    const s = await serve((_req, res) => {
      inRequest = currentContext()?.inRequest;
      res.end('ok');
    });
    try {
      expect(await get(`${s.url}/?q=1`)).toEqual({ status: 200, body: 'ok' });
      expect(inRequest).toBe(true);
    } finally {
      await s.close();
    }
  });

  it('answers 403 when an async handler is blocked after an await, and keeps serving', async () => {
    const onUnhandled = jest.fn();
    process.on('unhandledRejection', onUnhandled);
    const s = await serve(async (req, res) => {
      await new Promise((r) => setTimeout(r, 5));
      if (req.url?.includes('attack')) throw new RaspBlockedError('command_injection', 'cmdi.userinput', 'e'.repeat(32));
      res.end('ok');
    });
    try {
      const blocked = await get(`${s.url}/attack`);
      expect(blocked.status).toBe(403);
      expect(JSON.parse(blocked.body).attack).toBe('command_injection');
      expect(await get(`${s.url}/fine`)).toEqual({ status: 200, body: 'ok' });
      await new Promise((r) => setImmediate(r));
      expect(onUnhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', onUnhandled);
      await s.close();
    }
  });

  it('serves once listeners', async () => {
    const s = await serve((_req, res) => res.end('once'), true);
    try {
      expect(await get(s.url)).toEqual({ status: 200, body: 'once' });
    } finally {
      await s.close();
    }
  });

  it('with raspExpress() on top, a virtual patch is reported once', async () => {
    const mw = raspExpress();
    const s = await serve((req, res) => mw(req as any, res, () => res.end('ok')));
    try {
      await get(s.url, exampleHeaders);
      expect(vpFindings()).toHaveLength(1);
    } finally {
      await s.close();
    }
  });

  it('with withRasp() on top (Next.js route handlers), a virtual patch is reported once', async () => {
    const route = withRasp(async () => new Response('ok'));
    const s = await serve(async (req, res) => {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
      const out = await route(new Request(`http://localhost${req.url}`, { headers }), {} as never);
      res.statusCode = out.status;
      res.end(await out.text());
    });
    try {
      expect((await get(s.url, exampleHeaders)).status).toBe(200);
      expect(vpFindings()).toHaveLength(1);
    } finally {
      await s.close();
    }
  });
});

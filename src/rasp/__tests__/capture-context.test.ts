/**
 * Capture runs inside the request's context (README "Custom rules: when rules
 * run"): a custom finding rule that reads request fields must see the request
 * when a virtual patch or an upload check fires during capture, whichever
 * entry point captured it (raspHttp, raspExpress, raspFastify, raspKoa,
 * withRasp, the zero-code http capture, late body capture).
 */
import { createServer, request as httpRequest, type Server } from 'http';
import type { AddressInfo } from 'net';
import { installAutoHttpCapture, uninstallAutoHttpCapture } from '../auto-http';
import { captureBody, captureLater, captureRequest } from '../capture';
import { storage } from '../context';
import { resetCustomRuleWarnings } from '../custom-rules';
import { configureEngine, setEventSink, setRemoteConfig, type RemoteConfig } from '../engine';
import { raspExpress, raspFastify, raspHttp, raspKoa, withRasp } from '../middleware';
import { RaspBlockedError } from '../types';
import { BUILT_IN_RULES } from '../vpatch';
import { requestFor } from './corpus';

const exampleRule = BUILT_IN_RULES.find((r) => r.example)!;
const shape = requestFor(exampleRule);
const headers = shape.headers as Record<string, string>;
const path = shape.path;

type Event = { name: string; time: string; attrs: Record<string, string> };
let events: Event[] = [];

/** Virtual patches and uploads monitor; a finding rule on the request path blocks. */
function config(): RemoteConfig {
  return {
    version: 'v1',
    exp: Math.floor(Date.now() / 1000) + 3600,
    killSwitch: false,
    snippets: false,
    mode: 'monitor',
    attacks: { custom_rule: 'block' },
    rules: null,
    customRules: [
      { id: 'vp-on-path', expression: `attack.type == "virtual_patch" && request.path == ${JSON.stringify(path)}`, action: 'block', enabled: true },
      { id: 'upload-on-path', expression: 'attack.type == "file_write" && request.path == "/upload"', action: 'block', enabled: true },
    ],
  };
}

beforeEach(() => {
  resetCustomRuleWarnings();
  events = [];
  configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
  setEventSink({ add: (e) => events.push(e) });
  setRemoteConfig(config());
});
afterEach(() => {
  setEventSink(undefined);
  setRemoteConfig(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

const customRule = () => events.filter((e) => e.attrs['shield360.rasp.attack'] === 'custom_rule').map((e) => e.attrs['shield360.rasp.rule']);

function res() {
  const r: any = { statusCode: 0, headersSent: false, writableEnded: false, body: '', setHeader: () => undefined };
  r.end = (b: string) => ((r.body = b), (r.writableEnded = true));
  return r;
}

describe('a finding rule sees the request during capture', () => {
  it('raspHttp', () => {
    const handler = jest.fn();
    const r = res();
    raspHttp(handler)({ method: 'GET', url: path, headers, socket: { remoteAddress: '127.0.0.1' } } as any, r);
    expect(handler).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(403);
    expect(JSON.parse(r.body)).toMatchObject({ attack: 'custom_rule', rule: 'custom.vp-on-path' });
  });

  it('raspExpress', () => {
    const next = jest.fn();
    const r = res();
    raspExpress()({ method: 'GET', url: path, originalUrl: path, headers, query: {}, params: {} } as any, r, next);
    expect(next).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(403);
    expect(customRule()).toEqual(['custom.vp-on-path']);
  });

  it('raspFastify', () => {
    const hooks: Record<string, any> = {};
    raspFastify({ addHook: (name: string, fn: any) => (hooks[name] = fn) } as any, {}, () => undefined);
    const reply: any = { status: 0, code: (n: number) => ((reply.status = n), reply), header: () => reply, send: (b: unknown) => (reply.sent = b) };
    const next = jest.fn();
    hooks.onRequest({ method: 'GET', url: path, headers }, reply, next);
    expect(next).not.toHaveBeenCalled();
    expect(reply.status).toBe(403);
    expect(customRule()).toEqual(['custom.vp-on-path']);
  });

  it('raspKoa', async () => {
    const k: any = { method: 'GET', url: path, originalUrl: path, path, headers, query: {}, request: {}, set: jest.fn() };
    const next = jest.fn(async () => undefined);
    await raspKoa()(k, next);
    expect(next).not.toHaveBeenCalled();
    expect(k.status).toBe(403);
    expect(customRule()).toEqual(['custom.vp-on-path']);
  });

  it('withRasp (Next.js route handlers)', async () => {
    const res = await withRasp(async () => new Response('ran'))(new Request(`http://localhost${path}`, { headers }), {});
    expect(res.status).toBe(403);
    expect((await res.json()).rule).toBe('custom.vp-on-path');
  });

  it('the zero-code http capture', async () => {
    installAutoHttpCapture();
    const server: Server = createServer((_req, r) => r.end('ran'));
    await new Promise<void>((ok) => server.listen(0, '127.0.0.1', () => ok()));
    try {
      const { port } = server.address() as AddressInfo;
      const status = await new Promise<number>((ok, fail) => {
        httpRequest(`http://127.0.0.1:${port}${path}`, { headers }, (r) => {
          r.resume();
          r.on('end', () => ok(r.statusCode || 0));
        })
          .on('error', fail)
          .end();
      });
      expect(status).toBe(403);
      expect(customRule()).toEqual(['custom.vp-on-path']);
    } finally {
      server.closeAllConnections();
      await new Promise((ok) => server.close(ok));
      uninstallAutoHttpCapture();
    }
  });

  it('an upload checked when the body is captured', () => {
    const ctx = captureRequest({ framework: 'test', method: 'POST', url: '/upload', headers: {} });
    expect(() => captureBody(ctx, { body: {}, files: [{ fieldname: 'f', originalname: 'shell.php' }] })).toThrow(RaspBlockedError);
    expect(customRule()).toEqual(['custom.upload-on-path']);
  });

  it('late body capture, from inside another context', () => {
    const ctx = captureRequest({ framework: 'test', method: 'POST', url: '/upload', headers: {} });
    captureLater(ctx, () => ({ body: {}, files: [{ fieldname: 'f', originalname: 'shell.php' }] }));
    const other = captureRequest({ framework: 'test', method: 'GET', url: '/elsewhere', headers: {} });
    expect(() => storage.run(other, () => ctx.late?.())).toThrow(RaspBlockedError);
    expect(customRule()).toEqual(['custom.upload-on-path']);
  });
});

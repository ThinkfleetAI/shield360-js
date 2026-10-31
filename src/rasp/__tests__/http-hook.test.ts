import http = require('http');
import https = require('https');
import dns = require('dns');
import { AddressInfo } from 'net';
import * as detect from '../detect';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { RaspBlockedError } from '../types';
import { installHttpHooks, uninstallHttpHooks } from '../hooks/http';
import { alwaysAllowedHosts } from '../index';

let server: http.Server;
let url: string;
let port: number;
let arrivals: jest.Mock;
const tainted = <T>(value: string, fn: () => T): T => runWithInputs(
  [{ value, key: 'query.q', source: 'request' }], fn, { inRequest: true },
);
function configure(mode: 'monitor' | 'block' = 'block', outboundHosts: string[] = []): void {
  configureEngine({ enabled: true, applicationName: 'a', mode, allow: { outboundHosts }, env: {} });
}
function receive(request: http.ClientRequest): Promise<void> {
  return new Promise((resolve, reject) => {
    request.on('error', reject);
    request.on('response', response => {
      response.resume();
      response.on('end', resolve);
      response.on('error', reject);
    });
  });
}
beforeEach(async () => {
  configure();
  setEventSink({ add: () => undefined });
  arrivals = jest.fn();
  server = http.createServer((_req, res) => { arrivals(); res.end('fixture'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
  url = `http://127.0.0.1:${port}/x`;
});
afterEach(async () => {
  uninstallHttpHooks();
  jest.restoreAllMocks();
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  setEventSink(undefined);
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

for (const [owner, scheme] of [[http, 'http:'], [https, 'https:']] as const) {
  describe(scheme, () => {
    test.each(['request', 'get'] as const)('%s normalizes every call form', api => {
      const original = jest.spyOn(owner, api).mockImplementation((() => ({})) as unknown as typeof owner.request);
      const outbound = jest.spyOn(detect, 'detectOutbound').mockReturnValue(null);
      jest.spyOn(detect, 'detectSsrf').mockReturnValue(null);
      installHttpHooks({ alwaysAllowedHosts: [] });
      const endpoint = `${scheme}//127.0.0.1:${port}/x`;
      const callback = () => undefined;
      const forms: unknown[][] = [
        [endpoint], [new URL(endpoint)], [endpoint, callback],
        [endpoint, {}, callback], [new URL(endpoint), {}, callback],
        [{ protocol: scheme, hostname: '127.0.0.1', port, path: '/x' }, callback],
        [{ host: '127.0.0.1', port, path: '/x' }],
      ];
      for (const values of forms) {
        Reflect.apply(owner[api], owner, values);
        expect(outbound).toHaveBeenLastCalledWith(endpoint, [], []);
      }
      expect(original).toHaveBeenCalledTimes(forms.length);
      expect(outbound).toHaveBeenCalledTimes(forms.length);
    });
  });
}

test('tainted literal blocks synchronously before original or server', () => {
  const original = jest.spyOn(http, 'request');
  installHttpHooks({ alwaysAllowedHosts: [] });
  expect(() => tainted(url, () => http.request(url))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  expect(arrivals).not.toHaveBeenCalled();
});

test('untainted loopback passes and get is checked once', async () => {
  const detector = jest.spyOn(detect, 'detectSsrf');
  installHttpHooks({ alwaysAllowedHosts: [] });
  await receive(http.get(url));
  expect(arrivals).toHaveBeenCalledTimes(1);
  expect(detector).toHaveBeenCalledTimes(1);
});

test('monitor reports and permits the request', async () => {
  configure('monitor');
  const events = jest.fn();
  setEventSink({ add: events });
  installHttpHooks({ alwaysAllowedHosts: [] });
  await receive(tainted(url, () => http.get(url)));
  expect(arrivals).toHaveBeenCalledTimes(1);
  expect(events).toHaveBeenCalledWith(expect.objectContaining({ attrs: expect.objectContaining({
    'shield360.rasp.decision': 'monitored',
  }) }), expect.any(String));
});

test('outbound list applies without taint and alwaysAllowedHosts is honored', async () => {
  configure('block', ['allowed.invalid']);
  installHttpHooks({ alwaysAllowedHosts: [] });
  expect(() => http.get(url)).toThrow(RaspBlockedError);
  uninstallHttpHooks();
  installHttpHooks({ alwaysAllowedHosts: ['127.0.0.1'] });
  await receive(http.get(url));
  expect(arrivals).toHaveBeenCalledTimes(1);
});

test.each([false, true])('actual lookup blocks private resolution, all=%s', all => {
  installHttpHooks({ alwaysAllowedHosts: [] });
  const hostname = 'fixture.example';
  const endpoint = `http://${hostname}:${port}/x`;
  const lookup = jest.fn((_host: string, _options: unknown, callback: (...args: unknown[]) => void) => {
    process.nextTick(() => all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4));
  });
  const options = { lookup: lookup as unknown as typeof dns.lookup, all };
  const request = tainted(endpoint, () => http.get(endpoint, options));
  expect(options.lookup).toBe(lookup);
  return new Promise<void>((resolve, reject) => {
    request.on('response', () => reject(new Error('Unexpected connection')));
    request.on('error', error => {
      try {
        expect(error).toBeInstanceOf(RaspBlockedError);
        expect(arrivals).not.toHaveBeenCalled();
        resolve();
      } catch (failure) { reject(failure); }
    });
  });
});

test('fetch block rejects without calling original', async () => {
  const original = jest.spyOn(globalThis, 'fetch');
  installHttpHooks({ alwaysAllowedHosts: [] });
  await expect(tainted(url, () => fetch(url))).rejects.toBeInstanceOf(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  expect(arrivals).not.toHaveBeenCalled();
});

describe('an outbound finding in monitor does not hide an SSRF block', () => {
  const settings = () => configureEngine({
    enabled: true, applicationName: 'a', mode: 'block', attacks: { outbound: 'monitor', ssrf: 'block' },
    allow: { outboundHosts: ['api.example.com'] }, env: {},
  });

  test('http.get', () => {
    settings();
    const original = jest.spyOn(http, 'get');
    installHttpHooks({ alwaysAllowedHosts: [] });
    expect(() => tainted(url, () => http.get(url))).toThrow(expect.objectContaining({ attack: 'ssrf', rule: 'ssrf.internal' }));
    expect(original).not.toHaveBeenCalled();
    expect(arrivals).not.toHaveBeenCalled();
  });

  test('fetch', async () => {
    settings();
    const original = jest.spyOn(globalThis, 'fetch');
    installHttpHooks({ alwaysAllowedHosts: [] });
    await expect(tainted(url, () => fetch(url))).rejects.toMatchObject({ attack: 'ssrf', rule: 'ssrf.internal' });
    expect(original).not.toHaveBeenCalled();
    expect(arrivals).not.toHaveBeenCalled();
  });
});

test('fetch checks DNS addresses before calling original', async () => {
  const original = jest.spyOn(globalThis, 'fetch');
  jest.spyOn(dns.promises, 'lookup').mockImplementation((async () => [{ address: '127.0.0.1', family: 4 }]) as unknown as typeof dns.promises.lookup);
  installHttpHooks({ alwaysAllowedHosts: [] });
  const endpoint = `http://fixture.example:${port}/x`;
  await expect(tainted(endpoint, () => fetch(endpoint))).rejects.toBeInstanceOf(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
});

test('off does not run detection', async () => {
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  const detector = jest.spyOn(detect, 'detectSsrf');
  installHttpHooks({ alwaysAllowedHosts: [] });
  await receive(tainted(url, () => http.get(url)));
  expect(detector).not.toHaveBeenCalled();
});

test('detector errors fail open', async () => {
  jest.spyOn(detect, 'detectOutbound').mockImplementation(() => { throw new Error('unavailable'); });
  installHttpHooks({ alwaysAllowedHosts: [] });
  await receive(http.get(url));
  expect(arrivals).toHaveBeenCalledTimes(1);
});

test('a fetch that cannot be wrapped leaves the http hooks in place', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'fetch')!;
  const fetchValue = descriptor.value;
  Object.defineProperty(globalThis, 'fetch', { configurable: true, enumerable: descriptor.enumerable, get: () => fetchValue });
  try {
    const original = jest.spyOn(http, 'request');
    expect(installHttpHooks({ alwaysAllowedHosts: [] })).toBe(true);
    expect(() => tainted(url, () => http.request(url))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
    expect(Object.getOwnPropertyDescriptor(globalThis, 'fetch')!.get).toBeDefined();
  } finally {
    uninstallHttpHooks();
    Object.defineProperty(globalThis, 'fetch', descriptor);
  }
});

test('alwaysAllowedHosts takes the hosts of the Shield360 URL and the OTLP endpoint', () => {
  expect(alwaysAllowedHosts(['https://App.Shield360.ai/api', 'http://[::1]:4318/v1/traces', undefined, 'not a url'])).toEqual(['app.shield360.ai', '::1']);
});

test('install is idempotent and restores exact descriptors', () => {
  const entries = [http, https].flatMap(owner => ['request', 'get'].map(key => ({ owner, key })));
  const saved = [...entries, { owner: globalThis, key: 'fetch' }].map(entry => ({
    ...entry, descriptor: Object.getOwnPropertyDescriptor(entry.owner, entry.key),
  }));
  expect(installHttpHooks({ alwaysAllowedHosts: [] })).toBe(true);
  const wrapper = http.request;
  expect(installHttpHooks({ alwaysAllowedHosts: [] })).toBe(true);
  expect(http.request).toBe(wrapper);
  for (const { owner, key, descriptor } of saved) {
    const fn = Reflect.get(owner, key) as { name: string; length: number };
    expect(fn.name).toBe(descriptor!.value.name);
    expect(fn.length).toBe(descriptor!.value.length);
  }
  uninstallHttpHooks();
  uninstallHttpHooks();
  for (const { owner, key, descriptor } of saved) expect(Object.getOwnPropertyDescriptor(owner, key)).toEqual(descriptor);
});

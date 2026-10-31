import vm = require('vm');
import http = require('http');
import { AddressInfo } from 'net';
import * as hooks from '../hooks/code';
import * as detect from '../detect';
import { configureEngine, setEventSink } from '../engine';
import { runWithInputs } from '../context';
import { RaspBlockedError } from '../types';
const taint = <T>(value: string, fn: () => T): T => runWithInputs([{ value, key: 'query.q', source: 'request' }], fn, { inRequest: true });
const mode = (value: 'block' | 'monitor' = 'block') => configureEngine({ enabled: true, applicationName: 'a', mode: value, env: {} });
beforeEach(() => { mode(); setEventSink({ add: () => undefined }); });
afterEach(() => {
  hooks.uninstallCodeHooks();
  jest.restoreAllMocks();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
});
test('vm blocks before original and monitor evaluates harmless code', () => {
  const original = jest.spyOn(vm, 'runInNewContext');
  hooks.installCodeHooks();
  expect(() => taint('1 + 2', () => vm.runInNewContext('1 + 2'))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  mode('monitor');
  const events = jest.fn();
  setEventSink({ add: events });
  expect(taint('1 + 2', () => vm.runInNewContext('1 + 2'))).toBe(3);
  expect(events).toHaveBeenCalledTimes(1);
  expect(vm.runInNewContext('2 + 3')).toBe(5);
});
test('vm Script and Function preserve prototypes and constructor behavior', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Function');
  hooks.installCodeHooks();
  expect(new vm.Script('1 + 2')).toBeInstanceOf(vm.Script);
  expect(() => taint('1 + 2', () => new vm.Script('1 + 2'))).toThrow(RaspBlockedError);
  const fn = new Function('a', 'return a + 1');
  expect(fn).toBeInstanceOf(Function);
  expect(fn(2)).toBe(3);
  expect(Function('return 3')()).toBe(3);
  expect(() => taint('return a + 1', () => new Function('a', 'return a + 1'))).toThrow(RaspBlockedError);
  hooks.uninstallCodeHooks();
  expect(Object.getOwnPropertyDescriptor(globalThis, 'Function')).toEqual(descriptor);
});
test('eval is left alone, so direct eval keeps the caller scope', () => {
  const original = globalThis.eval;
  hooks.installCodeHooks();
  expect(globalThis.eval).toBe(original);
  const local = 41;
  // Direct eval: only possible while eval is the built-in itself.
  expect(taint('local + 1', () => eval('local + 1'))).toBe(local + 1);
});

test('code run by vm is still checked when it builds code itself', () => {
  hooks.installCodeHooks();
  // The vm-run code is untainted; the Function call it makes carries the input.
  const run = () => vm.runInNewContext('make(body)', { make: (b: string) => new Function(b), body: 'return a + 1' });
  expect(() => taint('return a + 1', run)).toThrow(RaspBlockedError);
});

test('response write/end are added on ServerResponse only and removed again', () => {
  const proto = http.ServerResponse.prototype;
  expect(Object.prototype.hasOwnProperty.call(proto, 'end')).toBe(false);
  hooks.installCodeHooks();
  expect(Object.prototype.hasOwnProperty.call(proto, 'end')).toBe(true);
  expect(Object.prototype.hasOwnProperty.call(http.ClientRequest.prototype, 'end')).toBe(false);
  hooks.uninstallCodeHooks();
  expect(Object.prototype.hasOwnProperty.call(proto, 'write')).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(proto, 'end')).toBe(false);
});
test('node-serialize and funcster are checked before harmless fake originals', () => {
  const module = { unserialize: jest.fn((..._args: unknown[]) => 'result') };
  const funcster = { deepDeserialize: jest.fn((..._args: unknown[]) => 'result') };
  hooks.patchNodeSerialize(module);
  hooks.patchFuncster(funcster);
  const data = '{"fixture":"_$$ND_FUNC$$_description only"}';
  expect(() => taint(data, () => module.unserialize(data))).toThrow(RaspBlockedError);
  expect(module.unserialize).not.toHaveBeenCalled();
  expect(taint('fixture', () => module.unserialize('fixture'))).toBe('result');
  const object = { __js_function: 'description only' };
  expect(() => taint(JSON.stringify(object), () => funcster.deepDeserialize(object))).toThrow(RaspBlockedError);
});
test.each(['3.14.0', '4.1.0'])('js-yaml %s checks unsafe schemas, including loadAll', version => {
  const original = jest.fn((..._args: unknown[]) => 'result');
  const module = { load: original, loadAll: original, DEFAULT_SCHEMA: {}, DEFAULT_FULL_SCHEMA: {}, CORE_SCHEMA: {}, JSON_SCHEMA: {}, FAILSAFE_SCHEMA: {} };
  hooks.patchJsYaml(module, version);
  const text = '!!js/function description-only';
  const unsafe = version.startsWith('3') ? module.DEFAULT_FULL_SCHEMA : {};
  expect(() => taint(text, () => module.load(text, { schema: unsafe }))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  expect(() => taint(text, () => module.loadAll(text, () => undefined, { schema: unsafe }))).toThrow(RaspBlockedError);
  expect(taint(text, () => module.load(text, { schema: module.CORE_SCHEMA }))).toBe('result');
});
test.each([hooks.patchLibxmljs, hooks.patchLibxmljs2])('XML resolving parser blocks before fake original', patch => {
  const original = jest.fn((..._args: unknown[]) => 'result');
  const module = { parseXml: original, parseXmlString: original };
  patch(module);
  const xml = '<!DOCTYPE fixture SYSTEM "file:///srv/app/fixtures/example.txt"><fixture/>';
  expect(() => taint(xml, () => module.parseXml(xml, { noent: true }))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  const detector = jest.spyOn(detect, 'detectXml').mockReturnValue(null);
  expect(taint(xml, () => module.parseXmlString(xml, {}))).toBe('result');
  expect(detector).toHaveBeenCalledWith(xml, expect.any(Array), false);
});
test('own registry patches under shimmer metadata and disables under a later wrapper', () => {
  const original = jest.fn((..._args: unknown[]) => 'result');
  const tracing = Object.assign((...args: unknown[]) => original(...args), { __wrapped: true, __unwrap: jest.fn() });
  const module = { unserialize: tracing as (...args: unknown[]) => unknown };
  hooks.patchNodeSerialize(module);
  const wrapper = module.unserialize;
  hooks.patchNodeSerialize(module);
  expect(module.unserialize).toBe(wrapper);
  expect((wrapper as unknown as { __wrapped?: boolean }).__wrapped).toBeUndefined();
  const text = '_$$ND_FUNC$$_description only';
  expect(() => taint(text, () => module.unserialize(text))).toThrow(RaspBlockedError);
  module.unserialize = (...args) => wrapper(...args);
  const outer = module.unserialize;
  hooks.unpatchNodeSerialize(module);
  expect(module.unserialize).toBe(outer);
  expect(taint(text, () => module.unserialize(text))).toBe('result');
});
test('unpatch restores library identity', () => {
  const original = (..._args: unknown[]) => 'result';
  const module = { unserialize: original };
  hooks.patchNodeSerialize(module);
  hooks.unpatchNodeSerialize(module);
  expect(module.unserialize).toBe(original);
});
test('install and uninstall preserve builtin descriptors exactly', () => {
  const entries = [
    ...['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'Script'].map(key => ({ owner: vm, key })),
    ...['Function', 'eval'].map(key => ({ owner: globalThis, key })),
  ].map(entry => ({ ...entry, descriptor: Object.getOwnPropertyDescriptor(entry.owner, entry.key) }));
  expect(hooks.installCodeHooks()).toBe(true);
  const wrapper = vm.Script;
  expect(hooks.installCodeHooks()).toBe(true);
  expect(vm.Script).toBe(wrapper);
  hooks.uninstallCodeHooks();
  hooks.uninstallCodeHooks();
  for (const { owner, key, descriptor } of entries) expect(Object.getOwnPropertyDescriptor(owner, key)).toEqual(descriptor);
});

test.each(['html', 'plain', 'oversize'])('response %s arrives unchanged; XSS is monitor only', async kind => {
  const input = '<script>alert(1)</script>xyz';
  const body = kind === 'oversize' ? 'a'.repeat(1024 * 1024) + input : input;
  const events: { attrs: Record<string, string> }[] = [];
  setEventSink({ add: (event: { attrs: Record<string, string> }) => { events.push(event); } });
  const server = http.createServer((_req, res) => {
    taint(input, () => {
      res.setHeader('content-type', kind === 'plain' ? 'text/plain' : 'text/html');
      res.write(body.slice(0, 10));
    });
    // The hook must use the first write's captured context here.
    res.end(body.slice(10));
  });
  hooks.installCodeHooks();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const received = await new Promise<string>((resolve, reject) => {
      http.get(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`, response => {
        const chunks: Buffer[] = [];
        response.on('data', chunk => chunks.push(Buffer.from(chunk)));
        response.on('end', () => resolve(Buffer.concat(chunks).toString()));
        response.on('error', reject);
      }).on('error', reject);
    });
    expect(received).toBe(body);
    const reflected = events.filter(event => event.attrs['shield360.rasp.sink'] === 'http.response');
    expect(reflected).toHaveLength(kind === 'html' ? 1 : 0);
    if (kind === 'html') expect(reflected[0].attrs['shield360.rasp.decision']).toBe('monitored');
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test('off skips evaluation checks and detector failures fail open', () => {
  const detector = jest.spyOn(detect, 'detectCode');
  hooks.installCodeHooks();
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  expect(taint('1 + 2', () => vm.runInNewContext('1 + 2'))).toBe(3);
  expect(detector).not.toHaveBeenCalled();
  mode();
  detector.mockImplementation(() => { throw new Error('unavailable'); });
  expect(taint('1 + 2', () => vm.runInNewContext('1 + 2'))).toBe(3);
});

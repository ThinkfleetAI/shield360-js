import fs = require('fs');
import { tmpdir } from 'os';
import { join } from 'path';
import { pathToFileURL } from 'url';
import { promisify } from 'util';
import * as detect from '../detect';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { RaspBlockedError } from '../types';
import { installFsHooks, uninstallFsHooks } from '../hooks/fs';

let dir: string;
let file: string;
const request = <T>(fn: () => T): T => runWithInputs(
  [{ value: '../escape.txt', key: 'query.q', source: 'request' }], fn, { inRequest: true },
);
const mode = (value: 'monitor' | 'block') => configureEngine({ enabled: true, applicationName: 'a', mode: value, env: {} });
const mappings: [string, detect.FileOp][] = [
  ['readFile', 'read'], ['readFileSync', 'read'], ['createReadStream', 'read'],
  ['open', 'read'], ['openSync', 'read'], ['writeFile', 'write'], ['writeFileSync', 'write'],
  ['appendFile', 'append'], ['appendFileSync', 'append'], ['createWriteStream', 'write'],
  ['unlink', 'delete'], ['unlinkSync', 'delete'], ['rm', 'delete'], ['rmSync', 'delete'],
  ['rename', 'rename'], ['renameSync', 'rename'], ['readdir', 'list'], ['readdirSync', 'list'],
  ['copyFile', 'read'], ['copyFileSync', 'read'],
];
function invoke(owner: object, api: string, values: unknown[]): unknown {
  return Reflect.apply(Reflect.get(owner, api) as (...args: unknown[]) => unknown, owner, values);
}
beforeEach(() => {
  dir = fs.mkdtempSync(join(tmpdir(), 'rasp-fs-'));
  file = join(dir, 'fixture.txt');
  fs.writeFileSync(file, 'fixture');
  mode('block');
  setEventSink({ add: () => undefined });
});
afterEach(() => {
  uninstallFsHooks();
  jest.restoreAllMocks();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  fs.rmSync(dir, { recursive: true, force: true });
});

describe.each([false, true])('promise owner: %s', promises => {
  test.each(mappings)('%s checks its path before calling the original', async (api, op) => {
    const owner = promises ? fs.promises : fs;
    if (!Object.prototype.hasOwnProperty.call(owner, api)) return;
    // Replace only the I/O boundary: checking every entry point must not leave
    // pending streams, callbacks, or open descriptors behind.
    const descriptor = Object.getOwnPropertyDescriptor(owner, api)!;
    const original = jest.fn(() => promises ? Promise.resolve('result') : 'result');
    Object.defineProperty(owner, api, { ...descriptor, value: original });
    try {
      const detector = jest.spyOn(detect, 'detectPath').mockReturnValue(null);
      expect(installFsHooks()).toBe(true);
      const target = join(dir, 'target.txt');
      const values = api.startsWith('rename') || api.startsWith('copyFile') ? [file, target] : [file, 'r'];
      await request(() => invoke(owner, api, values));
      expect(detector).toHaveBeenCalledWith(file, op, expect.any(Array), [], true);
      if (api.startsWith('rename') || api.startsWith('copyFile')) {
        expect(detector).toHaveBeenCalledWith(target, api.startsWith('copyFile') ? 'write' : 'rename', expect.any(Array), [], true);
      }
      expect(original).toHaveBeenCalledWith(...values);
    } finally {
      uninstallFsHooks();
      Object.defineProperty(owner, api, descriptor);
    }
  });
});

test('a copy reports the strongest of its two paths', () => {
  configureEngine({ enabled: true, applicationName: 'a', mode: 'block', attacks: { path_traversal: 'monitor', file_write: 'block' }, env: {} });
  const original = jest.spyOn(fs, 'copyFileSync');
  jest.spyOn(detect, 'detectPath').mockImplementation((_path, op) => op === 'read'
    ? { attack: 'path_traversal', rule: 'path.traversal' }
    : { attack: 'file_write', rule: 'file_write.script' });
  installFsHooks();
  expect(() => request(() => fs.copyFileSync(file, join(dir, 'copy.txt')))).toThrow(expect.objectContaining({ rule: 'file_write.script' }));
  expect(original).not.toHaveBeenCalled();
});

test('a path that lost to a blocked copy is still checked later in the request', () => {
  const original = jest.spyOn(fs, 'writeFileSync');
  jest.spyOn(detect, 'detectPath').mockImplementation((_path, op) => op === 'read'
    ? { attack: 'path_traversal', rule: 'path.traversal' }
    : { attack: 'file_write', rule: 'file_write.script' });
  installFsHooks();
  const target = join(dir, 'copy.php');
  request(() => {
    // Tie: the source wins and blocks; the app catches the error.
    expect(() => fs.copyFileSync(file, target)).toThrow(expect.objectContaining({ rule: 'path.traversal' }));
    expect(() => fs.writeFileSync(target, 'x')).toThrow(expect.objectContaining({ rule: 'file_write.script' }));
  });
  expect(original).not.toHaveBeenCalled();
});

test('block is synchronous and never invokes the callback original', () => {
  const original = jest.spyOn(fs, 'readFile');
  installFsHooks();
  expect(() => request(() => fs.readFile(`${dir}/../escape.txt`, () => undefined))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
});

test('promises reject rather than throwing synchronously', async () => {
  const original = jest.spyOn(fs.promises, 'readFile');
  installFsHooks();
  let result: Promise<Buffer> | undefined;
  expect(() => { result = request(() => fs.promises.readFile(`${dir}/../escape.txt`)); }).not.toThrow();
  await expect(result).rejects.toBeInstanceOf(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
});

test('monitor reports and permits actual file I/O', () => {
  mode('monitor');
  const events = jest.fn();
  setEventSink({ add: events });
  const escaped = `${dir}/child/../escape.txt`;
  fs.mkdirSync(join(dir, 'child'));
  fs.writeFileSync(join(dir, 'escape.txt'), 'fixture');
  installFsHooks();
  expect(request(() => fs.readFileSync(escaped, 'utf8'))).toBe('fixture');
  expect(events).toHaveBeenCalled();
});

test('off skips detection', () => {
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  const detector = jest.spyOn(detect, 'detectPath');
  installFsHooks();
  expect(fs.readFileSync(file, 'utf8')).toBe('fixture');
  expect(detector).not.toHaveBeenCalled();
});

test('Buffer and file URL paths normalize; descriptors skip detection', () => {
  const detector = jest.spyOn(detect, 'detectPath').mockReturnValue(null);
  const fd = fs.openSync(file, 'r');
  installFsHooks();
  try {
    fs.readFileSync(Buffer.from(file));
    fs.readFileSync(pathToFileURL(file));
    expect(detector).toHaveBeenCalledTimes(2);
    fs.readFileSync(fd);
    expect(detector).toHaveBeenCalledTimes(2);
  } finally { fs.closeSync(fd); }
});

test.each(['r', 'r+', 'w', 'a', fs.constants.O_RDWR])('open flags %s map to read/write', flags => {
  const detector = jest.spyOn(detect, 'detectPath').mockReturnValue(null);
  installFsHooks();
  const fd = fs.openSync(file, flags);
  fs.closeSync(fd);
  expect(detector.mock.calls[0][1]).toBe(flags === 'r' ? 'read' : 'write');
});

test('detector errors fail open and reporter file reads do not recurse', () => {
  const detector = jest.spyOn(detect, 'detectPath').mockImplementation(() => {
    expect(fs.readFileSync(file, 'utf8')).toBe('fixture');
    throw new Error('unavailable');
  });
  installFsHooks();
  expect(fs.readFileSync(file, 'utf8')).toBe('fixture');
  expect(detector).toHaveBeenCalledTimes(1);
});

test('promisify performs I/O and cannot bypass blocking', async () => {
  installFsHooks();
  await expect(promisify(fs.readFile)(file, 'utf8')).resolves.toBe('fixture');
  await expect(request(() => promisify(fs.readFile)(`${dir}/../escape.txt`))).rejects.toBeInstanceOf(RaspBlockedError);
});

test('a synchronous read is checked once, not again for the open Node makes inside it', () => {
  const detector = jest.spyOn(detect, 'detectPath').mockReturnValue(null);
  installFsHooks();
  fs.readFileSync(file, 'utf8');
  fs.writeFileSync(join(dir, 'out.txt'), 'fixture');
  expect(detector.mock.calls.map((c) => c[1])).toEqual(['read', 'write']);
});

test('a stream is checked once per request, not again when it opens', async () => {
  const detector = jest.spyOn(detect, 'detectPath').mockReturnValue(null);
  installFsHooks();
  const text = await request(
    () =>
      new Promise<string>((resolve, reject) => {
        let s = '';
        fs.createReadStream(file, 'utf8')
          .on('data', (c) => (s += c))
          .on('end', () => resolve(s))
          .on('error', reject);
      }),
  );
  expect(text).toBe('fixture');
  expect(detector).toHaveBeenCalledTimes(1);
});

test('a blocked write stream is refused before it exists', () => {
  const original = jest.spyOn(fs, 'createWriteStream');
  installFsHooks();
  expect(() => request(() => fs.createWriteStream(`${dir}/../escape.txt`))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
});

test('installation is idempotent and restores exact descriptors', () => {
  const saved = [fs, fs.promises].flatMap(owner => mappings.flatMap(([api]) => {
    const descriptor = Object.getOwnPropertyDescriptor(owner, api);
    return descriptor ? [{ owner, api, descriptor }] : [];
  }));
  expect(installFsHooks()).toBe(true);
  const wrapper = fs.readFile;
  expect(installFsHooks()).toBe(true);
  expect(fs.readFile).toBe(wrapper);
  for (const { owner, api, descriptor } of saved) {
    const fn = Reflect.get(owner, api) as { name: string; length: number };
    expect(fn.name).toBe(descriptor.value.name);
    expect(fn.length).toBe(descriptor.value.length);
  }
  uninstallFsHooks();
  uninstallFsHooks();
  for (const { owner, api, descriptor } of saved) {
    expect(Object.getOwnPropertyDescriptor(owner, api)).toEqual(descriptor);
  }
});

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  collectRuntimePackages,
  EVERY_MS,
  reportRuntimePackages,
  runtimePackagesActive,
  runtimePackagesEnabled,
  START_DELAY_MS,
  startRuntimePackages,
  stopRuntimePackages,
} from '../runtime-packages';

type Sent = { url: string; auth: string; body: { resource: Record<string, string>; events: Array<{ name: string; attrs: Record<string, string> }> } };

function fakeFetch(status = 200) {
  const sent: Sent[] = [];
  const fetchImpl = jest.fn(async (url: string, init: RequestInit) => {
    sent.push({ url, auth: String((init.headers as Record<string, string>).Authorization), body: JSON.parse(String(init.body)) });
    return new Response('{}', { status });
  });
  return { sent, fetchImpl: fetchImpl as unknown as typeof fetch };
}

const ctx = (fetchImpl: typeof fetch, collect = () => [{ ecosystem: 'npm', name: 'express', version: '4.21.2' }]) => ({
  url: 'https://shield.test/',
  apiKey: 'k-test',
  applicationName: 'orders-api',
  environment: 'production',
  sdkVersion: '1.2.4',
  fetchImpl,
  collect,
});

afterEach(() => {
  stopRuntimePackages();
  jest.useRealTimers();
});

describe('runtimePackagesEnabled', () => {
  it('is on by default and off by option or env', () => {
    expect(runtimePackagesEnabled(undefined, {})).toBe(true);
    expect(runtimePackagesEnabled(true, {})).toBe(true);
    expect(runtimePackagesEnabled(false, {})).toBe(false);
    for (const v of ['off', 'false', '0', 'NO']) expect(runtimePackagesEnabled(undefined, { SHIELD360_RUNTIME_PACKAGES: v })).toBe(false);
    expect(runtimePackagesEnabled(undefined, { SHIELD360_RUNTIME_PACKAGES: 'on' })).toBe(true);
  });
});

describe('reportRuntimePackages', () => {
  it('sends component records with names and versions only, to the guard events route with the API key', async () => {
    const { sent, fetchImpl } = fakeFetch();
    await expect(reportRuntimePackages(ctx(fetchImpl))).resolves.toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe('https://shield.test/api/guard/events');
    expect(sent[0].auth).toBe('Bearer k-test');
    expect(sent[0].body.resource).toMatchObject({ 'service.name': 'orders-api', 'deployment.environment': 'production', 'service.version': '1.2.4' });
    expect(sent[0].body.events).toEqual([
      {
        name: 'shield360.rasp.component',
        time: expect.any(String),
        attrs: {
          'shield360.rasp.app': 'orders-api',
          'shield360.rasp.component.ecosystem': 'npm',
          'shield360.rasp.component.name': 'express',
          'shield360.rasp.component.version': '4.21.2',
        },
      },
    ]);
  });

  it('batches by 100 and caps the report at 500 packages', async () => {
    const { sent, fetchImpl } = fakeFetch();
    const many = Array.from({ length: 700 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
    await reportRuntimePackages(ctx(fetchImpl, () => many));
    expect(sent.map((s) => s.body.events.length)).toEqual([100, 100, 100, 100, 100]);
  });

  it('stops at a refusal and never rejects', async () => {
    const { sent, fetchImpl } = fakeFetch(401);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const many = Array.from({ length: 250 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
    await expect(reportRuntimePackages(ctx(fetchImpl, () => many))).resolves.toBe(false);
    expect(sent).toHaveLength(1);
    await expect(reportRuntimePackages(ctx(fetchImpl, () => { throw new Error('boom'); }))).resolves.toBe(false);
    warn.mockRestore();
  });

  it('sends nothing without a URL and key', async () => {
    const { sent, fetchImpl } = fakeFetch();
    await expect(reportRuntimePackages({ ...ctx(fetchImpl), apiKey: undefined })).resolves.toBe(false);
    expect(sent).toHaveLength(0);
  });
});

describe('startRuntimePackages', () => {
  it('reports after the start delay and then daily, once per process', async () => {
    jest.useFakeTimers();
    const { sent, fetchImpl } = fakeFetch();
    expect(startRuntimePackages(ctx(fetchImpl), undefined, {})).toBe(true);
    expect(startRuntimePackages(ctx(fetchImpl), undefined, {})).toBe(false);
    expect(runtimePackagesActive()).toBe(true);
    expect(sent).toHaveLength(0);
    await jest.advanceTimersByTimeAsync(START_DELAY_MS);
    expect(sent).toHaveLength(1);
    await jest.advanceTimersByTimeAsync(EVERY_MS);
    expect(sent).toHaveLength(2);
    stopRuntimePackages();
    expect(runtimePackagesActive()).toBe(false);
    await jest.advanceTimersByTimeAsync(EVERY_MS);
    expect(sent).toHaveLength(2);
  });

  it('does not start when turned off or without a key', () => {
    const { fetchImpl } = fakeFetch();
    expect(startRuntimePackages(ctx(fetchImpl), false, {})).toBe(false);
    expect(startRuntimePackages(ctx(fetchImpl), undefined, { SHIELD360_RUNTIME_PACKAGES: 'off' })).toBe(false);
    expect(startRuntimePackages({ ...ctx(fetchImpl), url: undefined }, undefined, {})).toBe(false);
    expect(runtimePackagesActive()).toBe(false);
  });
});

describe('collectRuntimePackages', () => {
  let root: string;
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'runtime-packages-'));
    const pkg = (dir: string, name: string, version: string) => {
      mkdirSync(join(dir, 'node_modules', ...name.split('/')), { recursive: true });
      writeFileSync(join(dir, 'node_modules', ...name.split('/'), 'package.json'), JSON.stringify({ name, version, main: 'secret/path.js' }));
    };
    mkdirSync(join(root, 'cwd'), { recursive: true });
    writeFileSync(join(root, 'cwd', 'package.json'), JSON.stringify({ dependencies: { a: '1' } }));
    pkg(join(root, 'cwd'), 'a', '1.0.0');
    mkdirSync(join(root, 'app', 'dist'), { recursive: true });
    writeFileSync(join(root, 'app', 'package.json'), JSON.stringify({ dependencies: { '@s/b': '2', missing: '1' } }));
    pkg(join(root, 'app'), '@s/b', '2.0.0');
    pkg(join(root, 'app'), 'loaded', '3.0.0');
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it('reads the working directory, the entry script’s package and require.cache, without paths', () => {
    const cache = { [join(root, 'app', 'node_modules', 'loaded', 'index.js')]: {} };
    const got = collectRuntimePackages(cache, join(root, 'cwd'), join(root, 'app', 'dist', 'main.js'));
    expect(got).toEqual([
      { ecosystem: 'runtime', name: 'node', version: process.versions.node },
      { ecosystem: 'npm', name: 'a', version: '1.0.0' },
      { ecosystem: 'npm', name: 'loaded', version: '3.0.0' },
      { ecosystem: 'npm', name: '@s/b', version: '2.0.0' },
    ]);
    expect(JSON.stringify(got)).not.toContain(root);
  });

  it('works with an empty module cache (ESM)', () => {
    const got = collectRuntimePackages({}, join(root, 'cwd'), null);
    expect(got.map((c) => c.name)).toEqual(['node', 'a']);
  });
});

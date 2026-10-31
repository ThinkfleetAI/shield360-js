/**
 * RASP reporter: batched events through the guard events transport, folding
 * of repeats, the per-minute cap, the components report.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { collectComponents, FOLD_MS, PER_MINUTE, RaspReporter, type RaspEvent } from '../reporter';

const event = (rule = 'sqli.userinput'): RaspEvent => ({
  name: 'shield360.rasp.event',
  time: new Date(0).toISOString(),
  attrs: { 'shield360.rasp.attack': 'sql_injection', 'shield360.rasp.rule': rule },
});

function reporter() {
  const posts: { url: string; auth: string; body: any }[] = [];
  let now = 1_000_000;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    posts.push({ url, auth: (init?.headers as Record<string, string>).Authorization, body: JSON.parse(String(init?.body)) });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  const r = new RaspReporter({ url: 'https://shield.example.com/', apiKey: 'test-api-key', applicationName: 'orders-api', environment: 'prod', sdkVersion: '1.2.0', fetchImpl, now: () => now, retryDelayMs: 1 });
  return { r, posts, advance: (ms: number) => (now += ms) };
}

describe('RaspReporter', () => {
  it('posts batches to /api/guard/events with the resource and the API key', async () => {
    const { r, posts } = reporter();
    r.add(event(), 'k1');
    await r.flush();
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe('https://shield.example.com/api/guard/events');
    expect(posts[0].auth).toBe('Bearer test-api-key');
    expect(posts[0].body.resource).toMatchObject({ 'service.name': 'orders-api', 'deployment.environment': 'prod', 'service.version': '1.2.0' });
    expect(posts[0].body.events[0].name).toBe('shield360.rasp.event');
  });

  it('folds repeats within 10 s into one more event with shield360.rasp.count', async () => {
    const { r, posts, advance } = reporter();
    expect(r.add(event(), 'same')).toBe(true);
    expect(r.add(event(), 'same')).toBe(false);
    expect(r.add(event(), 'same')).toBe(false);
    expect(r.add(event('sqli.stacked'), 'other')).toBe(true);
    advance(FOLD_MS);
    await r.flush();
    const sent = posts.flatMap((p) => p.body.events);
    expect(sent).toHaveLength(3);
    expect(sent[2].attrs['shield360.rasp.count']).toBe('2');
    expect(sent[2].attrs['shield360.rasp.rule']).toBe('sqli.userinput');
  });

  it('caps events at 100 a minute per process', async () => {
    const { r, posts, advance } = reporter();
    for (let i = 0; i < PER_MINUTE + 20; i++) r.add(event(), `k${i}`);
    expect(r.pending()).toHaveLength(PER_MINUTE);
    advance(60_000);
    expect(r.add(event(), 'later')).toBe(true);
    await r.flush();
    expect(posts.flatMap((p) => p.body.events)).toHaveLength(PER_MINUTE + 1);
  });

  it('stop() closes open folds and sends them', async () => {
    const { r, posts } = reporter();
    r.add(event(), 'k');
    r.add(event(), 'k');
    await r.stop();
    expect(posts.flatMap((p) => p.body.events).map((e) => e.attrs['shield360.rasp.count'])).toEqual([undefined, '1']);
  });

  it('components: names and versions only, as component records', async () => {
    const { r, posts } = reporter();
    r.reportComponents([{ ecosystem: 'npm', name: 'express', version: '4.21.2' }]);
    await r.flush();
    expect(posts[0].body.events[0]).toMatchObject({
      name: 'shield360.rasp.component',
      attrs: { 'shield360.rasp.app': 'orders-api', 'shield360.rasp.component.ecosystem': 'npm', 'shield360.rasp.component.name': 'express', 'shield360.rasp.component.version': '4.21.2' },
    });
  });

  it('never rejects when the transport fails', async () => {
    const r = new RaspReporter({
      url: 'https://shield.example.com',
      apiKey: 'k',
      applicationName: 'a',
      retryDelayMs: 1,
      fetchImpl: (async () => {
        throw new Error('offline');
      }) as unknown as typeof fetch,
    });
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    r.add(event(), 'k');
    await expect(r.flush()).resolves.toBeUndefined();
    warn.mockRestore();
  });
});

describe('collectComponents', () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'rasp-components-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', dependencies: { left: '^1.0.0', '@scope/right': '^2.0.0' } }));
    for (const [name, version] of [['left', '1.4.0'], ['@scope/right', '2.1.0'], ['loaded', '3.0.0']]) {
      mkdirSync(join(dir, 'node_modules', ...name.split('/')), { recursive: true });
      writeFileSync(join(dir, 'node_modules', ...name.split('/'), 'package.json'), JSON.stringify({ name, version, description: 'not sent' }));
    }
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('lists the runtime, declared dependencies and loaded packages, with no other fields', () => {
    const cache = { [join(dir, 'node_modules', 'loaded', 'index.js')]: {}, [join(dir, 'src', 'app.js')]: {} };
    const got = collectComponents(cache, dir);
    expect(got[0]).toEqual({ ecosystem: 'runtime', name: 'node', version: process.versions.node });
    expect(got.slice(1)).toEqual([
      { ecosystem: 'npm', name: 'left', version: '1.4.0' },
      { ecosystem: 'npm', name: '@scope/right', version: '2.1.0' },
      { ecosystem: 'npm', name: 'loaded', version: '3.0.0' },
    ]);
  });
});

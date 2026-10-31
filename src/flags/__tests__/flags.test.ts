import * as fs from 'fs';
import * as path from 'path';
import { trace } from '@opentelemetry/api';
import Shield360Config from '../../config';
import * as engine from '../engine';
import { FlagsClient, promptRefOf } from '../client';
import Shield360 from '../../index';

/** Beside this SDK in the monorepo (sdk/flags-core), or inside the SDK's public mirror (flags-core/). */
function flagsCore(...parts: string[]): string {
  const candidates = [path.resolve(__dirname, '../../../../flags-core', ...parts), path.resolve(__dirname, '../../../flags-core', ...parts)];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[0];
}

const vectors = JSON.parse(fs.readFileSync(flagsCore('testdata', 'vectors.json'), 'utf8'));

describe('the engine', () => {
  it('is a byte-identical copy of sdk/flags-core', () => {
    expect(fs.readFileSync(path.resolve(__dirname, '../engine.ts'), 'utf8')).toBe(fs.readFileSync(flagsCore('src', 'engine.ts'), 'utf8'));
  });

  for (const c of vectors.evaluations as any[]) {
    it(`evaluates: ${c.name}`, () => {
      expect(engine.evaluate(c.flag, c.context, c.segments)).toEqual(c.expect);
    });
  }

  for (const c of vectors.segmentValidation as any[]) {
    it(`validates segment: ${c.name}`, () => {
      expect(engine.validateSegment(c.segment)).toEqual(c.errors);
    });
  }

  for (const c of vectors.validation as any[]) {
    it(`validates: ${c.name}`, () => {
      expect(engine.validateFlag(c.flag)).toEqual(c.errors);
    });
  }

  it('hashes and formats like every other SDK', () => {
    for (const c of vectors.murmur3) expect(engine.murmur3(c.input)).toBe(c.murmur3);
    for (const c of vectors.text) expect(engine.textOf(c.value)).toBe(c.text);
  });
});

const FLAG = {
  key: 'new-checkout',
  type: 'boolean',
  variations: [
    { key: 'on', value: true },
    { key: 'off', value: false },
  ],
  offVariation: 'off',
  on: true,
  rules: [{ id: 'pro', conditions: [{ attribute: 'plan', operator: 'equals', values: ['pro'] }], serve: { variation: 'on' } }],
  fallthrough: { variation: 'off' },
  salt: 's1',
  version: 3,
  appName: null,
};
const MODEL = {
  key: 'model-choice',
  type: 'string',
  variations: [
    { key: 'a', value: 'gpt-4o-mini' },
    { key: 'b', value: 'claude-haiku' },
  ],
  offVariation: 'a',
  on: true,
  rules: [],
  fallthrough: { variation: 'b' },
  salt: 's2',
  appName: 'checkout-api',
};

type Reply = { status: number; body?: unknown; etag?: string } | Error;

function fakeFetch(replies: Reply[]) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fn = jest.fn(async (url: string, init: { headers: Record<string, string> }) => {
    calls.push({ url, headers: init.headers });
    const reply = replies.length > 1 ? replies.shift()! : replies[0];
    if (reply instanceof Error) throw reply;
    return {
      status: reply.status,
      ok: reply.status >= 200 && reply.status < 300,
      headers: { get: (name: string) => (name.toLowerCase() === 'etag' ? reply.etag ?? null : null) },
      json: async () => reply.body,
    };
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

const client = (replies: Reply[], extra: Record<string, unknown> = {}) => {
  const f = fakeFetch(replies);
  const c = new FlagsClient({ url: 'https://s360.test/', apiKey: 'k1', applicationName: 'checkout-api', fetch: f.fn, ...extra });
  return { c, calls: f.calls };
};

afterEach(() => jest.restoreAllMocks());

describe('FlagsClient', () => {
  it('serves defaults until rules arrive, then evaluates locally', async () => {
    const { c, calls } = client([{ status: 200, body: { version: 'v1', flags: [FLAG, MODEL] }, etag: '"v1"' }]);
    expect(c.isEnabled('new-checkout', { plan: 'pro' })).toBe(false);
    expect(c.getFlagDetail('new-checkout', {}, false).reason.kind).toBe('NOT_READY');
    expect(await c.ready(1000)).toBe(true);
    expect(calls[0]).toEqual({ url: 'https://s360.test/api/flags/rules', headers: { Authorization: 'Bearer k1', Accept: 'application/json' } });
    expect(c.isEnabled('new-checkout', { key: 'u1', plan: 'pro' })).toBe(true);
    expect(c.isEnabled('new-checkout', { key: 'u1', plan: 'free' })).toBe(false);
    const model: string = c.getFlag('model-choice', { key: 'u1' }, 'gpt-4o-mini');
    expect(model).toBe('claude-haiku');
    expect(c.getFlag('missing', {}, 'fallback')).toBe('fallback');
    c.close();
  });

  it('sends the ETag back and keeps the rules on a 304', async () => {
    const { c, calls } = client([
      { status: 200, body: { version: 'v1', flags: [FLAG] }, etag: '"v1"' },
      { status: 304, etag: '"v1"' },
    ]);
    await c.refresh();
    await c.refresh();
    expect(calls[1].headers['If-None-Match']).toBe('"v1"');
    expect(c.isEnabled('new-checkout', { plan: 'pro' })).toBe(true);
  });

  it('keeps the last good rules through errors, and never throws', async () => {
    const { c } = client([{ status: 200, body: { flags: [FLAG] }, etag: '"v1"' }, { status: 500 }, new Error('offline'), { status: 200, body: 'garbage' }]);
    await c.refresh();
    expect(await c.refresh()).toBe(false);
    expect(await c.refresh()).toBe(false);
    expect(await c.refresh()).toBe(false);
    expect(c.isEnabled('new-checkout', { plan: 'pro' })).toBe(true);
    expect(() => c.getFlag('new-checkout', null as any, true)).not.toThrow();
  });

  it('leaves out a flag that does not validate, and one for another app', async () => {
    const broken = { ...FLAG, key: 'broken', offVariation: 'nope' };
    const { c } = client([{ status: 200, body: { flags: [broken, MODEL] } }], { applicationName: 'billing' });
    await c.refresh();
    expect(c.getFlagDetail('broken', {}, true)).toEqual({ value: true, variation: null, reason: { kind: 'FLAG_NOT_FOUND' } });
    expect(c.getFlagDetail('model-choice', {}, 'x').reason.kind).toBe('FLAG_NOT_FOUND');
  });

  it('returns the default when the flag is of another type', async () => {
    const { c } = client([{ status: 200, body: { flags: [MODEL] } }]);
    await c.refresh();
    expect(c.getFlagDetail('model-choice', {}, 7)).toEqual({ value: 7, variation: null, reason: { kind: 'WRONG_TYPE' } });
  });

  it('stamps the served variation on the active span', async () => {
    const setAttribute = jest.fn();
    jest.spyOn(trace, 'getActiveSpan').mockReturnValue({ isRecording: () => true, setAttribute } as any);
    const { c } = client([{ status: 200, body: { flags: [FLAG] } }]);
    await c.refresh();
    c.isEnabled('new-checkout', { plan: 'pro' });
    expect(setAttribute).toHaveBeenCalledWith('shield360.flag.new-checkout', 'on');
    setAttribute.mockClear();
    c.isEnabled('missing', {});
    expect(setAttribute).not.toHaveBeenCalled();
  });

  it('does nothing without a URL and key, and uses init()\'s when it has them', async () => {
    const f = fakeFetch([{ status: 200, body: { flags: [FLAG] } }]);
    const saved = { url: Shield360Config.shield360Url, key: Shield360Config.shield360ApiKey, env: { ...process.env } };
    delete process.env.SHIELD360_URL;
    delete process.env.SHIELD360_API_KEY;
    Shield360Config.shield360Url = undefined;
    Shield360Config.shield360ApiKey = undefined;
    try {
      const c = new FlagsClient({ fetch: f.fn });
      expect(await c.refresh()).toBe(false);
      expect(f.calls).toHaveLength(0);
      Shield360Config.shield360Url = 'https://from-init.test';
      Shield360Config.shield360ApiKey = 'init-key';
      expect(await c.refresh()).toBe(true);
      expect(f.calls[0].url).toBe('https://from-init.test/api/flags/rules');
    } finally {
      Shield360Config.shield360Url = saved.url;
      Shield360Config.shield360ApiKey = saved.key;
      process.env = saved.env;
    }
  });

  it('polls on a timer that does not keep the process alive', async () => {
    jest.useFakeTimers();
    try {
      const { c, calls } = client([{ status: 200, body: { flags: [FLAG] } }], { pollIntervalMs: 5000 });
      c.start();
      await jest.advanceTimersByTimeAsync(0);
      expect(calls).toHaveLength(1);
      await jest.advanceTimersByTimeAsync(5600);
      expect(calls).toHaveLength(2);
      c.close();
      await jest.advanceTimersByTimeAsync(20000);
      expect(calls).toHaveLength(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('is on the SDK as Shield360.flags', () => {
    expect(Shield360.flags).toBeInstanceOf(FlagsClient);
  });
});

describe('segments and AI helpers', () => {
  const SEGMENTED = {
    ...MODEL,
    key: 'support-model',
    appName: null,
    variations: [
      { key: 'premium', value: 'openai/gpt-4o' },
      { key: 'cheap', value: 'openai/gpt-4o-mini' },
    ],
    offVariation: 'cheap',
    rules: [{ id: 'beta', conditions: [{ attribute: 'segment', operator: 'in_segment', values: ['beta-users'] }], serve: { variation: 'cheap' } }],
    fallthrough: { variation: 'premium' },
  };
  const BETA = { key: 'beta-users', conditions: [{ attribute: 'groups', operator: 'in', values: ['beta'] }] };
  const KILL = { ...FLAG, key: 'summaries', rules: [], fallthrough: { variation: 'on' } };
  const PROMPT = {
    key: 'support-prompt',
    type: 'json',
    variations: [
      { key: 'v1', value: { name: 'support-reply', version: '1.0.0' } },
      { key: 'v2', value: 'support-reply@2.0.0' },
    ],
    offVariation: 'v1',
    on: true,
    rules: [],
    fallthrough: { variation: 'v2' },
    salt: 's3',
  };

  it('evaluates rules that name segments from the feed, and drops invalid segments', async () => {
    const { c } = client([{ status: 200, body: { version: 'v1', flags: [SEGMENTED], segments: [BETA, { key: 'bad', conditions: [] }] }, etag: '"v1"' }]);
    await c.ready(1000);
    expect(c.model('support-model', { key: 'u1', groups: ['beta'] }, 'x/y')).toBe('openai/gpt-4o-mini');
    expect(c.model('support-model', { key: 'u1', groups: ['staff'] }, 'x/y')).toBe('openai/gpt-4o');
    expect(c.model('missing', { key: 'u1' }, 'x/y')).toBe('x/y');
    c.close();
  });

  it('engages a kill switch only when the flag says so', async () => {
    const { c } = client([{ status: 200, body: { version: 'v1', flags: [KILL, { ...KILL, key: 'killed', on: false }] } }]);
    expect(c.killSwitch('summaries')).toBe(false); // not ready: keep running
    await c.ready(1000);
    expect(c.killSwitch('summaries', { key: 'u1' })).toBe(false);
    expect(c.killSwitch('killed', { key: 'u1' })).toBe(true);
    expect(c.killSwitch('unknown', { key: 'u1' })).toBe(false);
    c.close();
  });

  it('fetches the Prompt Hub version a prompt flag serves, and never rejects', async () => {
    const { c } = client([{ status: 200, body: { version: 'v1', flags: [PROMPT] } }]);
    await c.ready(1000);
    const hub = jest.spyOn(globalThis, 'fetch' as never).mockImplementation((async (_url: string, init: { body: string }) => ({
      ok: true,
      status: 200,
      json: async () => ({ err: null, res: { name: JSON.parse(init.body).name, version: JSON.parse(init.body).version, prompt: 'Hello' } }),
    })) as never);
    const served = await c.prompt('support-prompt', { key: 'u1' }, { name: 'fallback' });
    expect(served).toMatchObject({ name: 'support-reply', version: '2.0.0', variation: 'v2', error: null, prompt: { version: '2.0.0' } });
    const fallback = await c.prompt('missing', { key: 'u1' }, { name: 'fallback', version: '3' });
    expect(fallback).toMatchObject({ name: 'fallback', version: '3', variation: null });
    hub.mockImplementation((async () => {
      throw new Error('down');
    }) as never);
    const failed = await c.prompt('support-prompt', { key: 'u1' }, { name: 'fallback' });
    expect(failed.prompt).toBeNull();
    expect(failed.error).toContain('down');
    c.close();
  });

  it('reads prompt references from objects and name@version text', () => {
    expect(promptRefOf('a@1.2')).toEqual({ name: 'a', version: '1.2' });
    expect(promptRefOf('a')).toEqual({ name: 'a' });
    expect(promptRefOf('@1')).toBeNull();
    expect(promptRefOf({ name: 'a', version: 2 })).toBeNull();
    expect(promptRefOf(5)).toBeNull();
  });
});

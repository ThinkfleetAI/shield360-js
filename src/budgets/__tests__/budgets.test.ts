import { BudgetClient, BudgetExceededError } from '../index';
import { modelOf, setupAutoBudgetCheck } from '../auto';

type Answer = { status?: number; body?: unknown; throws?: boolean };

function fakeFetch(answers: Answer[] | ((url: string) => Answer)) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fn = jest.fn(async (url: string, init: { headers: Record<string, string> }) => {
    calls.push({ url, headers: init.headers });
    const a = typeof answers === 'function' ? answers(url) : answers.shift() ?? { status: 500 };
    if (a.throws) throw new Error('network down');
    return { ok: (a.status ?? 200) < 300, status: a.status ?? 200, json: async () => a.body } as unknown as Response;
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

const decision = (over: Record<string, unknown> = {}) => ({ action: 'allow', code: 'budget_ok', reason: '', limit: null, failClosed: false, ttlSeconds: 60, headroomUsd: null, ...over });

function client(f: ReturnType<typeof fakeFetch>, over: Record<string, unknown> = {}, clock = { t: 1_000_000 }) {
  return new BudgetClient({ url: 'https://shield.example/', apiKey: 'k_test', app: 'checkout-api', fetch: f.fn, now: () => clock.t, ...over });
}

describe('budgets.check', () => {
  it('asks for the app and model with the API key, and allows on allow', async () => {
    const f = fakeFetch([{ body: decision() }]);
    const r = await client(f).check({ model: 'gpt-4o', estimatedCostUsd: 0.02 });
    expect(r).toMatchObject({ allowed: true, action: 'allow', cached: false, unavailable: false });
    expect(f.calls[0].url).toBe('https://shield.example/api/budgets/decision?app=checkout-api&model=gpt-4o&cost=0.020000');
    expect(f.calls[0].headers.Authorization).toBe('Bearer k_test');
  });

  it('reuses a decision within its ttl while the calls fit its headroom, then asks again', async () => {
    const clock = { t: 0 };
    const f = fakeFetch(() => ({ body: decision({ headroomUsd: 1 }) }));
    const c = client(f, {}, clock);
    await c.check({ estimatedCostUsd: 0.4 });
    expect((await c.check({ estimatedCostUsd: 0.4 })).cached).toBe(true);
    expect(f.calls).toHaveLength(1);
    // 0.4 + 0.4 + 0.4 > 1: past the headroom, so the next call asks again.
    expect((await c.check({ estimatedCostUsd: 0.4 })).cached).toBe(false);
    expect(f.calls).toHaveLength(2);
    clock.t += 61_000;
    await c.check({});
    expect(f.calls).toHaveLength(3);
  });

  it('with no headroom limit, reuses the decision for its ttl however much is spent', async () => {
    const f = fakeFetch(() => ({ body: decision({ headroomUsd: null, ttlSeconds: 30 }) }));
    const c = client(f);
    for (let i = 0; i < 20; i++) await c.check({ estimatedCostUsd: 5 });
    expect(f.calls).toHaveLength(1);
  });

  it('shares one fetch between concurrent checks', async () => {
    const f = fakeFetch(() => ({ body: decision() }));
    const c = client(f);
    await Promise.all([c.check({}), c.check({}), c.check({})]);
    expect(f.calls).toHaveLength(1);
  });

  it('refuses on block and says why; allows on warn with the reason', async () => {
    const blocked = await client(fakeFetch([{ body: decision({ action: 'block', code: 'budget_block', reason: 'Over the Checkout budget.', limit: { id: 'b1', name: 'Checkout', scope: 'App: checkout-api' } }) }])).check();
    expect(blocked).toMatchObject({ allowed: false, action: 'block', code: 'budget_block', reason: 'Over the Checkout budget.' });
    expect(blocked.limit).toEqual({ id: 'b1', name: 'Checkout', scope: 'App: checkout-api' });
    const warned = await client(fakeFetch([{ body: decision({ action: 'warn', code: 'budget_warn', reason: 'At 85%.' }) }])).check();
    expect(warned).toMatchObject({ allowed: true, action: 'warn', reason: 'At 85%.' });
  });

  it('throttles to the requests a minute the decision allows', async () => {
    const clock = { t: 0 };
    const c = client(fakeFetch(() => ({ body: decision({ action: 'throttle', code: 'budget_throttle', throttle: { requestsPerMinute: 2 }, ttlSeconds: 600 }) })), {}, clock);
    expect((await c.check()).allowed).toBe(true);
    expect((await c.check()).allowed).toBe(true);
    expect((await c.check()).allowed).toBe(false);
    clock.t += 60_001;
    expect((await c.check()).allowed).toBe(true);
  });

  it('never throws, and fails open by default when no decision can be read', async () => {
    for (const answer of [{ throws: true }, { status: 503, body: { err: 'x' } }, { status: 200, body: 'nonsense' }, { status: 200, body: { action: 'explode' } }]) {
      const r = await client(fakeFetch([answer])).check();
      expect(r).toMatchObject({ allowed: true, action: 'allow', unavailable: true, code: 'budget_unavailable' });
    }
    // No URL or key: nothing to ask, so the fail mode applies without a request.
    const f = fakeFetch([]);
    expect((await new BudgetClient({ app: 'a', fetch: f.fn, url: '', apiKey: '' }).check()).unavailable).toBe(true);
    expect(f.calls).toHaveLength(0);
  });

  it('fails closed when asked to, on the client or for one check', async () => {
    const down = () => fakeFetch(() => ({ throws: true }));
    expect(await client(down(), { failClosed: true }).check()).toMatchObject({ allowed: false, action: 'block', unavailable: true });
    expect((await client(down()).check({ failClosed: true })).allowed).toBe(false);
    expect((await client(down(), { failClosed: true }).check({ failClosed: false })).allowed).toBe(true);
  });

  it('fails closed after a decision said a block rule asks for it', async () => {
    const clock = { t: 0 };
    let up = true;
    const f = fakeFetch(() => (up ? { body: decision({ failClosed: true, ttlSeconds: 1 }) } : { throws: true }));
    const c = client(f, {}, clock);
    expect((await c.check()).allowed).toBe(true);
    up = false;
    clock.t += 2_000;
    expect((await c.check()).allowed).toBe(false);
  });

  it('backs off for a few seconds after a failed read instead of asking on every call', async () => {
    const clock = { t: 0 };
    const f = fakeFetch(() => ({ throws: true }));
    const c = client(f, {}, clock);
    await c.check();
    await c.check();
    expect(f.calls).toHaveLength(1);
    clock.t += 6_000;
    await c.check();
    expect(f.calls).toHaveLength(2);
  });
});

describe('the automatic pre-call check', () => {
  it('names the model from the call, and from a Bedrock command', () => {
    expect(modelOf({ model: 'gpt-4o', messages: [] })).toBe('gpt-4o');
    expect(modelOf({ input: { modelId: 'anthropic.claude-3' } })).toBe('anthropic.claude-3');
    expect(modelOf(undefined)).toBeUndefined();
  });

  it('refuses a provider call a budget blocks, and lets an allowed one through', async () => {
    const proto = { create: jest.fn(async (params: { model: string }) => `ok ${params.model}`) };
    jest.doMock('fake-provider-for-budget-test', () => ({ Client: { prototype: proto } }), { virtual: true });
    let action = 'allow';
    const f = fakeFetch(() => ({ body: decision({ action, code: `budget_${action}`, reason: action === 'block' ? 'Over budget.' : '', ttlSeconds: 0.001 }) }));
    const clock = { t: 0 };
    const c = client(f, {}, clock);
    const report = setupAutoBudgetCheck({ client: c, methods: [{ npmPackage: 'fake-provider-for-budget-test', protoPath: ['Client', 'prototype'], methodName: 'create', extractInput: () => '', extractOutput: () => '' }] });
    expect(report.wrapped).toEqual(['fake-provider-for-budget-test']);
    expect(await proto.create({ model: 'gpt-4o' })).toBe('ok gpt-4o');
    expect(f.calls[0].url).toContain('model=gpt-4o');
    action = 'block';
    clock.t += 1_000;
    await expect(proto.create({ model: 'gpt-4o' })).rejects.toBeInstanceOf(BudgetExceededError);
    // Wrapping twice does not check twice.
    const again = setupAutoBudgetCheck({ client: c, methods: [{ npmPackage: 'fake-provider-for-budget-test', protoPath: ['Client', 'prototype'], methodName: 'create', extractInput: () => '', extractOutput: () => '' }] });
    expect(again.wrapped).toEqual([]);
  });
});

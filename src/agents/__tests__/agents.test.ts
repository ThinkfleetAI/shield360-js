/**
 * Agent passport verifier: every step and reason code of the contract, the
 * receiver policy, the console policy, reports, the middleware and the inputs
 * a passport can be read from. Keys are generated here; the network is mocked.
 */
import { generateKeyPairSync, KeyObject, randomUUID, sign } from 'crypto';
import { IncomingMessage } from 'http';
import { Socket } from 'net';
import { agentVerifier, AGENT_HEADER, AgentCheck, AgentVerifierOptions, MemoryReplayStore, ReplayStore } from '../index';
import { audienceMatches, parsePassport } from '../passport';

const ISS = 'https://app.shield360.ai';
const T0 = Date.UTC(2026, 9, 28, 12, 0, 0);

type Keys = { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> };

function makeKey(kid = 'k1'): Keys {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' } };
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function claims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const iat = Math.floor(T0 / 1000);
  return {
    iss: ISS,
    sub: 'agent:a1',
    aud: 'api.servflo.ai',
    iat,
    exp: iat + 120,
    jti: randomUUID(),
    agent: { id: 'a1', name: 'Dispatch bot', purpose: 'Schedules jobs' },
    operator: { id: 'org_1', name: 'Acme', domain: 'acme.com' },
    scope: 'jobs.read invoices.write',
    decision: { id: 'd1', policyVersion: 'pv1' },
    ...over,
  };
}

function passport(key: Keys, over: Record<string, unknown> = {}, header: Record<string, unknown> = {}): string {
  const h = b64({ alg: 'EdDSA', typ: 'shield360-agent+jwt', kid: key.kid, ...header });
  const p = b64(claims(over));
  const sig = sign(null, Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

type Net = {
  fetch: jest.Mock;
  keys: Keys[];
  verify?: (body: any) => Response | Promise<Response>;
  policy?: () => Response | Promise<Response>;
  decisions: any[][];
  decisionStatus?: number;
};

function net(keys: Keys[]): Net {
  const n: Net = { keys, decisions: [], fetch: jest.fn() };
  n.fetch.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    if (u.pathname === '/api/agent-passports/keys') return json({ keys: n.keys.map((k) => k.jwk) });
    if (u.pathname === '/api/agent-passports/verify') {
      if (!n.verify) throw new Error('no verify');
      return n.verify(JSON.parse(String(init.body)));
    }
    if (u.pathname === '/api/inbound-agents/policy') {
      if (!n.policy) throw new Error('no policy');
      return n.policy();
    }
    if (u.pathname === '/api/inbound-agents/decisions') {
      n.decisions.push(JSON.parse(String(init.body)).decisions);
      return json({ ok: true }, n.decisionStatus ?? 200);
    }
    throw new Error(`unexpected ${url}`);
  });
  return n;
}

let now = T0;
let key: Keys;
let n: Net;

function verifier(over: Partial<AgentVerifierOptions> = {}) {
  return agentVerifier({ audience: 'api.servflo.ai', fetch: n.fetch as unknown as typeof fetch, clock: () => now, ...over });
}

beforeEach(() => {
  now = T0;
  key = makeKey();
  n = net([key]);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

describe('a valid passport', () => {
  it('verifies and carries the agent, operator, person and scopes', async () => {
    const token = passport(key, { act: { sub: 'pairwiseId0123456789ab', domain: 'acme.com' } });
    const r = await verifier().check(token);
    expect(r).toMatchObject({
      status: 'verified',
      decision: 'allow',
      blocked: false,
      agent: { id: 'a1', name: 'Dispatch bot', purpose: 'Schedules jobs' },
      operator: { id: 'org_1', name: 'Acme', domain: 'acme.com' },
      onBehalfOf: { id: 'pairwiseId0123456789ab', domain: 'acme.com' },
      scopes: ['jobs.read', 'invoices.write'],
      issuer: ISS,
      expiresAt: new Date(T0 + 120_000).toISOString(),
    });
    expect(r.reason).toBeUndefined();
    expect(r.passportId).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.stringify(r)).not.toContain(token);
  });

  it('fetches the key by kid once and caches it', async () => {
    const v = verifier();
    await v.check(passport(key));
    await v.check(passport(key));
    expect(n.fetch).toHaveBeenCalledTimes(1);
    expect(n.fetch.mock.calls[0][0]).toBe(`${ISS}/api/agent-passports/keys?kid=k1`);
  });

  it('reads a passport without scope, decision or act domain (as the issuer emits them)', async () => {
    const r = await verifier().check(passport(key, { scope: undefined, act: { sub: 'p1', domain: null } }));
    expect(r).toMatchObject({ status: 'verified', scopes: [], onBehalfOf: { id: 'p1', domain: null } });
  });

  it('treats a 404 for an unknown kid as unknown_key', async () => {
    n.fetch.mockImplementationOnce(async () => json({ err: 'unknown kid', keys: [] }, 404));
    expect((await verifier().check(passport(key))).reason).toBe('unknown_key');
  });

  it('drops ill-formed scopes and keeps at most 32', async () => {
    const many = Array.from({ length: 40 }, (_, i) => `s${i}`).join(' ');
    const r = await verifier().check(passport(key, { scope: `bad/scope ${many}` }));
    expect(r.scopes).toHaveLength(32);
    expect(r.scopes).not.toContain('bad/scope');
  });
});

describe('every failure reason, in order', () => {
  const cases: Array<[string, () => string, string]> = [
    ['not three parts', () => 'abc.def', 'malformed'],
    ['bad base64', () => 'a$b.c.d', 'malformed'],
    ['header not JSON', () => `bm90LWpzb24.${b64(claims())}.${'A'.repeat(86)}`, 'malformed'],
    ['wrong typ', () => passport(key, {}, { typ: 'JWT' }), 'malformed'],
    ['crit header', () => passport(key, {}, { crit: ['x'] }), 'malformed'],
    ['missing claims', () => passport(key, { operator: undefined }), 'malformed'],
    ['aud array', () => passport(key, { aud: ['api.servflo.ai'] }), 'malformed'],
    ['huge token', () => 'a'.repeat(10_000), 'malformed'],
    ['alg none', () => passport(key, {}, { alg: 'none' }), 'unsupported_alg'],
    ['alg RS256', () => passport(key, {}, { alg: 'RS256' }), 'unsupported_alg'],
    ['untrusted issuer', () => passport(key, { iss: 'https://evil.example' }), 'untrusted_issuer'],
    ['unknown kid', () => passport(makeKey('other'), {}), 'unknown_key'],
    ['signed by another key', () => passport({ ...makeKey(), kid: 'k1' }), 'bad_signature'],
    ['expired', () => passport(key, { iat: T0 / 1000 - 400, exp: T0 / 1000 - 61 }), 'expired'],
    ['not yet valid', () => passport(key, { iat: T0 / 1000 + 61, exp: T0 / 1000 + 200 }), 'not_yet_valid'],
    ['lifetime too long', () => passport(key, { exp: T0 / 1000 + 301 }), 'lifetime_too_long'],
    ['wrong audience', () => passport(key, { aud: 'api.other.ai' }), 'wrong_audience'],
  ];
  it.each(cases)('%s', async (_name, make, reason) => {
    const r = await verifier().check(make());
    expect(r).toMatchObject({ status: 'invalid', decision: 'deny', blocked: false, reason });
  });

  it('is blocked only in enforce', async () => {
    const r = await verifier({ policy: { mode: 'enforce' } }).check('x.y.z');
    expect(r).toMatchObject({ status: 'invalid', decision: 'deny', blocked: true });
  });

  it('detects a tampered payload', async () => {
    const [h, , s] = passport(key).split('.');
    const r = await verifier().check(`${h}.${b64(claims({ operator: { id: 'org_2', name: 'X', domain: null } }))}.${s}`);
    expect(r.reason).toBe('bad_signature');
  });

  it('never throws on hostile input', async () => {
    const v = verifier();
    const inputs: unknown[] = [undefined, null, 42, {}, [], { headers: null }, { headers: { [AGENT_HEADER]: 5 } }, '....', '\u0000.\u0000.\u0000', { get: () => { throw new Error('x'); } }];
    for (const input of inputs) await expect(v.check(input as any)).resolves.toBeDefined();
  });
});

describe('time and skew', () => {
  it('accepts within the skew and rejects past it', async () => {
    const exp = T0 / 1000 + 10;
    now = T0 + 69_000; // exp + 59 s
    expect((await verifier().check(passport(key, { exp }))).status).toBe('verified');
    now = T0 + 71_000; // exp + 61 s
    expect((await verifier().check(passport(key, { exp }))).reason).toBe('expired');
  });

  it('honors a custom skew', async () => {
    const r = await verifier({ clockSkewSeconds: 5 }).check(passport(key, { iat: T0 / 1000 + 30, exp: T0 / 1000 + 100 }));
    expect(r.reason).toBe('not_yet_valid');
  });
});

describe('keys', () => {
  it('refetches an unknown kid at most once a minute per issuer', async () => {
    const v = verifier();
    const k2 = makeKey('k2');
    await v.check(passport(k2));
    await v.check(passport(k2));
    expect(n.fetch).toHaveBeenCalledTimes(1);
    n.keys.push(k2);
    now += 61_000;
    expect((await v.check(passport(k2, { iat: now / 1000, exp: now / 1000 + 60 }))).status).toBe('verified');
    expect(n.fetch).toHaveBeenCalledTimes(2);
  });

  it('refreshes after an hour and keeps a stale key when the refetch fails', async () => {
    const v = verifier();
    await v.check(passport(key));
    now += 61 * 60_000;
    n.fetch.mockImplementationOnce(async () => {
      throw new Error('down');
    });
    const r = await v.check(passport(key, { iat: now / 1000, exp: now / 1000 + 60 }));
    expect(r.status).toBe('verified');
    expect(n.fetch).toHaveBeenCalledTimes(2);
  });

  it('refuses a JWK that is not an Ed25519 public key', async () => {
    n.keys = [{ ...key, jwk: { ...key.jwk, crv: 'X25519' } }];
    expect((await verifier().check(passport(key))).reason).toBe('unknown_key');
  });
});

describe('audience', () => {
  it('matches a host against an origin and back, case-insensitively', async () => {
    expect((await verifier().check(passport(key, { aud: 'https://API.servflo.ai' }))).status).toBe('verified');
    expect((await verifier({ audience: 'https://api.servflo.ai' }).check(passport(key, { aud: 'api.servflo.ai' }))).status).toBe('verified');
    expect((await verifier({ audience: ['mcp.servflo.ai', 'API.SERVFLO.AI'] }).check(passport(key))).status).toBe('verified');
  });

  it('refuses http origins, paths and other ports in the passport', () => {
    expect(audienceMatches('http://api.servflo.ai', ['api.servflo.ai'])).toBe(false);
    expect(audienceMatches('https://api.servflo.ai/x', ['api.servflo.ai'])).toBe(false);
    expect(audienceMatches('https://api.servflo.ai:8443', ['api.servflo.ai'])).toBe(false);
    expect(audienceMatches('https://api.servflo.ai:8443', ['https://api.servflo.ai:8443'])).toBe(true);
    expect(audienceMatches('https://api.servflo.ai:8443', ['api.servflo.ai:8443'])).toBe(true);
    // two origins must be identical
    expect(audienceMatches('https://api.servflo.ai', ['http://api.servflo.ai'])).toBe(false);
    expect(audienceMatches('https://api.servflo.ai', ['https://API.servflo.ai'])).toBe(true);
  });
});

describe('replay', () => {
  it('accepts a passport once', async () => {
    const v = verifier();
    const token = passport(key);
    expect((await v.check(token)).status).toBe('verified');
    expect(await v.check(token)).toMatchObject({ status: 'invalid', reason: 'replayed', decision: 'deny' });
  });

  it('uses a pluggable store and remembers until exp + skew', async () => {
    const seen = jest.fn(async () => false);
    await verifier({ replay: { seen } }).check(passport(key));
    expect(seen).toHaveBeenCalledWith(expect.any(String), (T0 / 1000 + 120 + 60) * 1000);
  });

  it('denies when the store fails', async () => {
    const store: ReplayStore = { seen: async () => { throw new Error('redis down'); } };
    expect((await verifier({ replay: store }).check(passport(key))).reason).toBe('replay_check_failed');
  });

  it('the memory store forgets expired ids and keeps under its cap', async () => {
    let t = 0;
    const s = new MemoryReplayStore({ maxEntries: 3, clock: () => t });
    expect(await s.seen('a', 10)).toBe(false);
    expect(await s.seen('a', 10)).toBe(true);
    t = 11;
    expect(await s.seen('a', 20)).toBe(false);
    await s.seen('b', 100);
    await s.seen('c', 100);
    await s.seen('d', 100);
    expect(s.size).toBeLessThanOrEqual(3);
  });

  it('does not record a passport that failed earlier steps', async () => {
    const seen = jest.fn(async () => false);
    await verifier({ replay: { seen } }).check(passport(key, { aud: 'elsewhere.ai' }));
    expect(seen).not.toHaveBeenCalled();
  });
});

describe('online check', () => {
  it('posts the passport and audience and accepts a valid answer', async () => {
    n.verify = () => json({ valid: true });
    const token = passport(key);
    const r = await verifier().check(token, { online: true });
    expect(r.status).toBe('verified');
    const call = n.fetch.mock.calls.find((c) => String(c[0]).endsWith('/verify'));
    expect(JSON.parse(call[1].body)).toEqual({ passport: token, audience: 'api.servflo.ai' });
  });

  it.each(['revoked', 'unknown_passport'])('invalid with %s', async (reason) => {
    n.verify = () => json({ valid: false, reason });
    expect((await verifier().check(passport(key), { online: true })).reason).toBe(reason);
  });

  it('runs when the policy says online', async () => {
    n.verify = () => json({ valid: false, reason: 'revoked' });
    expect((await verifier({ policy: { online: true } }).check(passport(key))).reason).toBe('revoked');
  });

  it('an unreachable issuer does not deny by default', async () => {
    const r = await verifier().check(passport(key), { online: true });
    expect(r).toMatchObject({ status: 'verified', decision: 'allow', reason: 'issuer_unreachable' });
  });

  it('a 429 from the issuer is issuer_unreachable even with a valid-looking body', async () => {
    n.verify = () => json({ valid: false, reason: 'revoked' }, 429);
    expect((await verifier().check(passport(key), { online: true })).reason).toBe('issuer_unreachable');
  });

  it('an unreachable issuer denies when onlineFailure is deny', async () => {
    n.verify = () => new Response('busy', { status: 503 });
    const r = await verifier({ onlineFailure: 'deny' }).check(passport(key), { online: true });
    expect(r).toMatchObject({ status: 'invalid', decision: 'deny', reason: 'issuer_unreachable' });
  });
});

describe('receiver policy', () => {
  it('observe never blocks; enforce blocks what it denies', async () => {
    const o = await verifier({ policy: { operators: ['other.com'] } }).check(passport(key));
    expect(o).toMatchObject({ status: 'verified', decision: 'deny', blocked: false, reason: 'operator_not_allowed' });
    const e = await verifier({ policy: { operators: ['other.com'], mode: 'enforce' } }).check(passport(key));
    expect(e).toMatchObject({ decision: 'deny', blocked: true });
  });

  it('requireAgent denies a call without a passport', async () => {
    expect(await verifier().check({})).toMatchObject({ status: 'absent', decision: 'allow', blocked: false, reason: 'absent', scopes: [] });
    expect(await verifier({ policy: { requireAgent: true, mode: 'enforce' } }).check({})).toMatchObject({ status: 'absent', decision: 'deny', blocked: true });
  });

  it('allows operators by id or by domain', async () => {
    expect((await verifier({ policy: { operators: ['org_1'] } }).check(passport(key))).decision).toBe('allow');
    expect((await verifier({ policy: { operators: ['ACME.com'] } }).check(passport(key))).decision).toBe('allow');
    const noDomain = passport(key, { operator: { id: 'org_9', name: 'N', domain: null } });
    expect((await verifier({ policy: { operators: ['acme.com'] } }).check(noDomain)).reason).toBe('operator_not_allowed');
  });

  it('requireOnBehalfOf needs act', async () => {
    const v = verifier({ policy: { requireOnBehalfOf: true } });
    expect((await v.check(passport(key))).reason).toBe('on_behalf_of_required');
    expect((await v.check(passport(key, { act: { sub: 'p', domain: 'acme.com' } }))).decision).toBe('allow');
  });
});

describe('policyFrom', () => {
  const remote = { mode: 'enforce', requireAgent: true, operators: ['org_1'], requireOnBehalfOf: false, online: false, minAssurance: 'named' };

  it('follows the console policy, sends the API key as a bearer token and caches 60 s', async () => {
    n.policy = () => json(remote);
    const v = verifier({ policyFrom: { apiKey: 'sk-test', baseUrl: 'https://console.example/' } });
    expect(await v.policy()).toEqual(remote);
    await v.policy();
    const calls = n.fetch.mock.calls.filter((c) => String(c[0]).includes('/policy'));
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe('https://console.example/api/inbound-agents/policy');
    expect(calls[0][1].headers.Authorization).toBe('Bearer sk-test');
    now += 61_000;
    await v.policy();
    await new Promise((r) => setImmediate(r));
    expect(n.fetch.mock.calls.filter((c) => String(c[0]).includes('/policy'))).toHaveLength(2);
  });

  it('accepts { policy: {...} } and lets the local policy override fields', async () => {
    n.policy = () => json({ policy: remote });
    const v = verifier({ policyFrom: { apiKey: 'k' }, policy: { mode: 'observe' } });
    expect(await v.policy()).toEqual({ ...remote, mode: 'observe' });
  });

  it('keeps the last good policy on failure, and the defaults when there never was one', async () => {
    n.policy = () => json(remote);
    const v = verifier({ policyFrom: { apiKey: 'k' } });
    await v.policy();
    n.policy = () => json({ error: 'x' }, 500);
    now += 61_000;
    await v.policy();
    await new Promise((r) => setImmediate(r));
    expect(await v.policy()).toEqual(remote);

    n.policy = () => {
      throw new Error('down');
    };
    expect(await verifier({ policyFrom: { apiKey: 'k' }, policy: { operators: ['x'] } }).policy()).toEqual({
      mode: 'observe',
      requireAgent: false,
      operators: ['x'],
      requireOnBehalfOf: false,
      online: false,
      minAssurance: 'none',
    });
  });

  it('ignores ill-typed fields', async () => {
    n.policy = () => json({ mode: 'block-all', requireAgent: 'yes', operators: [1, 'ok'], minAssurance: 'high' });
    expect(await verifier({ policyFrom: { apiKey: 'k' } }).policy()).toMatchObject({ mode: 'observe', requireAgent: false, operators: ['ok'], minAssurance: 'none' });
  });
});

describe('report', () => {
  it('batches results to the decision log without the passport', async () => {
    const v = verifier({ report: { apiKey: 'rk', baseUrl: 'https://console.example' } });
    const token = passport(key);
    await v.check(token, { route: '/v1/jobs', method: 'post' });
    await v.check('bad', { route: '/v1/jobs' });
    await v.check({}); // absent and allowed: not reported
    await v.flush();
    expect(n.decisions).toHaveLength(1);
    const [a, b] = n.decisions[0];
    expect(a).toMatchObject({ status: 'verified', route: '/v1/jobs', method: 'POST', receiver: 'api.servflo.ai', at: new Date(T0).toISOString() });
    expect(b).toMatchObject({ status: 'invalid', reason: 'malformed' });
    expect(JSON.stringify(n.decisions)).not.toContain(token);
    const call = n.fetch.mock.calls.find((c) => String(c[0]).endsWith('/decisions'));
    expect(call[0]).toBe('https://console.example/api/inbound-agents/decisions');
    expect(call[1].headers.Authorization).toBe('Bearer rk');
    await v.close();
  });

  it('sends at most 100 per call and flushes at 100', async () => {
    const v = verifier({ report: { apiKey: 'rk' } });
    for (let i = 0; i < 250; i++) await v.check('bad');
    await v.flush();
    expect(n.decisions.map((d) => d.length)).toEqual([100, 100, 50]);
    await v.close();
  });

  it('never throws into the caller when delivery fails', async () => {
    n.decisionStatus = 401;
    const v = verifier({ report: { apiKey: 'rk' } });
    await expect(v.check('bad')).resolves.toMatchObject({ status: 'invalid' });
    await expect(v.flush()).resolves.toBeUndefined();
    expect(console.warn).toHaveBeenCalled();
    await v.close();
  });
});

describe('inputs', () => {
  it('reads a Fetch Request, Headers, a record, an IncomingMessage and an Express-style req', async () => {
    const v = verifier();
    const results: AgentCheck[] = [];
    results.push(await v.check(new Request('https://api.servflo.ai/x', { headers: { [AGENT_HEADER]: passport(key) } })));
    results.push(await v.check(new Headers({ 'shield360-agent': passport(key) })));
    results.push(await v.check({ 'SHIELD360-AGENT': passport(key) }));
    const msg = new IncomingMessage(new Socket());
    msg.headers['shield360-agent'] = passport(key);
    results.push(await v.check(msg));
    const token = passport(key);
    results.push(await v.check({ headers: {}, get: (name: string) => (name.toLowerCase() === 'shield360-agent' ? token : undefined) }));
    expect(results.map((r) => r.status)).toEqual(['verified', 'verified', 'verified', 'verified', 'verified']);
  });

  it('two passports in one call are malformed', async () => {
    expect((await verifier().check({ 'shield360-agent': [passport(key), passport(key)] })).reason).toBe('malformed');
    expect((await verifier().check(new Headers([[AGENT_HEADER, passport(key)], [AGENT_HEADER, passport(key)]]))).reason).toBe('malformed');
  });
});

describe('middleware', () => {
  function run(v: ReturnType<typeof verifier>, headers: Record<string, string>) {
    const req: any = { method: 'GET', url: '/v1/jobs?token=secret', headers };
    const res: any = { statusCode: 200, headers: {} as Record<string, string>, body: '', setHeader(k: string, val: string) { this.headers[k] = val; }, end(b: string) { this.body = b; } };
    return new Promise<{ req: any; res: any; nextCalled: boolean }>((resolve) => {
      v.middleware()(req, res, () => {
        clearInterval(t);
        resolve({ req, res, nextCalled: true });
      });
      const t: ReturnType<typeof setInterval> = setInterval(() => {
        if (res.body) {
          clearInterval(t);
          resolve({ req, res, nextCalled: false });
        }
      }, 1);
    });
  }

  it('sets req.shield360Agent and calls next', async () => {
    const { req, nextCalled } = await run(verifier(), { 'shield360-agent': passport(key) });
    expect(nextCalled).toBe(true);
    expect(req.shield360Agent.status).toBe('verified');
  });

  it('observe passes a bad passport through', async () => {
    const { req, nextCalled } = await run(verifier(), { 'shield360-agent': 'bad' });
    expect(nextCalled).toBe(true);
    expect(req.shield360Agent).toMatchObject({ decision: 'deny', blocked: false });
  });

  it('answers 403 JSON when blocked', async () => {
    const { res, nextCalled } = await run(verifier({ policy: { mode: 'enforce', requireAgent: true } }), {});
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.headers['Content-Type']).toContain('application/json');
    expect(JSON.parse(res.body)).toEqual({ error: 'agent_not_allowed', reason: 'absent' });
  });

  it('reports the path without the query', async () => {
    const v = verifier({ report: { apiKey: 'rk' } });
    await run(v, { 'shield360-agent': 'bad' });
    await v.flush();
    expect(n.decisions[0][0].route).toBe('/v1/jobs');
    await v.close();
  });
});

describe('parsePassport', () => {
  it('rejects a 63-byte signature', () => {
    const [h, p] = passport(key).split('.');
    expect(parsePassport(`${h}.${p}.${Buffer.alloc(63).toString('base64url')}`)).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('assurance, mandates and the agent profile', () => {
  const act = (over: Record<string, unknown> = {}) => ({ sub: 'pairwise0123456789abcd', domain: 'acme.com', ...over });
  const mandate = { id: 'm1', expiresAt: '2026-11-28T12:00:00.000Z' };

  it('passes the new claims through', async () => {
    const agent = {
      id: 'a1',
      name: 'Dispatch bot',
      status: 'enrolled',
      environment: 'production',
      risk: 'low',
      owner: { domain: 'acme.com' },
      reviewedAt: '2026-10-01T00:00:00.000Z',
      enrolledAt: null,
    };
    const r = await verifier().check(passport(key, { agent, act: act({ assurance: 'delegated', mandate }) }));
    expect(r.status).toBe('verified');
    expect(r.agent).toEqual(agent);
    expect(r.onBehalfOf).toEqual({ id: 'pairwise0123456789abcd', domain: 'acme.com', assurance: 'delegated', mandate });
  });

  it('treats act without assurance as named and an unknown assurance as unverified', async () => {
    expect((await verifier().check(passport(key, { act: act() }))).onBehalfOf?.assurance).toBe('named');
    expect((await verifier().check(passport(key, { act: act({ assurance: 'super' }) }))).onBehalfOf?.assurance).toBe('unverified');
  });

  it('drops ill-typed optional fields instead of failing', async () => {
    const r = await verifier().check(
      passport(key, { agent: { id: 'a1', name: 'B', status: 'weird', risk: 5, owner: 'x' }, act: act({ mandate: { id: 1 } }) }),
    );
    expect(r.status).toBe('verified');
    expect(r.agent).toEqual({ id: 'a1', name: 'B' });
    expect(r.onBehalfOf?.mandate).toBeUndefined();
  });

  it.each([
    ['none', undefined, 'allow'],
    ['unverified', undefined, 'deny'],
    ['unverified', 'unverified', 'allow'],
    ['named', 'unverified', 'deny'],
    ['named', null, 'allow'], // act without assurance is named
    ['named', 'named', 'allow'],
    ['delegated', 'named', 'deny'],
    ['delegated', 'delegated', 'allow'],
  ] as const)('minAssurance %s with act assurance %s: %s', async (minAssurance, assurance, decision) => {
    const claimsOver = assurance === undefined ? {} : { act: act(assurance === null ? {} : { assurance }) };
    const r = await verifier({ policy: { minAssurance, mode: 'enforce' } }).check(passport(key, claimsOver));
    expect(r.decision).toBe(decision);
    if (decision === 'deny') expect(r).toMatchObject({ reason: 'assurance_too_low', blocked: true, status: 'verified' });
  });

  it('keeps requireOnBehalfOf working alongside minAssurance', async () => {
    const r = await verifier({ policy: { requireOnBehalfOf: true, minAssurance: 'delegated' } }).check(passport(key));
    expect(r.reason).toBe('on_behalf_of_required');
    const ok = await verifier({ policy: { requireOnBehalfOf: true } }).check(passport(key, { act: act({ assurance: 'unverified' }) }));
    expect(ok.decision).toBe('allow');
  });

  it('lowers the assurance when the issuer says so online, and the policy sees the lower one', async () => {
    n.verify = () => json({ valid: true, assurance: 'named', reason: 'mandate_revoked' });
    const token = () => passport(key, { act: act({ assurance: 'delegated', mandate }) });
    const r = await verifier().check(token(), { online: true });
    expect(r).toMatchObject({ status: 'verified', decision: 'allow', reason: 'mandate_revoked', onBehalfOf: { assurance: 'named' } });
    expect(r.onBehalfOf?.mandate).toBeUndefined();
    const d = await verifier({ policy: { minAssurance: 'delegated' } }).check(token(), { online: true });
    expect(d).toMatchObject({ decision: 'deny', reason: 'assurance_too_low' });
  });

  it('never raises the assurance online', async () => {
    n.verify = () => json({ valid: true, assurance: 'delegated' });
    const r = await verifier().check(passport(key, { act: act({ assurance: 'unverified' }) }), { online: true });
    expect(r.onBehalfOf?.assurance).toBe('unverified');
  });

  it('reports the new fields', async () => {
    const v = verifier({ report: { apiKey: 'rk' } });
    await v.check(passport(key, { agent: { id: 'a1', name: 'B', risk: 'high' }, act: act({ assurance: 'delegated', mandate }) }));
    await v.flush();
    expect(n.decisions[0][0]).toMatchObject({ agent: { risk: 'high' }, onBehalfOf: { assurance: 'delegated', mandate } });
    await v.close();
  });
});

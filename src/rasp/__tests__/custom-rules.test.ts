/**
 * Custom rules in the SDK (README "Custom rules"): rules arrive inside the
 * signed config, invalid ones are skipped with one warning and never break
 * the config, request rules run with the request's capture, finding rules
 * when a built-in check fires, the custom_rule mode caps every action, and
 * evaluation fails open.
 */
import { generateKeyPairSync, sign } from 'crypto';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { captureBody, captureRequest, runVirtualPatches } from '../capture';
import { JWS_TYPE, type RaspClaims } from '../config-client';
import { storage } from '../context';
import { parseCustomRules, requestSubject, resetCustomRuleWarnings } from '../custom-rules';
import { configureEngine, customRules, handleFinding, modeFor, setEventSink, setRemoteConfig, type RemoteConfig } from '../engine';
import { initRasp, shutdownRasp } from '../index';
import { raspHttp } from '../middleware';
import { RaspBlockedError } from '../types';

type Event = { name: string; time: string; attrs: Record<string, string> };

const rule = (over: Record<string, unknown> = {}) => ({ id: 'r1', name: 'Rule one', expression: 'request.path.startsWith("/admin")', action: 'monitor', enabled: true, ...over });

function remote(customRules: unknown[] | null, attacks: RemoteConfig['attacks'] = {}): RemoteConfig {
  return { version: 'v1', exp: Math.floor(Date.now() / 1000) + 3600, killSwitch: false, snippets: false, mode: 'monitor', attacks, rules: [], customRules };
}

let events: Event[] = [];
let warn: jest.SpyInstance;

beforeEach(() => {
  resetCustomRuleWarnings();
  events = [];
  warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
  setEventSink({ add: (e) => events.push(e) });
});

afterEach(() => {
  warn.mockRestore();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

const request = (url: string, extra: Partial<Parameters<typeof captureRequest>[0]> = {}) =>
  captureRequest({ framework: 'test', method: 'GET', url, headers: { 'user-agent': 'curl/8.4', host: 'a' }, ip: '::ffff:10.1.2.3', ...extra });

describe('parseCustomRules', () => {
  it('keeps valid, enabled rules for this app, in order', () => {
    const rules = parseCustomRules([rule(), rule({ id: 'r2', apps: ['orders-api', 'billing'] }), rule({ id: 'r3', apps: ['billing'] }), rule({ id: 'r4', enabled: false })], 'orders-api');
    expect(rules.map((r) => r.id)).toEqual(['r1', 'r2']);
    expect(warn).not.toHaveBeenCalled();
  });

  it('skips each invalid rule with one warning, and never warns twice for it', () => {
    const raw = [
      rule({ id: 'Bad Id' }),
      rule({ id: 'ok-1' }),
      rule({ id: 'ok-1' }),
      rule({ id: 'x2', action: 'allow' }),
      rule({ id: 'x3', enabled: 'yes' }),
      rule({ id: 'x4', expression: 'request.method = "GET"' }),
      rule({ id: 'x5', apps: 'orders-api' }),
      rule({ id: 'x6', name: 7 }),
      null,
      'rule',
    ];
    expect(parseCustomRules(raw, 'orders-api').map((r) => r.id)).toEqual(['ok-1']);
    expect(warn).toHaveBeenCalledTimes(9);
    expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain('expression: syntax');
    parseCustomRules(raw, 'orders-api');
    expect(warn).toHaveBeenCalledTimes(9);
  });

  it('keeps at most 64', () => {
    const many = Array.from({ length: 70 }, (_, i) => rule({ id: `r${i}` }));
    expect(parseCustomRules(many, 'a')).toHaveLength(64);
  });

  it('is empty for anything but a list', () => {
    for (const v of [null, undefined, {}, 'x']) expect(parseCustomRules(v, 'a')).toEqual([]);
  });
});

describe('request subject', () => {
  it('reads the request as the language sees it', () => {
    const ctx = request('/api/orders/42?id=42&id=43&q=%252e%252e', { method: 'post', headers: { 'User-Agent': 'curl/8.4', 'x-multi': ['a', 'b'] } });
    captureBody(ctx, { body: { user: { role: 'admin' } }, contentType: 'application/json' });
    const s = requestSubject(ctx, 'orders-api');
    expect(s.request).toMatchObject({ method: 'POST', path: '/api/orders/42', route: '/api/orders/:id', ip: '::ffff:10.1.2.3', query: { id: '42', q: '%2e%2e' }, body: { 'user.role': 'admin' } });
    expect(s.request?.headers).toMatchObject({ 'user-agent': 'curl/8.4', 'x-multi': 'a, b' });
    expect(s.inputs?.some((i) => i.key === 'query.q' && i.value === '..')).toBe(true);
  });
});

describe('request rules', () => {
  it('report a match as a custom_rule event and let the request through in monitor', () => {
    setRemoteConfig(remote([rule({ action: 'alert' })]));
    const ctx = request('/admin/users');
    runVirtualPatches(ctx);
    expect(events).toHaveLength(1);
    expect(events[0].attrs).toMatchObject({
      'shield360.rasp.attack': 'custom_rule',
      'shield360.rasp.rule': 'custom.r1',
      'shield360.rasp.decision': 'monitored',
      'shield360.rasp.sink': 'server.request',
      'shield360.rasp.route': '/admin/users',
      'shield360.rasp.config_version': 'v1',
    });
  });

  it('block only when the rule says block and the custom_rule mode is block', () => {
    setRemoteConfig(remote([rule({ action: 'block' })]));
    expect(() => runVirtualPatches(request('/admin'))).not.toThrow();
    expect(events[0].attrs['shield360.rasp.decision']).toBe('monitored');

    setRemoteConfig(remote([rule({ action: 'monitor' })], { custom_rule: 'block' }));
    expect(() => runVirtualPatches(request('/admin'))).not.toThrow();

    setRemoteConfig(remote([rule({ action: 'block' })], { custom_rule: 'block' }));
    expect(() => runVirtualPatches(request('/admin'))).toThrow(RaspBlockedError);
    try {
      runVirtualPatches(request('/admin'));
    } catch (e) {
      expect(e).toMatchObject({ attack: 'custom_rule', rule: 'custom.r1' });
    }

    setRemoteConfig(remote([rule({ action: 'block' })], { custom_rule: 'off' }));
    events = [];
    runVirtualPatches(request('/admin'));
    expect(events).toEqual([]);
  });

  it('match each rule once per request; input rules run again when the body arrives', () => {
    setRemoteConfig(
      remote([
        rule({ id: 'path', expression: 'request.path == "/upload"' }),
        rule({ id: 'traversal', expression: 'input.value.contains("../")' }),
        rule({ id: 'role', expression: 'request.body["role"] == "admin"' }),
        rule({ id: 'ip', expression: 'request.ip.inCidr("10.0.0.0/8") && request.headers["user-agent"].startsWith("curl/")' }),
      ]),
    );
    const ctx = request('/upload', { method: 'POST' });
    runVirtualPatches(ctx);
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['custom.path', 'custom.ip']);
    captureBody(ctx, { body: { role: 'admin', file: '../../etc/passwd' }, contentType: 'application/json' });
    runVirtualPatches(ctx);
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['custom.path', 'custom.ip', 'custom.traversal', 'custom.role']);
    expect(events[2].attrs['shield360.rasp.input_key']).toBe('body.file');
  });

  it('stop at the first rule that blocks', () => {
    setRemoteConfig(remote([rule({ id: 'a', action: 'block' }), rule({ id: 'b' })], { custom_rule: 'block' }));
    expect(() => runVirtualPatches(request('/admin'))).toThrow(RaspBlockedError);
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['custom.a']);
  });

  it('fail open when the work budget runs out', () => {
    setRemoteConfig(remote([rule({ expression: 'input.value.matches("a{100}x")', action: 'block' })], { custom_rule: 'block' }));
    const ctx = request(`/x?${Array.from({ length: 200 }, (_, i) => `k${i}=${'a'.repeat(4096)}`).join('&')}`);
    expect(() => runVirtualPatches(ctx)).not.toThrow();
    expect(events).toEqual([]);
  });

  it('do nothing while RASP is off', () => {
    setRemoteConfig(remote([rule({ action: 'block' })], { custom_rule: 'block' }));
    configureEngine({ enabled: false, applicationName: 'orders-api', env: {} });
    expect(() => runVirtualPatches(request('/admin'))).not.toThrow();
    expect(events).toEqual([]);
  });

  it('block through the middleware with the contract 403', async () => {
    setRemoteConfig(remote([rule({ expression: 'request.headers["x-debug"] == "1"', action: 'block' })], { custom_rule: 'block' }));
    let body = '';
    let status = 0;
    const res = { statusCode: 0, headersSent: false, writableEnded: false, setHeader: () => undefined, end: (b: string) => ((body = b), (status = res.statusCode)) } as any;
    const handler = jest.fn();
    raspHttp(handler)({ method: 'GET', url: '/a', headers: { 'x-debug': '1' }, socket: { remoteAddress: '127.0.0.1' } } as any, res);
    expect(handler).not.toHaveBeenCalled();
    expect(status).toBe(403);
    expect(JSON.parse(body)).toMatchObject({ attack: 'custom_rule', rule: 'custom.r1' });
  });
});

describe('mode off', () => {
  it('skips custom rules: nothing is evaluated, no budget is spent', () => {
    for (const local of [false, true]) {
      configureEngine({ enabled: true, applicationName: 'orders-api', env: {}, ...(local ? { attacks: { custom_rule: 'off' } } : {}) });
      setEventSink({ add: (e) => events.push(e) });
      events = [];
      setRemoteConfig(
        remote(
          [
            rule({ id: 'req', expression: 'input.value.matches("a+b")', action: 'block' }),
            rule({ id: 'fnd', expression: 'attack.type != null && input.value.matches("a+b")', action: 'block' }),
          ],
          { custom_rule: local ? 'block' : 'off' },
        ),
      );
      const ctx = request(`/x?q=${'a'.repeat(4000)}`);
      runVirtualPatches(ctx);
      storage.run(ctx, () => handleFinding({ attack: 'sql_injection', rule: 'sqli.userinput' }, 'pg.query'));
      expect([local, ctx.rules]).toEqual([local, undefined]);
      expect(events.filter((e) => e.attrs['shield360.rasp.attack'] === 'custom_rule')).toEqual([]);
    }
  });
});

describe('finding rules', () => {
  const sqli = { attack: 'sql_injection' as const, rule: 'sqli.userinput', input: { value: '1 OR 1=1', key: 'query.q', source: 'request' as const } };

  it('see the built-in finding, its sink and the request', () => {
    setRemoteConfig(remote([rule({ id: 'admin-sqli', expression: 'attack.type == "sql_injection" && sink.name == "pg.query" && request.path.startsWith("/admin")', action: 'alert' })]));
    const ctx = request('/admin/search?q=1%20OR%201%3D1');
    storage.run(ctx, () => handleFinding(sqli, 'pg.query'));
    expect(events.map((e) => [e.attrs['shield360.rasp.attack'], e.attrs['shield360.rasp.rule'], e.attrs['shield360.rasp.sink']])).toEqual([
      ['sql_injection', 'sqli.userinput', 'pg.query'],
      ['custom_rule', 'custom.admin-sqli', 'pg.query'],
    ]);
    expect(events[1].attrs['shield360.rasp.input_key']).toBe('query.q');
  });

  it('never run in the request phase, and request rules never run on findings', () => {
    setRemoteConfig(remote([rule({ id: 'f', expression: 'attack.type != null' }), rule({ id: 'q', expression: 'request.path == "/a"' })]));
    const ctx = request('/a');
    runVirtualPatches(ctx);
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['custom.q']);
    events = [];
    storage.run(ctx, () => handleFinding(sqli, 'pg.query'));
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['sqli.userinput', 'custom.f']);
  });

  it('can block a finding the attack type only monitors; the built-in block wins when both block', () => {
    setRemoteConfig(remote([rule({ id: 'stop', expression: 'attack.type == "sql_injection"', action: 'block' })], { custom_rule: 'block' }));
    expect(() => storage.run(request('/a'), () => handleFinding(sqli, 'pg.query'))).toThrow(expect.objectContaining({ attack: 'custom_rule' }));
    setRemoteConfig(remote([rule({ id: 'stop', expression: 'attack.type == "sql_injection"', action: 'block' })], { custom_rule: 'block', sql_injection: 'block' }));
    expect(() => storage.run(request('/a'), () => handleFinding(sqli, 'pg.query'))).toThrow(expect.objectContaining({ attack: 'sql_injection' }));
  });

  it('skip attack types that are off', () => {
    setRemoteConfig(remote([rule({ expression: 'attack.type == "sql_injection"' })], { sql_injection: 'off' }));
    expect(modeFor('sql_injection')).toBe('off');
    storage.run(request('/a'), () => handleFinding(sqli, 'pg.query'));
    expect(events).toEqual([]);
  });

  it('run outside a request with the request fields null', () => {
    setRemoteConfig(remote([rule({ expression: 'request.path == null && app.name == "orders-api" && attack.type == "sql_injection"' })]));
    handleFinding(sqli, 'pg.query');
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['sqli.userinput', 'custom.r1']);
  });
});

describe('signed config round trip', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'k1' };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jws = (c: RaspClaims) => {
    const head = b64({ alg: 'EdDSA', typ: JWS_TYPE, kid: 'k1' });
    const body = b64(c);
    return `${head}.${body}.${sign(null, Buffer.from(`${head}.${body}`), privateKey).toString('base64url')}`;
  };

  afterEach(async () => {
    await shutdownRasp();
  });

  it('applies the signed rules; an invalid rule is skipped with one warning and the rest of the config holds', async () => {
    const claims: RaspClaims = {
      v: 1,
      app: 'orders-api',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
      version: 'cfg-1',
      mode: 'monitor',
      attacks: { ssrf: 'block', custom_rule: 'block' },
      rules: null,
      customRules: [rule({ action: 'block' }), rule({ id: 'broken', expression: 'request.path.matches("(a+)+")' })],
    };
    const fetchImpl = (async (url: string) =>
      String(url).includes('/api/rasp/config') ? new Response(JSON.stringify({ config: jws(claims) }), { status: 200 }) : new Response('{}')) as unknown as typeof fetch;
    const dir = mkdtempSync(join(tmpdir(), 'rasp-rules-'));
    try {
      initRasp({ enabled: true, configPublicKey: jwk as any, components: false, cacheDir: dir }, { applicationName: 'orders-api', url: 'https://s.example.com', apiKey: 'k', env: {}, fetchImpl });
      for (let i = 0; i < 50 && !customRules().length; i++) await new Promise((r) => setTimeout(r, 10));
      expect(customRules().map((r) => r.id)).toEqual(['r1']);
      expect(modeFor('ssrf')).toBe('block');
      expect(warn.mock.calls.filter((c) => String(c[0]).includes('custom rule')).map((c) => String(c[0]))).toEqual([expect.stringContaining('"broken"')]);
      expect(() => runVirtualPatches(request('/admin'))).toThrow(RaspBlockedError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a tampered rule fails the signature and the rules are not applied', async () => {
    const claims: RaspClaims = { v: 1, app: 'orders-api', exp: Math.floor(Date.now() / 1000) + 600, version: 'cfg-2', customRules: [rule()] };
    const token = jws(claims).split('.');
    token[1] = b64({ ...claims, customRules: [rule({ expression: 'true', action: 'block' })] });
    const fetchImpl = (async (url: string) =>
      String(url).includes('/api/rasp/config') ? new Response(JSON.stringify({ config: token.join('.') }), { status: 200 }) : new Response('{}')) as unknown as typeof fetch;
    const dir = mkdtempSync(join(tmpdir(), 'rasp-rules-'));
    try {
      initRasp({ enabled: true, configPublicKey: jwk as any, components: false, cacheDir: dir }, { applicationName: 'orders-api', url: 'https://s.example.com', apiKey: 'k', env: {}, fetchImpl });
      await new Promise((r) => setTimeout(r, 100));
      expect(customRules()).toEqual([]);
      expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain('signature');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

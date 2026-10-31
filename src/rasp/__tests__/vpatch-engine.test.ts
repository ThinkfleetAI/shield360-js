/**
 * Virtual patches: each built-in rule matches a request built from the shape
 * its own rule file documents (no new payloads), and stops matching when one
 * clause is missing. Then the engine: modes, caps, kill switches, events.
 */
import { currentContext, routeOf, storage, newContext } from '../context';
import {
  check,
  configureEngine,
  handleFinding,
  isActive,
  modeFor,
  setEventSink,
  setRemoteConfig,
  setRuntimeDisabled,
  virtualPatches,
  maskSnippet,
  type RemoteConfig,
} from '../engine';
import { RaspBlockedError, type Finding } from '../types';
import { BUILT_IN_RULES, matchVirtualPatches, needsBody, ruleApplies, clauseMatches, type MatchClause, type VirtualPatch, type VpRequest } from '../vpatch';
import { requestFor } from './corpus';

/** The same request without what one clause needs. */
function without(rule: VirtualPatch, i: number): VpRequest {
  return requestFor({ ...rule, match: rule.match.filter((_, k) => k !== i) });
}

const versionIn = (rule: VirtualPatch) => rule.runtimeVersions?.node?.[0]?.[0] ?? process.versions.node;

describe('virtual patches', () => {
  it.each(BUILT_IN_RULES.map((r) => [r.id, r]))('%s matches its documented request shape', (_id, rule) => {
    const f = matchVirtualPatches(requestFor(rule), [rule], 'all', 'node', versionIn(rule));
    expect(f).toMatchObject({ attack: 'virtual_patch', rule: rule.id, action: rule.action ?? 'block' });
    if (rule.cves?.length) expect(f?.cve).toBe(rule.cves[0]);
  });

  it.each(BUILT_IN_RULES.map((r) => [r.id, r]))('%s needs every clause', (_id, rule) => {
    rule.match.forEach((c: MatchClause, i: number) => {
      const req = without(rule, i);
      // A clause on a target the remaining clauses also fill can still be met; only check clauses that are not.
      if (clauseMatches(req, c)) return;
      expect(matchVirtualPatches(req, [rule], 'all', 'node', versionIn(rule))).toBeNull();
    });
  });

  it('runtimeVersions: [from, to) ranges; other runtimes skip node rules', () => {
    const rule = BUILT_IN_RULES.find((r) => r.runtimeVersions?.node)!;
    const [from, to] = rule.runtimeVersions!.node[0];
    expect(ruleApplies(rule, 'node', from)).toBe(true);
    expect(ruleApplies(rule, 'node', to)).toBe(false);
    expect(ruleApplies(rule, 'python', from)).toBe(false);
  });

  it('phases: head rules never read the body; body rules wait for it', () => {
    const bodyRule = BUILT_IN_RULES.find(needsBody)!;
    const req = requestFor(bodyRule);
    expect(matchVirtualPatches(req, [bodyRule], 'head')).toBeNull();
    expect(matchVirtualPatches(req, [bodyRule], 'body', 'node', versionIn(bodyRule))?.rule).toBe(bodyRule.id);
  });

  it('refuses patterns with backreferences or lookaround', () => {
    const req: VpRequest = { method: 'GET', path: '/aa', query: '', headers: {}, cookie: '', body: '' };
    expect(clauseMatches(req, { target: 'path', op: 'regex', value: '^/a+$' })).toBe(true);
    expect(clauseMatches(req, { target: 'path', op: 'regex', value: '(a)\\1' })).toBe(false);
    expect(clauseMatches(req, { target: 'path', op: 'regex', value: 'a(?=a)' })).toBe(false);
  });
});

describe('engine', () => {
  const events: any[] = [];
  const sink = { add: (e: any) => events.push(e) };
  const finding: Finding = { attack: 'sql_injection', rule: 'sqli.userinput', input: { value: 'v', key: 'query.id', source: 'request' } };
  const remote = (over: Partial<RemoteConfig> = {}): RemoteConfig => ({
    version: 'v1',
    exp: Date.now() / 1000 + 3600,
    killSwitch: false,
    snippets: false,
    attacks: {},
    rules: null,
    ...over,
  });

  beforeEach(() => {
    events.length = 0;
    configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
    setEventSink(sink);
  });
  afterAll(() => {
    setEventSink(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  it('monitor by default: reports, never throws', () => {
    expect(handleFinding(finding, 'pg.query')).toBe('monitored');
    expect(events).toHaveLength(1);
    const a = events[0].attrs;
    expect(a['shield360.rasp.event_id']).toMatch(/^[a-f0-9]{32}$/);
    expect(a['shield360.rasp.input_key']).toBe('query.id');
    expect(a['shield360.rasp.config_version']).toBe('local');
    expect(JSON.stringify(events)).not.toContain('"v"');
  });

  it('block mode throws the typed error with the event id', () => {
    configureEngine({ enabled: true, applicationName: 'a', attacks: { sql_injection: 'block' }, env: {} });
    setEventSink(sink);
    let err: unknown;
    try {
      handleFinding(finding, 'pg.query');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RaspBlockedError);
    expect((err as RaspBlockedError).eventId).toBe(events[0].attrs['shield360.rasp.event_id']);
    expect((err as RaspBlockedError).statusCode).toBe(403);
  });

  it('xss never blocks', () => {
    configureEngine({ enabled: true, applicationName: 'a', mode: 'block', env: {} });
    expect(modeFor('xss')).toBe('monitor');
    expect(handleFinding({ attack: 'xss', rule: 'xss.reflected' }, 'http.response')).toBe('monitored');
  });

  it('a virtual patch is capped by its own action and by the virtual_patch mode', () => {
    configureEngine({ enabled: true, applicationName: 'a', attacks: { virtual_patch: 'block' }, env: {} });
    expect(handleFinding({ attack: 'virtual_patch', rule: 'vp.x', action: 'monitor' }, 'server.request')).toBe('monitored');
    configureEngine({ enabled: true, applicationName: 'a', env: {} });
    expect(handleFinding({ attack: 'virtual_patch', rule: 'vp.x', action: 'block' }, 'server.request')).toBe('monitored');
  });

  it('the signed config overrides local modes, except a local off', () => {
    configureEngine({ enabled: true, applicationName: 'a', attacks: { sql_injection: 'monitor', ssrf: 'off' }, env: {} });
    setRemoteConfig(remote({ attacks: { sql_injection: 'block', ssrf: 'block' } }));
    expect(modeFor('sql_injection')).toBe('block');
    expect(modeFor('ssrf')).toBe('off');
    expect(modeFor('xxe')).toBe('monitor');
  });

  it('monitor-only (no pinned key) caps block', () => {
    configureEngine({ enabled: true, applicationName: 'a', mode: 'block', monitorOnly: true, env: {} });
    expect(modeFor('sql_injection')).toBe('monitor');
  });

  it('kill switch order: env off, signed killSwitch, runtime call', () => {
    configureEngine({ enabled: true, applicationName: 'a', env: { SHIELD360_RASP: 'off' } });
    expect(isActive()).toBe(false);
    configureEngine({ enabled: true, applicationName: 'a', env: {} });
    setRemoteConfig(remote({ killSwitch: true }));
    expect(isActive()).toBe(false);
    expect(modeFor('sql_injection')).toBe('off');
    setRemoteConfig(remote());
    setRuntimeDisabled(true);
    expect(isActive()).toBe(false);
    setRuntimeDisabled(false);
    expect(isActive()).toBe(true);
  });

  it('SHIELD360_RASP=block sets the default mode', () => {
    configureEngine({ enabled: true, applicationName: 'a', env: { SHIELD360_RASP: 'block' } });
    expect(modeFor('command_injection')).toBe('block');
  });

  it('the signed config rules replace the built-in list; null keeps it', () => {
    setRemoteConfig(remote({ rules: [{ id: 'vp.only', match: [{ target: 'method', op: 'equals', values: ['GET'] }] }] }));
    expect(virtualPatches().map((r) => r.id)).toEqual(['vp.only']);
    setRemoteConfig(remote({ rules: null }));
    expect(virtualPatches()).toBe(BUILT_IN_RULES);
  });

  it('snippets only with the signed snippets flag, masked and at most 64 characters', () => {
    const secret = `token=${'s'.repeat(30)}`;
    handleFinding({ ...finding, input: { value: secret, key: 'body.t', source: 'request' } }, 'pg.query');
    expect(events[0].attrs['shield360.rasp.snippet']).toBeUndefined();
    setRemoteConfig(remote({ snippets: true }));
    handleFinding({ ...finding, rule: 'sqli.stacked', input: { value: secret, key: 'body.t', source: 'request' } }, 'pg.query');
    expect(events[1].attrs['shield360.rasp.snippet']).toBe('token=***');
    expect(maskSnippet('a'.repeat(200)).length).toBeLessThanOrEqual(64);
  });

  it('events carry the route template or the path with ids replaced, and shaped keys', () => {
    expect(routeOf('/api/orders/12345/items/3f2a9c1e-0b1d-4e6f-8a7b-9c0d1e2f3a4b')).toBe('/api/orders/:id/items/:id');
    storage.run(newContext({ inRequest: true, method: 'get', path: '/api/orders/42', framework: 'express' }), () => {
      expect(currentContext()).toBeDefined();
      handleFinding({ ...finding, input: { value: 'v', key: 'query.a b', source: 'request' } }, 'pg.query');
    });
    const a = events[0].attrs;
    expect(a['shield360.rasp.route']).toBe('/api/orders/:id');
    expect(a['shield360.rasp.method']).toBe('GET');
    expect(a['shield360.rasp.framework']).toBe('express');
    expect(a['shield360.rasp.input_key']).toBe('query.a_b');
  });

  it('check() fails open on detector errors and rethrows only the block error', () => {
    expect(
      check('pg.query', () => {
        throw new Error('detector bug');
      }),
    ).toBeNull();
    configureEngine({ enabled: true, applicationName: 'a', mode: 'block', env: {} });
    expect(() => check('pg.query', () => finding)).toThrow(RaspBlockedError);
  });

  it('inactive: findings are dropped', () => {
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    expect(handleFinding(finding, 'pg.query')).toBeNull();
  });
});

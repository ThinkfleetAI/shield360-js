/**
 * Sink rules: validation, the generic wrapper running the named check, the
 * rule's action capping the decision, rule sets replacing each other, and
 * built-in hooks never wrapped twice. Fake modules only.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import * as detect from '../detect';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { patchPg, unpatchPg } from '../hooks/db';
import { applySinkRule, BUILT_IN_SINKS, parseSinkRule, parseSinkRules, setSinkRules, type SinkRule } from '../hooks/sinks';
import { RaspBlockedError, type RaspInput } from '../types';
import { describeHookContract } from './hook-kit';
import { RASP_DIR } from './corpus';

const input = "' OR '1'='1";
const query = `SELECT * FROM products WHERE name = '${input}'`;
const req = (value: string): RaspInput => ({ value, key: 'query.q', source: 'request' });
const tainted = <T>(fn: () => T, trees: unknown[] = []): T => runWithInputs([req(input)], fn, { inRequest: true, trees });

const rule = (extra: Partial<SinkRule> = {}): SinkRule =>
  parseSinkRule({ id: 'sink.fake.query', module: 'fake-driver', target: 'Connection.prototype.query', check: 'sql', dialect: 'postgres', action: 'block', ...extra })!;

function fakeDriver() {
  const original = jest.fn((..._values: unknown[]) => 'rows');
  class Connection {}
  Object.defineProperty(Connection.prototype, 'query', { value: original, configurable: true, writable: true });
  return { original, exports: { Connection }, Connection: Connection as unknown as { new (): { query: (...a: unknown[]) => unknown }; prototype: any } };
}

const events: { attrs: Record<string, string> }[] = [];
beforeEach(() => {
  events.length = 0;
  configureEngine({ enabled: true, applicationName: 'a', mode: 'block', env: {} });
  setEventSink({ add: (e) => events.push(e) });
});
afterEach(() => {
  setSinkRules([]);
  jest.restoreAllMocks();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

describe('parseSinkRule', () => {
  it('accepts a complete rule and fills defaults', () => {
    expect(parseSinkRule({ id: 'sink.x', module: '@scope/pkg', target: 'default.query', check: 'sql' })).toMatchObject({ arg: 0, action: 'monitor' });
    for (const dialect of ['oracle', 'db2']) expect(parseSinkRule({ id: 'sink.x', module: 'm', target: 'a', check: 'sql', dialect })).toMatchObject({ dialect });
  });

  it.each([
    ['no id', { module: 'm', target: 'a', check: 'sql' }],
    ['an id with a hyphen', { id: 'sink.my-driver.query', module: 'm', target: 'a', check: 'sql' }],
    ['an id too long for the event sink', { id: `s${'x'.repeat(59)}`, module: 'm', target: 'a', check: 'sql' }],
    ['__proto__ in the path', { id: 'x', module: 'm', target: 'a.__proto__.b', check: 'sql' }],
    ['constructor in the path', { id: 'x', module: 'm', target: 'constructor', check: 'sql' }],
    ['too deep a path', { id: 'x', module: 'm', target: 'a.b.c.d.e', check: 'sql' }],
    ['an unknown check', { id: 'x', module: 'm', target: 'a', check: 'eval-anything' }],
    ['deser without a format', { id: 'x', module: 'm', target: 'a', check: 'deser' }],
    ['an action of off', { id: 'x', module: 'm', target: 'a', check: 'sql', action: 'off' }],
    ['another runtime only', { id: 'x', module: 'm', target: 'a', check: 'sql', runtimes: ['python'] }],
    ['a module path with ..', { id: 'x', module: '../m', target: 'a', check: 'sql' }],
    ['a field that is not a name', { id: 'x', module: 'm', target: 'a', check: 'sql', field: 'a.b' }],
  ])('drops %s', (_n, raw) => {
    expect(parseSinkRule(raw)).toBeNull();
  });

  it('keeps the valid rules of a list, at most 64, first id wins', () => {
    const many = Array.from({ length: 70 }, (_, i) => ({ id: `r${i}`, module: 'm', target: 'a', check: 'sql' }));
    expect(parseSinkRules([{ bad: true }, ...many])).toHaveLength(64);
    expect(parseSinkRules([{ id: 'a', module: 'm', target: 'x', check: 'sql' }, { id: 'a', module: 'm', target: 'y', check: 'sql' }])[0].target).toBe('x');
    expect(parseSinkRules('nope')).toEqual([]);
  });

  it('the built-in list is the contract copy and parses', () => {
    const embedded = readFileSync(join(__dirname, '..', 'data', 'default-sinks.json'));
    expect(embedded.equals(readFileSync(join(RASP_DIR, 'rules', 'default-sinks.json')))).toBe(true);
    expect(Array.isArray(BUILT_IN_SINKS)).toBe(true);
  });
});

describe('a rule at work', () => {
  it('blocks when the rule and the attack mode both say block, with the rule as the sink', () => {
    const d = fakeDriver();
    applySinkRule(rule(), d.exports);
    expect(() => tainted(() => new d.Connection().query(query))).toThrow(RaspBlockedError);
    expect(d.original).not.toHaveBeenCalled();
    expect(events[0].attrs['shield360.rasp.sink']).toBe('rule:sink.fake.query');
  });

  it('a monitor rule only reports, even in block mode', () => {
    const d = fakeDriver();
    applySinkRule(rule({ action: 'monitor' }), d.exports);
    expect(tainted(() => new d.Connection().query(query))).toBe('rows');
    expect(events[0].attrs['shield360.rasp.decision']).toBe('monitored');
  });

  it('reads an object argument through field, and passes bound parameters', () => {
    const d = fakeDriver();
    applySinkRule(rule({ field: 'sql' }), d.exports);
    expect(() => tainted(() => new d.Connection().query({ sql: query }))).toThrow(RaspBlockedError);
    expect(tainted(() => new d.Connection().query('SELECT * FROM products WHERE name = $1', [input]))).toBe('rows');
  });

  it('runs the nosql check on the request trees', () => {
    const d = fakeDriver();
    applySinkRule(rule({ check: 'nosql' }), d.exports);
    const body = { name: { $ne: null } };
    expect(() => tainted(() => new d.Connection().query({ name: body.name }), [body])).toThrow(RaspBlockedError);
  });

  it('a new rule set switches the old rules off at once', () => {
    const d = fakeDriver();
    applySinkRule(rule(), d.exports);
    setSinkRules([]);
    expect(tainted(() => new d.Connection().query(query))).toBe('rows');
    expect(d.Connection.prototype.query).toBe(d.original);
  });

  it('never wraps a function a built-in hook already checks', () => {
    class Client {
      query(...v: unknown[]): unknown {
        return v.length;
      }
    }
    patchPg({ Client });
    const wrapped = Client.prototype.query;
    const detector = jest.spyOn(detect, 'detectSql');
    applySinkRule(rule({ module: 'pg', target: 'Client.prototype.query' }), { Client });
    expect(Client.prototype.query).toBe(wrapped);
    expect(() => tainted(() => new Client().query(query))).toThrow(RaspBlockedError);
    expect(detector).toHaveBeenCalledTimes(1);
    unpatchPg({ Client });
  });

  it('a target that does not exist leaves the module alone', () => {
    const d = fakeDriver();
    applySinkRule(rule({ target: 'Missing.prototype.query' }), d.exports);
    expect(d.Connection.prototype.query).toBe(d.original);
  });
});

const contractDriver = fakeDriver();
describeHookContract({
  name: 'sink rule (sql)',
  install: () => {
    applySinkRule(rule(), contractDriver.exports);
    return true;
  },
  uninstall: () => setSinkRules([]),
  replaced: [{ owner: contractDriver.Connection.prototype, key: 'query' }],
  trigger: () => new contractDriver.Connection().query(query),
  inputs: [req(input)],
  detector: { module: detect, name: 'detectSql' },
  attack: 'sql_injection',
});

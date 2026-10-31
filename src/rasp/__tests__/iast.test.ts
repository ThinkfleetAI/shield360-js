/**
 * Passive IAST (README "Passive IAST"): the shared conformance corpus
 * (sdk/rasp/testdata/iast.json), the thresholds, and how the engine arms,
 * samples, dedupes and reports vulnerabilities without ever blocking.
 */
import * as fs from 'fs';
import { runWithInputs } from '../context';
import { check, configureEngine, setEventSink, setRemoteConfig, setRuntimeDisabled } from '../engine';
import {
  codeLocation,
  configureIast,
  IAST_REPORT_EVERY_MS,
  iastEnabled,
  iastSampleRate,
  isAppFrame,
  RASP_VULNERABILITY,
  resetIast,
  setIastRemote,
  setIastSink,
  vulnFingerprint,
} from '../iast';
import { captureVulnerability, iastArmed } from '../iast-scope';
import { qualifies, VULN_RULES } from '../iast-rules';
import {
  detectArgv,
  detectCode,
  detectCommand,
  detectDeserialization,
  detectInclude,
  detectPath,
  detectShellSpawn,
  detectSql,
  detectSsrf,
  detectXml,
  shellScriptOf,
  type DeserFormat,
  type FileOp,
} from '../detect';
import type { SqlDialect } from '../lexers';
import { installFsHooks, uninstallFsHooks } from '../hooks/fs';
import { RaspBlockedError, type Finding, type RaspInput } from '../types';
import { loadJson, normalise } from './corpus';
import { PER_MINUTE, RaspReporter } from '../reporter';

const corpus = loadJson('testdata/iast.json');
const cases: any[] = corpus.cases;
const fingerprints: any[] = corpus.fingerprints;

/** Runs one corpus case through the detectors with an IAST slot armed. */
function runIastCase(c: any): { finding: Finding | null; vuln: ReturnType<typeof captureVulnerability>['vuln'] } {
  const inputs = normalise(c.inputs);
  const { result, vuln } = captureVulnerability((): Finding | null => {
    switch (c.check) {
      case 'sql':
        return detectSql(c.query, inputs, c.dialect as SqlDialect);
      case 'command': {
        if (typeof c.command === 'string') return detectCommand(c.command, inputs) ?? detectShellSpawn({ command: c.command, inRequest: true, allow: [] });
        const argv: string[] = c.argv;
        const script = shellScriptOf(argv);
        return detectArgv(argv, inputs) ?? (script ? detectCommand(script, inputs) : null) ?? detectShellSpawn({ argv0: argv[0], inRequest: true, allow: [] });
      }
      case 'path':
        return detectPath(c.path, c.op as FileOp, inputs, c.fileRoots || []);
      case 'ssrf':
        return detectSsrf(c.url, inputs, c.resolved || []);
      case 'code':
        return detectCode(c.code, inputs);
      case 'include':
        return detectInclude(c.specifier, inputs);
      case 'deser':
        return detectDeserialization(c.format as DeserFormat, c.data, inputs);
      case 'xml':
        return detectXml(c.xml, inputs, Boolean(c.resolvesExternal));
    }
    throw new Error(`unknown check ${c.check}`);
  });
  return { finding: result, vuln };
}

describe('passive IAST conformance corpus', () => {
  it('is version 1 with cases for every rule', () => {
    expect(corpus.version).toBe(1);
    const rules = new Set(corpus.cases.map((c: any) => c.expect.rule).filter(Boolean));
    expect([...rules].sort()).toEqual([...VULN_RULES].sort());
  });

  it.each(cases.map((c) => [c.name, c] as [string, any]))('%s', (_name, c: any) => {
    const { finding, vuln } = runIastCase(c);
    // Every case is harmless: the attack checks fire nothing.
    expect(finding).toBeNull();
    if (c.expect.rule === null) {
      expect(vuln).toBeNull();
    } else {
      expect(vuln?.rule).toBe(c.expect.rule);
      if (c.expect.position) expect(vuln?.position).toBe(c.expect.position);
      if (c.expect.input_key) expect(vuln?.input.key).toBe(c.expect.input_key);
    }
  });

  it.each(fingerprints.map((f) => [f.fingerprint, f] as [string, any]))('fingerprint %s', (_fp, f: any) => {
    expect(vulnFingerprint(f.route, f.sink, f.input_key, f.rule)).toBe(f.fingerprint);
  });

  it('notes nothing when no slot is armed', () => {
    expect(iastArmed()).toBe(false);
    const inputs: RaspInput[] = [{ value: 'alice@example.com', key: 'query.email', source: 'request' }];
    expect(detectSql("SELECT 1 FROM t WHERE e = 'alice@example.com'", inputs)).toBeNull();
    expect(iastArmed()).toBe(false);
  });
});

describe('thresholds', () => {
  it.each([
    ['1', false],
    ['42', false],
    ['100', false],
    ['true', false],
    ['active', false],
    ['desc', false],
    ['aaaaaaaaaa', false],
    ['----', false],
    ['1234', true],
    ['created_at', true],
    ['en-GB', true],
    ['alice@example.com', true],
    ['Saint Paul', true],
    ['password', true],
  ])('%s qualifies: %s', (value, expected) => {
    expect(qualifies(value)).toBe(expected);
  });
});

describe('passive IAST in the engine', () => {
  const events: { name: string; attrs: Record<string, string> }[] = [];
  const sink = { add: (e: { name: string; attrs: Record<string, string> }) => void events.push(e) };
  let clock = 1_000_000;
  const email: RaspInput[] = [{ value: 'alice@example.com', key: 'query.email', source: 'request' }];
  const query = "SELECT id FROM orders WHERE customer_email = 'alice@example.com'";
  const runSql = (inputs = email, q = query) =>
    runWithInputs(inputs, () => check('pg.query', () => detectSql(q, inputs, 'postgres')), { inRequest: true, method: 'get', route: '/api/orders/:id', framework: 'express' });

  const setup = (o: { iast?: unknown; env?: NodeJS.ProcessEnv; mode?: 'block' | 'monitor'; environment?: string; random?: () => number } = {}) => {
    configureEngine({ enabled: true, applicationName: 'orders-api', mode: o.mode ?? 'block', env: {} });
    setEventSink(sink);
    configureIast({ option: o.iast as never, applicationName: 'orders-api', environment: o.environment, env: o.env ?? {}, now: () => clock, random: o.random });
    setIastSink(sink);
  };

  beforeEach(() => {
    events.length = 0;
    clock = 1_000_000;
  });
  afterEach(() => {
    resetIast();
    setEventSink(undefined);
    setRemoteConfig(undefined);
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
  });

  const vulns = () => events.filter((e) => e.name === RASP_VULNERABILITY);

  it('is off by default', () => {
    setup();
    expect(iastEnabled()).toBe(false);
    expect(runSql()).toBeNull();
    expect(vulns()).toEqual([]);
  });

  it('reports a vulnerability once, with locations and no value, and never blocks', () => {
    setup({ iast: true, mode: 'block' });
    expect(runSql()).toBeNull();
    expect(vulns()).toHaveLength(1);
    const a = vulns()[0].attrs;
    expect(a).toMatchObject({
      'shield360.rasp.kind': 'vulnerability',
      'shield360.rasp.app': 'orders-api',
      'shield360.rasp.rule': 'vuln.sql_concat',
      'shield360.rasp.sink': 'pg.query',
      'shield360.rasp.source': 'request',
      'shield360.rasp.input_key': 'query.email',
      'shield360.rasp.route': '/api/orders/:id',
      'shield360.rasp.method': 'GET',
      'shield360.rasp.framework': 'express',
      'shield360.rasp.language': 'node',
      'shield360.rasp.config_version': 'local',
      'shield360.rasp.vuln.position': 'string',
      'shield360.rasp.count': '1',
    });
    expect(a['shield360.rasp.vuln.fingerprint']).toBe(vulnFingerprint('/api/orders/:id', 'pg.query', 'query.email', 'vuln.sql_concat'));
    expect(a['shield360.rasp.event_id']).toMatch(/^[a-f0-9]{32}$/);
    // This test file is the app's code here.
    expect(a['shield360.rasp.vuln.location']).toMatch(/^src\/rasp\/__tests__\/iast\.test\.ts:\d+$/);
    expect(JSON.stringify(vulns())).not.toContain('alice@example.com');
    expect(a['shield360.rasp.snippet']).toBeUndefined();
    expect(events.filter((e) => e.name === 'shield360.rasp.event')).toEqual([]);
  });

  it('reports each fingerprint at most once an hour, with the count seen since', () => {
    setup({ iast: true });
    runSql();
    runSql();
    runSql();
    expect(vulns()).toHaveLength(1);
    clock += IAST_REPORT_EVERY_MS;
    runSql();
    expect(vulns()).toHaveLength(2);
    expect(vulns()[1].attrs['shield360.rasp.count']).toBe('3');
  });

  it('reports nothing for an attack (the attack event covers it)', () => {
    setup({ iast: true, mode: 'monitor' });
    const attack: RaspInput[] = [{ value: "x' OR '1'='1", key: 'query.q', source: 'request' }];
    runSql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'");
    expect(events.map((e) => e.name)).toEqual(['shield360.rasp.event']);
  });

  it('works whatever the attack mode, even off', () => {
    configureEngine({ enabled: true, applicationName: 'orders-api', attacks: { sql_injection: 'off' }, env: {} });
    configureIast({ option: true, applicationName: 'orders-api', env: {}, now: () => clock });
    setIastSink(sink);
    runSql();
    expect(vulns()).toHaveLength(1);
  });

  it('stands down with the kill switch', () => {
    setup({ iast: true });
    setRuntimeDisabled(true);
    runSql();
    setRuntimeDisabled(false);
    expect(vulns()).toEqual([]);
  });

  it('does nothing without request input in scope', () => {
    setup({ iast: true });
    check('pg.query', () => detectSql(query, [], 'postgres'));
    expect(vulns()).toEqual([]);
  });

  it('samples checks', () => {
    setup({ iast: { sampleRate: 0.5 }, random: () => 0.9 });
    runSql();
    expect(vulns()).toEqual([]);
    setup({ iast: { sampleRate: 0.5 }, random: () => 0.1 });
    runSql();
    expect(vulns()).toHaveLength(1);
  });

  it('defaults to every check, a tenth in production', () => {
    setup({ iast: true });
    expect(iastSampleRate()).toBe(1);
    setup({ iast: true, environment: 'production' });
    expect(iastSampleRate()).toBe(0.1);
    setup({ iast: true, env: { NODE_ENV: 'production', SHIELD360_IAST_SAMPLE_RATE: '0.5' } });
    expect(iastSampleRate()).toBe(0.5);
    setup({ iast: true, env: { SHIELD360_IAST_SAMPLE_RATE: '7' } });
    expect(iastSampleRate()).toBe(1);
  });

  it('is switched by the env and the signed config, env off winning', () => {
    setup({ env: { SHIELD360_IAST: 'on' } });
    expect(iastEnabled()).toBe(true);
    setIastRemote({ iast: 'off', version: 'v2' });
    expect(iastEnabled()).toBe(false);
    setup({ random: () => 0.1 });
    setIastRemote({ iast: 'on', iastSampleRate: 0.25, version: 'v3' });
    expect(iastEnabled()).toBe(true);
    expect(iastSampleRate()).toBe(0.25);
    runSql();
    expect(vulns()[0].attrs['shield360.rasp.config_version']).toBe('v3');
    setup({ iast: true, env: { SHIELD360_IAST: 'off' } });
    setIastRemote({ iast: 'on', version: 'v4' });
    expect(iastEnabled()).toBe(false);
    setIastRemote(undefined);
    expect(iastEnabled()).toBe(false);
  });

  it('fails open when a rule throws', () => {
    setup({ iast: true });
    const throwing = { get value(): string { throw new Error('boom'); }, key: 'query.x', source: 'request' as const };
    expect(() => runWithInputs([email[0]], () => check('pg.query', () => detectSql(query, [email[0], throwing as unknown as RaspInput]), {}))).not.toThrow();
  });

  it('never exports a secret-looking path segment when the framework gives no route template', () => {
    setup({ iast: true });
    const inputs = email;
    runWithInputs(inputs, () => check('pg.query', () => detectSql(query, inputs, 'postgres')), { inRequest: true, method: 'GET', path: '/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm' });
    expect(vulns()).toHaveLength(1);
    const route = vulns()[0].attrs['shield360.rasp.route'];
    expect(route).toBe('/api/v2/reset/:id/confirm');
    expect(JSON.stringify(vulns())).not.toContain('AbCdEfGhIjKlMnOpQrSt');
  });

  it('retries a report the reporter refused, keeping the count', () => {
    setup({ iast: true });
    const accepted: { name: string; attrs: Record<string, string> }[] = [];
    let refuse = true;
    setIastSink({ add: (e: { name: string; attrs: Record<string, string> }) => (refuse ? false : (accepted.push(e), true)) });
    runSql();
    expect(accepted).toHaveLength(0);
    refuse = false;
    clock += 61_000;
    runSql();
    expect(accepted).toHaveLength(1);
    expect(accepted[0].attrs['shield360.rasp.count']).toBe('2');
    runSql();
    expect(accepted).toHaveLength(1);
  });

  it('a report the real reporter refuses is never folded and sent behind its back', () => {
    setup({ iast: true });
    const reporter = new RaspReporter({ url: 'https://shield.example.com/', apiKey: 'k', applicationName: 'orders-api', now: () => clock });
    // Use up the minute's events.
    for (let i = 0; i < PER_MINUTE; i++) reporter.add({ name: 'shield360.rasp.event', time: '', attrs: {} }, `filler${i}`);
    setIastSink(reporter);
    runSql(); // refused: the minute is full
    clock += 1_000;
    runSql(); // refused again, inside the reporter's 10 s fold window
    clock += 60_000;
    runSql(); // a new minute: sent, with every sighting since
    const sent = reporter.pending().filter((e) => e.name === RASP_VULNERABILITY);
    expect(sent.map((e) => e.attrs['shield360.rasp.count'])).toEqual(['3']);
  });

  it('reaches the real fs hook', () => {
    setup({ iast: true });
    installFsHooks();
    try {
      const inputs: RaspInput[] = [{ value: 'invoice-2026-0193', key: 'query.file', source: 'request' }];
      runWithInputs(inputs, () => fs.existsSync('/nonexistent-shield360-iast/invoice-2026-0193.pdf'), { inRequest: true, route: '/files/:name' });
      runWithInputs(inputs, () => {
        try {
          fs.readFileSync('/nonexistent-shield360-iast/invoice-2026-0193.pdf');
        } catch {
          // missing on purpose
        }
      }, { inRequest: true, route: '/files/:name' });
    } finally {
      uninstallFsHooks();
    }
    const found = vulns().filter((e) => e.attrs['shield360.rasp.rule'] === 'vuln.path_from_input');
    expect(found.length).toBeGreaterThanOrEqual(1);
    expect(found[0].attrs['shield360.rasp.input_key']).toBe('query.file');
    expect(found[0].attrs['shield360.rasp.sink']).toMatch(/^fs\./);
  });

  it('a blocking attack still blocks with IAST on', () => {
    setup({ iast: true, mode: 'block' });
    const attack: RaspInput[] = [{ value: "x' OR '1'='1", key: 'query.q', source: 'request' }];
    expect(() => runSql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'")).toThrow(RaspBlockedError);
    expect(iastArmed()).toBe(false);
  });
});

describe('code location', () => {
  it('takes the first app frame outside node_modules, Node and the SDK', () => {
    const cwd = process.cwd();
    const stack = [
      'Error',
      `    at reportVulnerability (${cwd}/src/rasp/iast.ts:10:5)`,
      '    at Object.query (/app/node_modules/pg/lib/client.js:500:10)',
      '    at node:internal/process/task_queues:95:5',
      `    at getOrder (${cwd}/routes/orders.ts:42:17)`,
      `    at ${cwd}/server.ts:7:1`,
    ].join('\n');
    expect(codeLocation(stack)).toBe('routes/orders.ts:42');
  });

  it('keeps the last three segments outside the working directory', () => {
    expect(codeLocation('Error\n    at x (/opt/other/app/lib/db/run.js:3:9)')).toBe('lib/db/run.js:3');
  });

  it('is empty when there is no app frame', () => {
    expect(codeLocation('Error\n    at x (/app/node_modules/a/b.js:1:1)')).toBe('');
    expect(isAppFrame('node:fs')).toBe(false);
  });
});

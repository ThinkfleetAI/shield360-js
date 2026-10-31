/**
 * Allow-list targets and the SQL dialect (README "Events", "Allow-list
 * targets"): the shared conformance file, the detectors, and the engine's
 * gating on the signed `reportTargets` flag.
 */
import { detectOutbound, detectPath, detectShellSpawn, detectSql, targetDirectory } from '../detect';
import { configureEngine, handleFinding, maskTarget, setEventSink, setRemoteConfig, type RemoteConfig } from '../engine';
import type { Finding } from '../types';
import { loadJson } from './corpus';

const targets = loadJson('testdata/targets.json');

describe('targets.json conformance', () => {
  it('masks every raw target as the file says', () => {
    for (const c of targets.mask as { raw: string; target: string | null }[]) expect([c.raw, maskTarget(c.raw) ?? null]).toEqual([c.raw, c.target]);
  });
  it('gives every resolved path its directory', () => {
    for (const c of targets.directory as { resolved: string; directory: string }[]) expect(targetDirectory(c.resolved)).toBe(c.directory);
  });
});

describe('detectors', () => {
  const inp = (value: string) => [{ value, key: 'query.q', source: 'request' as const }];
  it('shell_spawn.shell names the executable basename, never the arguments', () => {
    const f = detectShellSpawn({ argv0: '/usr/bin/BASH.exe', inRequest: true, allow: [] });
    expect(f).toMatchObject({ rule: 'shell_spawn.shell', target: 'bash' });
  });
  it('outbound.not_allowed names the host only', () => {
    expect(detectOutbound('https://API.Example.com:8443/p?q=1', ['ok.example.com'])).toMatchObject({ target: 'api.example.com' });
  });
  it('path.outside_root names the directory, never the file name; other path rules name nothing', () => {
    const f = detectPath('/var/data/report.txt', 'read', inp('report.txt'), ['/srv/app']);
    expect(f).toMatchObject({ rule: 'path.outside_root', target: '/var/data' });
    expect(detectPath('/srv/app/../../etc/passwd', 'read', inp('../../etc/passwd'), ['/srv/app'])?.target).toBeUndefined();
  });
  it('SQL findings carry the dialect', () => {
    expect(detectSql("SELECT * FROM t WHERE id = 1 OR 1=1", inp('1 OR 1=1'), 'postgres')).toMatchObject({ rule: 'sqli.userinput', dialect: 'postgres' });
    expect(detectSql("SELECT * FROM t WHERE id = 1 OR 1=1", inp('1 OR 1=1'))?.dialect).toBe('generic');
  });
});

describe('engine', () => {
  const events: any[] = [];
  const remote = (over: Partial<RemoteConfig> = {}): RemoteConfig => ({ version: 'v1', exp: Date.now() / 1000 + 3600, killSwitch: false, snippets: false, attacks: {}, rules: null, ...over });
  const outbound: Finding = { attack: 'outbound', rule: 'outbound.not_allowed', target: 'api.example.com' };
  const attrs = (f: Finding) => {
    events.length = 0;
    handleFinding(f, 'http.request');
    return events[0].attrs as Record<string, string>;
  };
  beforeEach(() => {
    configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
    setEventSink({ add: (e: any) => events.push(e) });
  });
  afterAll(() => {
    setEventSink(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  it('sends the target only with the signed reportTargets flag', () => {
    expect(attrs(outbound)['shield360.rasp.target']).toBeUndefined();
    setRemoteConfig(remote({ reportTargets: false }));
    expect(attrs(outbound)['shield360.rasp.target']).toBeUndefined();
    setRemoteConfig(remote({ reportTargets: true }));
    expect(attrs(outbound)['shield360.rasp.target']).toBe('api.example.com');
    expect(attrs({ attack: 'shell_spawn', rule: 'shell_spawn.shell', target: 'curl' })['shield360.rasp.target']).toBe('curl');
  });

  it('only for the three allow-list rules', () => {
    setRemoteConfig(remote({ reportTargets: true }));
    expect(attrs({ attack: 'path_traversal', rule: 'path.traversal', target: '/var/data' })['shield360.rasp.target']).toBeUndefined();
  });

  it('masked and capped', () => {
    setRemoteConfig(remote({ reportTargets: true }));
    expect(attrs({ ...outbound, target: `${'abcdefghijklmnopqrstuvwxyz0123'}.example.com` })['shield360.rasp.target']).toBe('***.example.com');
    expect(attrs({ attack: 'path_traversal', rule: 'path.outside_root', target: '/ab'.repeat(100) })['shield360.rasp.target']).toBeUndefined();
  });

  it('SQL events carry the dialect whatever reportTargets says; unknown dialects are left out', () => {
    const sql: Finding = { attack: 'sql_injection', rule: 'sqli.userinput', dialect: 'oracle' };
    expect(attrs(sql)['shield360.rasp.sql.dialect']).toBe('oracle');
    expect(attrs({ ...sql, dialect: 'cobol' })['shield360.rasp.sql.dialect']).toBeUndefined();
    expect(attrs(outbound)['shield360.rasp.sql.dialect']).toBeUndefined();
  });
});

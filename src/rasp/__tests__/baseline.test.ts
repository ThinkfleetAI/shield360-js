/**
 * Security baseline: each rule from what it reads (pure), nothing for a
 * sound set-up, monitor only even in block mode, once per process, and no
 * setting's value in an event.
 */
import { baselineFindings, isProduction, resetBaseline, runBaseline, type BaselineInput } from '../baseline';
import { configureEngine, setEventSink } from '../engine';

const sound: BaselineInput = {
  env: { NODE_ENV: 'production' },
  environment: 'production',
  remoteWanted: true,
  pinned: true,
  execArgv: [],
  nodeVersion: '22.11.0',
  uid: 1000,
  inspectorOpen: false,
  now: new Date('2026-10-29T00:00:00Z'),
};
const rules = (over: Partial<BaselineInput>) => baselineFindings({ ...sound, ...over }).map((f) => f.rule);

describe('baselineFindings', () => {
  it('finds nothing for a sound production set-up', () => {
    expect(rules({})).toEqual([]);
  });

  it.each([
    ['TLS checks off', { env: { NODE_ENV: 'production', NODE_TLS_REJECT_UNAUTHORIZED: '0' } }, 'baseline.tls_verify_off'],
    ['an inspector flag in production', { execArgv: ['--inspect=0.0.0.0:9229'] }, 'baseline.inspector_in_production'],
    ['an inspector in NODE_OPTIONS in production', { env: { NODE_ENV: 'production', NODE_OPTIONS: '--max-old-space-size=512 --inspect' } }, 'baseline.inspector_in_production'],
    ['an open inspector in production', { inspectorOpen: true }, 'baseline.inspector_in_production'],
    ['development mode under a production environment', { env: { NODE_ENV: 'development' } }, 'baseline.development_mode_in_production'],
    ['running as root', { uid: 0 }, 'baseline.running_as_root'],
    ['an unpinned config key in production', { pinned: false }, 'baseline.config_key_unpinned'],
    ['an end-of-life Node line', { nodeVersion: '18.20.4' }, 'baseline.runtime_end_of_life'],
    ['an odd (short-lived) Node line', { nodeVersion: '23.1.0' }, 'baseline.runtime_end_of_life'],
  ])('reports %s', (_label, over, rule) => {
    expect(rules(over as Partial<BaselineInput>)).toContain(rule);
  });

  it('leaves development set-ups alone where the rule is about production', () => {
    const dev = { env: { NODE_ENV: 'development' }, environment: 'development', inspectorOpen: true, pinned: false };
    expect(rules(dev)).toEqual([]);
  });

  it('a release line still in support passes; one past its date does not', () => {
    expect(rules({ nodeVersion: '20.18.0', now: new Date('2026-04-30T12:00:00Z') })).toEqual([]);
    expect(rules({ nodeVersion: '20.18.0', now: new Date('2026-05-01T00:00:00Z') })).toEqual(['baseline.runtime_end_of_life']);
  });

  it('reads production from NODE_ENV, ENVIRONMENT or the SDK option', () => {
    expect(isProduction({ NODE_ENV: 'production' })).toBe(true);
    expect(isProduction({ ENVIRONMENT: 'Prod' })).toBe(true);
    expect(isProduction({}, 'production')).toBe(true);
    expect(isProduction({ NODE_ENV: 'staging' }, 'qa')).toBe(false);
  });
});

describe('runBaseline', () => {
  const events: { attrs: Record<string, string> }[] = [];
  beforeEach(() => {
    events.length = 0;
    resetBaseline();
    configureEngine({ enabled: true, applicationName: 'orders-api', mode: 'block', env: {} });
    setEventSink({ add: (e) => events.push(e) });
  });
  afterAll(() => {
    setEventSink(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  it('reports each finding once per process, monitored even in block mode, without the setting values', () => {
    const env = { NODE_ENV: 'production', NODE_TLS_REJECT_UNAUTHORIZED: '0', NODE_OPTIONS: '--inspect' };
    expect(() => runBaseline({ environment: 'production', remoteWanted: true, pinned: false, env })).not.toThrow();
    runBaseline({ environment: 'production', remoteWanted: true, pinned: false, env });
    const got = events.map((e) => e.attrs['shield360.rasp.rule']);
    expect(got).toEqual(expect.arrayContaining(['baseline.tls_verify_off', 'baseline.inspector_in_production', 'baseline.config_key_unpinned']));
    expect(new Set(got).size).toBe(got.length);
    for (const e of events) {
      expect(e.attrs['shield360.rasp.attack']).toBe('baseline');
      expect(e.attrs['shield360.rasp.decision']).toBe('monitored');
      expect(e.attrs['shield360.rasp.sink']).toBe('startup');
      expect(JSON.stringify(e.attrs)).not.toContain('--inspect');
    }
  });

  it('does nothing while RASP is off', () => {
    configureEngine({ enabled: false, applicationName: 'orders-api', env: {} });
    runBaseline({ remoteWanted: false, pinned: false, env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' } });
    expect(events).toHaveLength(0);
  });
});

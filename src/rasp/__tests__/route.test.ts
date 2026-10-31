/**
 * Event route (README "Event route"): the shared conformance cases
 * (sdk/rasp/testdata/routes.json), and attack events built from a path when
 * the framework gives no route template.
 */
import { eventRouteOf, newContext, storage } from '../context';
import { configureEngine, handleFinding, setEventSink } from '../engine';
import { iastRouteOf } from '../iast';
import type { Finding } from '../types';
import { loadJson } from './corpus';

const cases: { path: string; route: string }[] = loadJson('testdata/routes.json').cases;

describe('event route conformance (testdata/routes.json)', () => {
  it.each(cases.map((c) => [c.path, c.route]))('%s -> %s', (path, route) => {
    expect(eventRouteOf(path)).toBe(route);
    expect(iastRouteOf(path)).toBe(route);
  });
});

describe('attack event route', () => {
  const events: any[] = [];
  const finding: Finding = { attack: 'sql_injection', rule: 'sqli.userinput', input: { value: 'v', key: 'query.id', source: 'request' } };
  const routeOfEvent = (ctx: Parameters<typeof newContext>[0]) => {
    storage.run(newContext({ inRequest: true, method: 'get', ...ctx }), () => handleFinding(finding, 'pg.query'));
    return events[events.length - 1].attrs['shield360.rasp.route'];
  };

  beforeEach(() => {
    events.length = 0;
    configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
    setEventSink({ add: (e: any) => events.push(e) });
  });
  afterAll(() => {
    setEventSink(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  it('never carries a secret-looking path segment when the framework gives no template', () => {
    expect(routeOfEvent({ path: '/reset/Zx9TqLm2Rk7WpA4s/confirm' })).toBe('/reset/:id/confirm');
  });

  it('keeps the framework route template unchanged', () => {
    expect(routeOfEvent({ path: '/reset/Zx9TqLm2Rk7WpA4s/confirm', route: '/reset/:Token/confirm' })).toBe('/reset/:Token/confirm');
  });

  it('keeps a route passed by the hook unchanged', () => {
    handleFinding(finding, 'pg.query', { route: '/Files/{fileName}', path: '/Files/Secret' });
    expect(events[0].attrs['shield360.rasp.route']).toBe('/Files/{fileName}');
  });
});

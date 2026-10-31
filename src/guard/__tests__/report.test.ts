import { createServer, Server } from 'http';
import { AddressInfo } from 'net';
import { Pipeline } from '../pipeline';
import { PII } from '../pii';
import { configureGuardReports, flushGuardReports, resetGuardReports } from '../report';

describe('guard reports', () => {
  let server: Server;
  const received: { auth?: string; path?: string; body: any }[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/api/guard/config') {
        res.end(JSON.stringify({ fingerprintKey: 'org-secret' }));
        return;
      }
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        received.push({ auth: req.headers.authorization, path: req.url, body: JSON.parse(raw) });
        res.end('{}');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  });

  afterAll(async () => {
    await resetGuardReports();
    await new Promise((r) => server.close(r));
  });

  it('reports decisions, but never the text', async () => {
    const port = (server.address() as AddressInfo).port;
    expect(
      configureGuardReports({ url: `http://127.0.0.1:${port}`, apiKey: 'key-1', applicationName: 'support-bot', environment: 'test' }),
    ).toBe(true);
    const pipeline = new Pipeline({ guards: [new PII({ action: 'redact' })] });
    pipeline.evaluate('SSN 123-45-6789', 'preflight');
    pipeline.evaluate('nothing to see', 'preflight');
    await flushGuardReports();

    const events = received.flatMap((r) => r.body.events);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('shield360.guard.decision');
    expect(events[0].attrs['shield360.guard.action']).toBe('redact');
    expect(events[0].attrs['shield360.guard.kinds']).toBe('ssn');
    expect(events[0].attrs['shield360.guard.client']).toBe('support-bot');
    expect(events[0].attrs['shield360.guard.app']).toBe('support-bot');
    expect(received[0].body.resource['service.name']).toBe('support-bot');
    expect(received[0].auth).toBe('Bearer key-1');
    expect(received[0].path).toBe('/api/guard/events');
    expect(JSON.stringify(received)).not.toContain('123-45-6789');
  });

  it('sends nothing without a URL and key', () => {
    expect(configureGuardReports({ applicationName: 'a', environment: 'e' })).toBe(false);
  });
});

describe('guard heartbeat', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { guardModes, heartbeatAttrs, heartbeatEnabled, nextDelay, HEARTBEAT_INTERVAL_MS } = require('../heartbeat');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { PromptInjection } = require('../prompt-injection');
  let server: Server;
  const received: any[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.method === 'GET') return res.end('{}');
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        received.push(JSON.parse(raw));
        res.end('{}');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  });

  afterEach(async () => {
    await resetGuardReports();
    received.length = 0;
  });

  afterAll(async () => {
    await new Promise((r) => server.close(r));
  });

  const url = () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  it('maps each guard kind to off, warn or block, strongest first', () => {
    expect(guardModes([new PII({ action: 'warn' }), new PII({ action: 'redact' }), new PromptInjection({ action: 'allow' })])).toEqual({ pii: 'block', prompt_injection: 'off' });
    const attrs = heartbeatAttrs([new PromptInjection({ action: 'deny' })], 'support-bot', '1.2.3');
    expect(attrs).toEqual({
      'shield360.guard.app': 'support-bot',
      'shield360.guard.modes': '{"prompt_injection":"block"}',
      'shield360.guard.injection': 'true',
      'shield360.sdk.name': 'shield360-typescript',
      'shield360.sdk.version': '1.2.3',
    });
  });

  it('beats once at start, with no content, host or user', async () => {
    configureGuardReports({ url: url(), apiKey: 'k', applicationName: 'support-bot', environment: 'prod', sdkVersion: '1.2.3', guards: [new PII({ action: 'redact' })] });
    await flushGuardReports();
    const events = received.flatMap((b) => b.events);
    expect(events).toHaveLength(1);
    expect(events[0].name).toBe('shield360.guard.heartbeat');
    expect(events[0].attrs['shield360.guard.modes']).toBe('{"pii":"block"}');
    expect(Object.keys(events[0].attrs).sort()).toEqual(['shield360.guard.app', 'shield360.guard.injection', 'shield360.guard.modes', 'shield360.sdk.name', 'shield360.sdk.version']);
  });

  it('is off without guards, with the option, or with the environment variable', async () => {
    configureGuardReports({ url: url(), apiKey: 'k', applicationName: 'a', environment: 'e' });
    configureGuardReports({ url: url(), apiKey: 'k', applicationName: 'a', environment: 'e', guards: [new PII()], heartbeat: false });
    await flushGuardReports();
    expect(received.flatMap((b) => b.events)).toHaveLength(0);
    expect(heartbeatEnabled(undefined, { SHIELD360_GUARD_HEARTBEAT: 'false' })).toBe(false);
    expect(heartbeatEnabled(undefined, {})).toBe(true);
  });

  it('beats about every five minutes, jittered', () => {
    expect(nextDelay(() => 0)).toBe(HEARTBEAT_INTERVAL_MS * 0.8);
    expect(nextDelay(() => 1)).toBe(HEARTBEAT_INTERVAL_MS * 1.2);
  });

  it('never throws when Shield360 cannot be reached', async () => {
    expect(() => configureGuardReports({ url: 'http://127.0.0.1:1', apiKey: 'k', applicationName: 'a', environment: 'e', guards: [new PII()] })).not.toThrow();
    await resetGuardReports();
  });
});

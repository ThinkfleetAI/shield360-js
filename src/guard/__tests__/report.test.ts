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
    expect(received[0].auth).toBe('Bearer key-1');
    expect(received[0].path).toBe('/api/guard/events');
    expect(JSON.stringify(received)).not.toContain('123-45-6789');
  });

  it('sends nothing without a URL and key', () => {
    expect(configureGuardReports({ applicationName: 'a', environment: 'e' })).toBe(false);
  });
});

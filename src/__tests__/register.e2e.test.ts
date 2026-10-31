/**
 * End to end: a tiny app that never imports Shield360 is started through the
 * zero-code entry (`node --require shield360/register`, and `--import` for
 * ESM). Shield360 starts from SHIELD360_* variables alone: RASP blocks a
 * command injection in a raw `http` handler (no middleware) and reports the
 * event to a fake Shield360.
 *
 * Runs against the built package (`dist/`), as `npm test` does in CI after
 * `npm run build`; it builds incrementally first.
 */
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'child_process';
import { generateKeyPairSync } from 'crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { createServer, get, type Server } from 'http';
import type { AddressInfo } from 'net';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { pathToFileURL } from 'url';

jest.setTimeout(120_000);

const ROOT = resolve(__dirname, '..', '..');
const REGISTER = join(ROOT, 'dist', 'register.js');
const INDEX = join(ROOT, 'dist', 'index.js');

const CJS_APP = `
const http = require('http');
const { exec } = require('child_process');
const server = http.createServer((req, res) => {
  const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
  exec('echo ' + q, (err, out) => { res.end(err ? 'error' : out); });
});
server.listen(0, '127.0.0.1', () => console.log('PORT ' + server.address().port));
`;

// An async handler that reaches the sink after an await.
const ASYNC_APP = `
const http = require('http');
const { execSync } = require('child_process');
const server = http.createServer(async (req, res) => {
  await new Promise((r) => setTimeout(r, 5));
  const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
  res.end(execSync('echo ' + q).toString());
});
server.listen(0, '127.0.0.1', () => console.log('PORT ' + server.address().port));
`;

// Takes its names at load, the way ESM apps do: the hooks must already be in place.
const ESM_APP = `
import http from 'node:http';
import { execSync } from 'node:child_process';
const server = http.createServer((req, res) => {
  const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
  res.end(execSync('echo ' + q).toString());
});
server.listen(0, '127.0.0.1', () => console.log('PORT ' + server.address().port));
`;

// An ESM app preloaded through NODE_OPTIONS (how containers turn Shield360 on), importing a
// CommonJS driver shaped like pg: `module.exports = new PG()` hides its named exports from ESM.
const ESM_DB_APP = `
import http from 'node:http';
import pg from 'pg';
const client = new pg.Client();
const server = http.createServer((req, res) => {
  const id = new URL(req.url, 'http://x').searchParams.get('id') || '1';
  res.end(client.query('SELECT name FROM items WHERE id = ' + id));
});
server.listen(0, '127.0.0.1', () => console.log('PORT ' + server.address().port));
`;

const FAKE_PG = `
function Client() {}
Client.prototype.query = function query(text) { return 'ran'; };
function PG() { this.Client = Client; }
module.exports = new PG();
`;

// Calls init() itself as well: the zero-code start wins, the call is a no-op.
const DOUBLE_INIT_APP = `
require(${JSON.stringify(INDEX)}).default.init({ rasp: false });
${CJS_APP}
`;

type Fake = { server: Server; url: string; events: unknown[] };

async function startFakeShield360(): Promise<Fake> {
  const events: unknown[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      if (req.method === 'POST' && req.url?.startsWith('/api/guard/events')) {
        try {
          events.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          // not JSON: ignore
        }
      }
      if (req.url?.startsWith('/api/rasp/config')) {
        res.statusCode = 404;
        return res.end('{}');
      }
      res.setHeader('Content-Type', 'application/json');
      res.end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, events };
}

function fetchText(url: string): Promise<{ status: number; body: string }> {
  return new Promise((ok, fail) => {
    get(url, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => ok({ status: res.statusCode || 0, body }));
    }).on('error', fail);
  });
}

type App = { child: ChildProcess; port: number; stderr: () => string };

function startApp(args: string[], env: NodeJS.ProcessEnv): Promise<App> {
  return new Promise((ok, fail) => {
    const child = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => fail(new Error(`app did not start: ${err}`)), 30_000);
    child.stderr?.on('data', (c) => (err += c));
    child.stdout?.on('data', (c) => {
      out += c;
      const m = /PORT (\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        ok({ child, port: Number(m[1]), stderr: () => err });
      }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      fail(new Error(`app exited (${code}): ${err}`));
    });
  });
}

async function waitFor(cond: () => boolean, ms = 10_000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return cond();
}

function stop(app?: App): void {
  if (app && app.child.exitCode === null) {
    app.child.removeAllListeners('exit');
    app.child.kill('SIGKILL');
  }
}

describe('zero-code entry (shield360/register), end to end', () => {
  let dir: string;
  let fake: Fake;
  let baseEnv: NodeJS.ProcessEnv;

  beforeAll(async () => {
    execFileSync(process.execPath, [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '--build'], { cwd: ROOT, stdio: 'pipe' });
    dir = mkdtempSync(join(tmpdir(), 'shield360-zero-code-'));
    writeFileSync(join(dir, 'app.js'), CJS_APP);
    writeFileSync(join(dir, 'app.mjs'), ESM_APP);
    writeFileSync(join(dir, 'double.js'), DOUBLE_INIT_APP);
    writeFileSync(join(dir, 'async.js'), ASYNC_APP);
    writeFileSync(join(dir, 'db.mjs'), ESM_DB_APP);
    mkdirSync(join(dir, 'node_modules', 'pg'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'pg', 'package.json'), JSON.stringify({ name: 'pg', version: '8.23.1', main: 'index.js' }));
    writeFileSync(join(dir, 'node_modules', 'pg', 'index.js'), FAKE_PG);
    fake = await startFakeShield360();
    const x = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x as string;
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('SHIELD360_') || k.startsWith('OTEL_') || k === 'NODE_OPTIONS') delete env[k];
    baseEnv = {
      ...env,
      OTEL_SERVICE_NAME: 'zero-code-e2e',
      OTEL_EXPORTER_OTLP_ENDPOINT: fake.url,
      SHIELD360_URL: fake.url,
      SHIELD360_API_KEY: 'zero-code-e2e',
      SHIELD360_CONFIG_PUBLIC_KEY: x,
      SHIELD360_RASP: 'block',
    };
  });

  afterAll(async () => {
    await new Promise((r) => fake.server.close(r));
    rmSync(dir, { recursive: true, force: true });
  });

  it('--require: RASP blocks a command injection in a raw http app and reports it, with no code change', async () => {
    let app: App | undefined;
    try {
      app = await startApp(['--require', REGISTER, join(dir, 'app.js')], baseEnv);
      const okRes = await fetchText(`http://127.0.0.1:${app.port}/?q=hello`);
      expect(okRes).toEqual({ status: 200, body: 'hello\n' });

      const attack = await fetchText(`http://127.0.0.1:${app.port}/?q=${encodeURIComponent('hello; cat /etc/passwd')}`);
      expect(attack.status).toBe(403);
      expect(attack.body).not.toContain('root:');

      const seen = await waitFor(() => JSON.stringify(fake.events).includes('command_injection'));
      expect(seen).toBe(true);
      expect(JSON.stringify(fake.events)).toContain('zero-code-e2e');
    } finally {
      stop(app);
    }
  });

  it('an async raw http handler blocked after an await answers 403 and the process keeps running', async () => {
    let app: App | undefined;
    try {
      app = await startApp(['--require', REGISTER, join(dir, 'async.js')], baseEnv);
      const attack = await fetchText(`http://127.0.0.1:${app.port}/?q=${encodeURIComponent('hi; id')}`);
      expect(attack.status).toBe(403);
      expect(await fetchText(`http://127.0.0.1:${app.port}/?q=ok`)).toEqual({ status: 200, body: 'ok\n' });
      expect(app.child.exitCode).toBeNull();
    } finally {
      stop(app);
    }
  });

  it('--import: an ESM app that takes execSync at load is protected too', async () => {
    let app: App | undefined;
    try {
      app = await startApp(['--import', pathToFileURL(REGISTER).href, join(dir, 'app.mjs')], baseEnv);
      expect((await fetchText(`http://127.0.0.1:${app.port}/?q=hi`)).status).toBe(200);
      const attack = await fetchText(`http://127.0.0.1:${app.port}/?q=${encodeURIComponent('hi && id')}`);
      expect(attack.status).toBe(403);
    } finally {
      stop(app);
    }
  });

  it('NODE_OPTIONS=--require works and a later init() in app code is a no-op', async () => {
    let app: App | undefined;
    try {
      app = await startApp([join(dir, 'double.js')], { ...baseEnv, NODE_OPTIONS: `--require ${JSON.stringify(REGISTER)}` });
      // init({ rasp: false }) in the app did not turn RASP off.
      const attack = await fetchText(`http://127.0.0.1:${app.port}/?q=${encodeURIComponent('x | id')}`);
      expect(attack.status).toBe(403);
      expect(app.stderr().match(/this Shield360\.init\(\) call is ignored/g)).toHaveLength(1);
    } finally {
      stop(app);
    }
  });

  it('NODE_OPTIONS=--require with an ESM app: it starts, and a CommonJS driver it imports is checked', async () => {
    let app: App | undefined;
    try {
      // The preload runs again in Node's module-hooks thread; registering the ESM hook from
      // there made every import fail ("source ... from the load hook but got undefined").
      app = await startApp([join(dir, 'db.mjs')], { ...baseEnv, NODE_OPTIONS: `--require ${JSON.stringify(REGISTER)}` });
      expect(await fetchText(`http://127.0.0.1:${app.port}/?id=7`)).toEqual({ status: 200, body: 'ran' });
      const attack = await fetchText(`http://127.0.0.1:${app.port}/?id=${encodeURIComponent('7 OR 1=1')}`);
      expect(attack.status).toBe(403);
      expect(app.stderr()).not.toMatch(/already been initialized/);
    } finally {
      stop(app);
    }
  });

  it('a Shield360 URL without a key prints nothing but the app, even with stdout captured as logs', () => {
    // SKUFlow, 2026-10-31: no key, so every signal fell back to the console, and stdout capture fed each
    // printed record back in as a new log record (hundreds of lines a second from an idle app).
    writeFileSync(join(dir, 'logger.js'), `
      process.stdout.write(JSON.stringify({ level: 'info', msg: 'started' }) + '\\n');
      setTimeout(() => process.exit(0), 1500);
    `);
    const env: NodeJS.ProcessEnv = { ...baseEnv, SHIELD360_URL: fake.url, SHIELD360_CAPTURE_LOGS: 'true', SHIELD360_CAPTURE_STDIO: 'true', SHIELD360_RASP: 'off', OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL: '200' };
    delete env.SHIELD360_API_KEY;
    delete env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const run = spawnSync(process.execPath, ['--require', REGISTER, join(dir, 'logger.js')], { env, encoding: 'utf8', timeout: 30_000 });
    expect(run.stdout.trim()).toBe('{"level":"info","msg":"started"}');
    expect(run.stderr).not.toContain('telemetry.sdk.name');
    expect(run.stderr.match(/SHIELD360_API_KEY is not set/g)).toHaveLength(1);
  });

  it('with RASP off the app runs unchanged', async () => {
    let app: App | undefined;
    try {
      app = await startApp(['--require', REGISTER, join(dir, 'app.js')], { ...baseEnv, SHIELD360_RASP: 'off' });
      const res = await fetchText(`http://127.0.0.1:${app.port}/?q=${encodeURIComponent('a; echo b')}`);
      expect(res).toEqual({ status: 200, body: 'a\nb\n' });
    } finally {
      stop(app);
    }
  });
});

/**
 * Signed config client: verified only against a pinned key; the response's
 * own keys are never trusted unless allowUnpinnedConfig (trust on first use);
 * JWKS rotation; expiry; ETag; cache re-verification; the kill switch.
 */
import { generateKeyPairSync, sign, type KeyObject } from 'crypto';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { BACKOFF_MS, JWS_TYPE, parsePublicKeys, RaspConfigClient, verifyConfigJws, type RaspClaims } from '../config-client';
import { configureEngine, isActive, modeFor, setRemoteConfig } from '../engine';
import { initRasp, resetRaspWarnings, shutdownRasp, tofuAllowed } from '../index';

type Pair = { kid: string; x: string; priv: KeyObject; pem: string };

function keyPair(kid: string): Pair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { kid, x: jwk.x, priv: privateKey, pem: publicKey.export({ format: 'pem', type: 'spki' }).toString() };
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const NOW = 1_800_000_000;

function claims(over: Partial<RaspClaims> = {}): RaspClaims {
  return { v: 1, app: 'orders-api', iat: NOW, exp: NOW + 3600, version: 'abc123', killSwitch: false, snippets: false, mode: 'monitor', attacks: {}, allow: { commands: [], outboundHosts: [], fileRoots: [] }, rules: null, ...over };
}

function jws(key: Pair, c: RaspClaims, header: Record<string, unknown> = {}): string {
  const head = b64({ alg: 'EdDSA', typ: JWS_TYPE, kid: key.kid, ...header });
  const body = b64(c);
  return `${head}.${body}.${sign(null, Buffer.from(`${head}.${body}`), key.priv).toString('base64url')}`;
}

const jwkOf = (k: Pair) => ({ kty: 'OKP', crv: 'Ed25519', x: k.x, kid: k.kid });

type Served = { status?: number; config?: string; keys?: unknown[]; etag?: string };

function fakeFetch(serve: () => Served) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const impl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, headers: (init?.headers || {}) as Record<string, string> });
    const s = serve();
    const status = s.status ?? 200;
    return new Response(status === 304 ? null : JSON.stringify({ config: s.config, keys: s.keys ?? [] }), {
      status,
      headers: s.etag ? { ETag: s.etag } : {},
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe('verifyConfigJws', () => {
  const k1 = keyPair('k1');
  const k2 = keyPair('k2');
  const pinned = parsePublicKeys(jwkOf(k1));

  it('accepts a config signed by the pinned key', () => {
    const r = verifyConfigJws(jws(k1, claims()), pinned, 'orders-api', NOW);
    expect(r.ok && r.claims.version).toBe('abc123');
  });

  it('refuses another key, whatever kid it names', () => {
    expect(verifyConfigJws(jws(k2, claims()), pinned, 'orders-api', NOW)).toEqual({ ok: false, reason: 'signature' });
    expect(verifyConfigJws(jws({ ...k2, kid: 'k1' }, claims()), pinned, 'orders-api', NOW)).toEqual({ ok: false, reason: 'signature' });
  });

  it('refuses a wrong typ, alg, app, version, or an expired config (60 s skew)', () => {
    expect(verifyConfigJws(jws(k1, claims(), { typ: 'JWT' }), pinned, 'orders-api', NOW)).toMatchObject({ reason: 'typ' });
    expect(verifyConfigJws(jws(k1, claims(), { alg: 'none' }), pinned, 'orders-api', NOW)).toMatchObject({ reason: 'alg' });
    expect(verifyConfigJws(jws(k1, claims({ app: 'other' })), pinned, 'orders-api', NOW)).toMatchObject({ reason: 'app' });
    expect(verifyConfigJws(jws(k1, claims({ v: 2 })), pinned, 'orders-api', NOW)).toMatchObject({ reason: 'version' });
    expect(verifyConfigJws(jws(k1, claims({ exp: NOW - 61 })), pinned, 'orders-api', NOW)).toMatchObject({ reason: 'expired' });
    expect(verifyConfigJws(jws(k1, claims({ exp: NOW - 30 })), pinned, 'orders-api', NOW).ok).toBe(true);
  });

  it('refuses a tampered payload', () => {
    const [h, , s] = jws(k1, claims()).split('.');
    expect(verifyConfigJws(`${h}.${b64(claims({ killSwitch: true }))}.${s}`, pinned, 'orders-api', NOW)).toMatchObject({ reason: 'signature' });
  });

  it('JWKS rotation: either pinned kid verifies; an unpinned kid does not', () => {
    const k3 = keyPair('k3');
    const jwks = parsePublicKeys(JSON.stringify({ keys: [jwkOf(k1), jwkOf(k2)] }));
    expect(jwks).toHaveLength(2);
    expect(verifyConfigJws(jws(k1, claims()), jwks, 'orders-api', NOW).ok).toBe(true);
    expect(verifyConfigJws(jws(k2, claims()), jwks, 'orders-api', NOW).ok).toBe(true);
    expect(verifyConfigJws(jws(k3, claims()), jwks, 'orders-api', NOW).ok).toBe(false);
  });

  it('parses the pinned key as a JWK, a JWKS, or the bare base64url x; refuses anything else', () => {
    expect(parsePublicKeys(k1.x)).toHaveLength(1);
    expect(parsePublicKeys(JSON.stringify(jwkOf(k1)))[0].kid).toBe('k1');
    expect(parsePublicKeys({ keys: [jwkOf(k1)] })[0].x).toBe(k1.x);
    expect(parsePublicKeys(k1.pem)).toEqual([]);
    expect(parsePublicKeys('not-a-key')).toEqual([]);
    expect(parsePublicKeys({ kty: 'RSA', crv: 'x', x: k1.x })).toEqual([]);
    // A bare key (no kid) verifies whatever kid the header names; so does a JWKS when the header's kid is not listed.
    expect(verifyConfigJws(jws(k1, claims()), parsePublicKeys(k1.x), 'orders-api', NOW).ok).toBe(true);
    expect(verifyConfigJws(jws({ ...k1, kid: 'unlisted' }, claims()), parsePublicKeys({ keys: [jwkOf(k2), jwkOf(k1)] }), 'orders-api', NOW).ok).toBe(true);
  });
});

describe('RaspConfigClient', () => {
  const k1 = keyPair('k1');
  const k2 = keyPair('k2');
  let dir: string;
  let applied: (RaspClaims | undefined)[];
  let warnings: string[];
  let now: number;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'rasp-config-'));
    applied = [];
    warnings = [];
    now = NOW * 1000;
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const client = (serve: () => Served, over: Partial<ConstructorParameters<typeof RaspConfigClient>[0]> = {}) => {
    const f = fakeFetch(serve);
    const c = new RaspConfigClient({
      url: 'https://shield.example.com/',
      apiKey: 'test-api-key',
      app: 'orders-api',
      pinned: parsePublicKeys(jwkOf(k1)),
      cacheDir: dir,
      onConfig: (x) => applied.push(x),
      onWarning: (w) => warnings.push(w),
      fetchImpl: f.impl,
      now: () => now,
      ...over,
    });
    return { c, calls: f.calls };
  };

  it('pinned: fetches with the API key and applies a verified config', async () => {
    const { c, calls } = client(() => ({ config: jws(k1, claims()), keys: [jwkOf(k1)], etag: '"e1"' }));
    expect(await c.poll()).toBe('updated');
    expect(calls[0].url).toBe('https://shield.example.com/api/rasp/config?app=orders-api');
    expect(calls[0].headers.Authorization).toBe('Bearer test-api-key');
    expect(applied[0]?.version).toBe('abc123');
  });

  it('a poll still in flight when the client stops applies and caches nothing', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const f = fakeFetch(() => ({ config: jws(k1, claims({ killSwitch: true })), keys: [jwkOf(k1)] }));
    const { c } = client(() => ({}), {
      fetchImpl: (async (url: string, init?: RequestInit) => {
        await gate;
        return f.impl(url, init);
      }) as unknown as typeof fetch,
    });
    const pending = c.poll();
    // RASP re-initialized (another app or key) while the request was out.
    c.stop();
    release();
    await pending;
    expect(applied).toEqual([]);
    expect(readdirSync(dir)).toEqual([]);
  });

  it("pinned: the response's own key is not trusted", async () => {
    const { c } = client(() => ({ config: jws(k2, claims()), keys: [jwkOf(k2)] }));
    expect(await c.poll()).toBe('rejected');
    expect(applied).toEqual([]);
    expect(warnings).toEqual(['signature']);
  });

  it('unpinned: refused without fetching; nothing applied', async () => {
    const { c, calls } = client(() => ({ config: jws(k1, claims()), keys: [jwkOf(k1)] }), { pinned: [] });
    expect(await c.poll()).toBe('rejected');
    expect(calls).toHaveLength(0);
    expect(applied).toEqual([]);
    expect(warnings).toEqual(['unpinned']);
  });

  it('allowUnpinnedConfig: trusts the first key, then refuses a different one', async () => {
    let key = k1;
    const { c } = client(() => ({ config: jws(key, claims()), keys: [jwkOf(key)] }), { pinned: [], allowUnpinned: true });
    expect(await c.poll()).toBe('updated');
    expect(warnings).toContain('trust_on_first_use');
    key = k2;
    expect(await c.poll()).toBe('rejected');
  });

  it('ETag: sends If-None-Match and keeps the config on 304', async () => {
    let status = 200;
    const { c, calls } = client(() => ({ status, config: jws(k1, claims()), etag: '"e1"' }));
    await c.poll();
    status = 304;
    expect(await c.poll()).toBe('unchanged');
    expect(calls[1].headers['If-None-Match']).toBe('"e1"');
    expect(c.current?.version).toBe('abc123');
  });

  it('expiry: an expired config is refused; the one in force is dropped once it expires', async () => {
    const { c: stale } = client(() => ({ config: jws(k1, claims({ exp: NOW - 3600 })) }));
    expect(await stale.poll()).toBe('rejected');
    let up = true;
    const { c } = client(() => (up ? { config: jws(k1, claims({ exp: NOW + 120 })) } : { status: 503 }));
    await c.poll();
    up = false;
    now += 600_000;
    expect(await c.poll()).toBe('failed');
    expect(applied[applied.length - 1]).toBeUndefined();
    expect(c.current).toBeUndefined();
  });

  it('failures back off to 5 minutes; success polls about every minute', () => {
    const { c } = client(() => ({}), { random: () => 1 });
    expect(c.nextDelay('failed')).toBe(BACKOFF_MS);
    expect(c.nextDelay('rejected')).toBe(BACKOFF_MS);
    expect(c.nextDelay('updated')).toBe(70_000);
  });

  it('cache: the last verified config is re-verified on load; a tampered cache is refused', async () => {
    const { c } = client(() => ({ config: jws(k1, claims({ version: 'cached' })) }));
    await c.poll();
    const { c: fresh } = client(() => ({ status: 503 }));
    expect(fresh.loadCache()).toBe(true);
    expect(fresh.current?.version).toBe('cached');
    writeFileSync(fresh.cacheFile(), JSON.stringify({ config: jws(k2, claims({ version: 'forged' })), tofu: [jwkOf(k2)] }));
    const { c: other } = client(() => ({ status: 503 }));
    expect(other.loadCache()).toBe(false);
    expect(other.current).toBeUndefined();
  });

  it('never throws on a network error or a malformed body', async () => {
    const boom = new RaspConfigClient({
      url: 'https://shield.example.com',
      apiKey: 'k',
      app: 'orders-api',
      pinned: parsePublicKeys(jwkOf(k1)),
      cacheDir: dir,
      onConfig: () => undefined,
      fetchImpl: (async () => {
        throw new Error('offline');
      }) as unknown as typeof fetch,
    });
    expect(await boom.poll()).toBe('failed');
    const { c } = client(() => ({ config: 'not.a.jws' }));
    expect(await c.poll()).toBe('rejected');
  });
});

describe('initRasp and the signed config', () => {
  const k1 = keyPair('k1');
  let warn: jest.SpyInstance;
  beforeEach(() => {
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });
  afterEach(async () => {
    warn.mockRestore();
    await shutdownRasp();
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  it('without a pin: no config fetch, built-in defaults in monitor mode, one log line per process, no reported event', async () => {
    resetRaspWarnings();
    const urls: string[] = [];
    const fetchImpl = (async (url: string) => {
      urls.push(String(url));
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
    const ctx = { applicationName: 'orders-api', url: 'https://shield.example.com', apiKey: 'k', env: {}, fetchImpl };
    expect(initRasp({ enabled: true, mode: 'block', attacks: { ssrf: 'off' }, components: false }, ctx)).toBe(true);
    expect(modeFor('sql_injection')).toBe('monitor');
    expect(modeFor('ssrf')).toBe('off');
    initRasp({ enabled: true, components: false }, ctx);
    await shutdownRasp();
    expect(urls.filter((u) => u.includes('/api/rasp/config'))).toEqual([]);
    expect(urls.filter((u) => u.includes('/api/guard/events'))).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('configPublicKey');
  });

  it('trust on first use: only with the opt-in, never in production', async () => {
    expect(tofuAllowed(true, {})).toBe(true);
    expect(tofuAllowed(undefined, { SHIELD360_CONFIG_TOFU: 'dev' })).toBe(true);
    expect(tofuAllowed(undefined, {})).toBe(false);
    expect(tofuAllowed(true, { NODE_ENV: 'production' })).toBe(false);
    expect(tofuAllowed(undefined, { SHIELD360_CONFIG_TOFU: 'dev', ENVIRONMENT: 'production' })).toBe(false);

    resetRaspWarnings();
    const fetchImpl = (async () => new Response('{}', { status: 503 })) as unknown as typeof fetch;
    initRasp({ enabled: true, mode: 'block', allowUnpinnedConfig: true, components: false }, { applicationName: 'a', url: 'https://s.example.com', apiKey: 'k', env: { NODE_ENV: 'production' }, fetchImpl });
    expect(modeFor('sql_injection')).toBe('monitor');
    const dir = mkdtempSync(join(tmpdir(), 'rasp-tofu-'));
    initRasp({ enabled: true, mode: 'block', components: false, cacheDir: dir }, { applicationName: 'a', url: 'https://s.example.com', apiKey: 'k', env: { SHIELD360_CONFIG_TOFU: 'dev' }, fetchImpl });
    expect(modeFor('sql_injection')).toBe('block');
    rmSync(dir, { recursive: true, force: true });
  });

  it('with a pin from SHIELD360_CONFIG_PUBLIC_KEY: the signed kill switch turns checks off', async () => {
    const fetchImpl = (async (url: string) =>
      String(url).includes('/api/rasp/config')
        ? new Response(JSON.stringify({ config: jws(k1, claims({ exp: Math.floor(Date.now() / 1000) + 600, killSwitch: true })) }), { status: 200 })
        : new Response('{}')) as unknown as typeof fetch;
    const cacheDir = mkdtempSync(join(tmpdir(), 'rasp-init-'));
    initRasp(
      { enabled: true, components: false, cacheDir },
      { applicationName: 'orders-api', url: 'https://shield.example.com', apiKey: 'k', env: { SHIELD360_CONFIG_PUBLIC_KEY: JSON.stringify({ keys: [jwkOf(k1)] }) }, fetchImpl },
    );
    expect(isActive()).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    expect(isActive()).toBe(false);
    rmSync(cacheDir, { recursive: true, force: true });
  });

  it('SHIELD360_RASP=off wins over enabled: true; no URL means local options only', () => {
    expect(initRasp({ enabled: true }, { applicationName: 'a', env: { SHIELD360_RASP: 'off' } })).toBe(false);
    expect(initRasp({ enabled: true, mode: 'block' }, { applicationName: 'a', env: {} })).toBe(true);
    expect(modeFor('sql_injection')).toBe('block');
    expect(initRasp(undefined, { applicationName: 'a', env: { SHIELD360_RASP: 'monitor' } })).toBe(true);
    expect(initRasp(undefined, { applicationName: 'a', env: {} })).toBe(false);
    setRemoteConfig(undefined);
  });
});

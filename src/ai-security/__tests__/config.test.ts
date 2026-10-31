import { generateKeyPairSync, sign } from 'crypto';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ConfigClient, CONFIG_JWS_TYPE, pinnedKeysFrom, publicKeyFrom, verifyPolicy } from '../config';
import { configureAiSecurity, currentPolicy, resetAiSecurity } from '../index';
import { MemorySink } from '../events';

const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, jwk };
}

function token(privateKey: ReturnType<typeof keypair>['privateKey'], claims: object, typ = CONFIG_JWS_TYPE) {
  const input = `${b64({ alg: 'EdDSA', typ, kid: 'k1' })}.${b64(claims)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

const NOW = 1_800_000_000_000;
const claims = (over: object = {}) => ({ app: 'shop', policy: { output: { mode: 'enforce' } }, ver: 3, iat: NOW / 1000, exp: NOW / 1000 + 600, ...over });

describe('signed config', () => {
  const k = keypair();
  const key = publicKeyFrom(k.jwk)!;

  it('verifies a policy for this app', () => {
    expect(verifyPolicy(token(k.privateKey, claims()), key, 'shop', NOW)).toMatchObject({ app: 'shop', ver: 3 });
  });
  it('refuses another app, an expired token, another type and a tampered body', () => {
    expect(verifyPolicy(token(k.privateKey, claims({ app: 'other' })), key, 'shop', NOW)).toBeNull();
    expect(verifyPolicy(token(k.privateKey, claims({ exp: NOW / 1000 - 1 })), key, 'shop', NOW)).toBeNull();
    expect(verifyPolicy(token(k.privateKey, claims(), 'JWT'), key, 'shop', NOW)).toBeNull();
    const t = token(k.privateKey, claims()).split('.');
    expect(verifyPolicy(`${t[0]}.${b64(claims({ policy: { output: { mode: 'off' } } }))}.${t[2]}`, key, 'shop', NOW)).toBeNull();
  });
  it('refuses a token signed by another key', () => {
    const other = keypair();
    expect(verifyPolicy(token(other.privateKey, claims()), key, 'shop', NOW)).toBeNull();
  });

  const client = (answers: unknown[], extra: Record<string, unknown> = {}) => {
    const got: number[] = [];
    let i = 0;
    const fetched: string[] = [];
    const c = new ConfigClient({
      url: 'https://s360.test',
      apiKey: 'k',
      app: 'shop',
      now: () => NOW,
      fetch: (async (url: string) => {
        fetched.push(url);
        return { ok: true, json: async () => answers[i++] };
      }) as unknown as typeof fetch,
      onPolicy: (p) => got.push(p.ver),
      ...extra,
    });
    return { c, got, fetched };
  };

  it('refuses everything without a pinned key, even a validly signed answer, and never fetches', async () => {
    const saved = process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    delete process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    const { c, got, fetched } = client([{ jws: token(k.privateKey, claims()), publicKey: k.jwk }]);
    expect(c.usable).toBe(false);
    expect(await c.refresh()).toBe(false);
    expect(got).toEqual([]);
    expect(fetched).toEqual([]);
    if (saved !== undefined) process.env.SHIELD360_CONFIG_PUBLIC_KEY = saved;
  });

  it('accepts an answer signed by the pinned key, and refuses one whose sent key differs from the pin', async () => {
    const other = keypair();
    const pinned = client([{ jws: token(k.privateKey, claims()), publicKey: other.jwk }], { publicKey: k.jwk });
    expect(await pinned.c.refresh()).toBe(true);
    expect(pinned.got).toEqual([3]);
    const forged = client([{ jws: token(other.privateKey, claims()), publicKey: other.jwk }], { publicKey: k.jwk });
    expect(await forged.c.refresh()).toBe(false);
  });

  it('rotates through a JWKS of several pinned keys, and reads the pin from the environment', async () => {
    const next = keypair();
    const jwks = { keys: [{ ...k.jwk, kid: 'old' }, { ...next.jwk, kid: 'new' }] };
    expect(pinnedKeysFrom(jwks)).toHaveLength(2);
    const rotated = client([{ jws: token(k.privateKey, claims()) }, { jws: token(next.privateKey, claims({ ver: 4 })) }], { publicKey: jwks });
    expect(await rotated.c.refresh()).toBe(true);
    expect(await rotated.c.refresh()).toBe(true);
    expect(rotated.got).toEqual([3, 4]);
    const saved = process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    process.env.SHIELD360_CONFIG_PUBLIC_KEY = JSON.stringify(jwks);
    const fromEnv = client([{ jws: token(next.privateKey, claims()) }]);
    expect(await fromEnv.c.refresh()).toBe(true);
    if (saved === undefined) delete process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    else process.env.SHIELD360_CONFIG_PUBLIC_KEY = saved;
  });

  it('without a pin, runs the policy from code and reports it once', () => {
    const saved = process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    delete process.env.SHIELD360_CONFIG_PUBLIC_KEY;
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const sink = new MemorySink();
    configureAiSecurity({ url: 'https://s360.test', apiKey: 'k', app: 'shop', sink, fetch: (async () => { throw new Error('no'); }) as unknown as typeof fetch });
    expect(sink.events.filter((e) => e.kind === 'config_unpinned')).toHaveLength(1);
    expect(currentPolicy().output.mode).toBe('monitor');
    warn.mockRestore();
    resetAiSecurity();
    if (saved !== undefined) process.env.SHIELD360_CONFIG_PUBLIC_KEY = saved;
  });

  it('development only: trusts the first key seen when allowed, then refuses answers signed by another', async () => {
    const other = keypair();
    const answers = [
      { jws: token(k.privateKey, claims()), publicKey: k.jwk },
      { jws: token(other.privateKey, claims({ ver: 4 })), publicKey: other.jwk },
    ];
    const got: number[] = [];
    let i = 0;
    const client = new ConfigClient({
      url: 'https://s360.test',
      apiKey: 'k',
      app: 'shop',
      now: () => NOW,
      fetch: (async () => ({ ok: true, json: async () => answers[i++] })) as unknown as typeof fetch,
      onPolicy: (p) => got.push(p.ver),
      allowUnpinned: true,
    });
    expect(await client.refresh()).toBe(true);
    expect(await client.refresh()).toBe(false);
    expect(got).toEqual([3]);
  });

  it('honours a configured public key and caches verified answers to a file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 's360-'));
    const cacheFile = join(dir, 'policy.json');
    const answer = { jws: token(k.privateKey, claims()), publicKey: k.jwk };
    const seen: number[] = [];
    const client = new ConfigClient({
      url: 'https://s360.test',
      apiKey: 'k',
      app: 'shop',
      publicKey: k.jwk,
      cacheFile,
      now: () => NOW,
      fetch: (async () => ({ ok: true, json: async () => answer })) as unknown as typeof fetch,
      onPolicy: (p) => seen.push(p.ver),
    });
    expect(await client.refresh()).toBe(true);
    expect(JSON.parse(readFileSync(cacheFile, 'utf8')).jws).toBe(answer.jws);
    // A restart with the platform down starts from the cache.
    const restarted: number[] = [];
    const offline = new ConfigClient({
      url: 'https://s360.test',
      apiKey: 'k',
      app: 'shop',
      publicKey: k.jwk,
      cacheFile,
      refreshSeconds: 3600,
      now: () => NOW,
      fetch: (async () => {
        throw new Error('down');
      }) as unknown as typeof fetch,
      onPolicy: (p) => restarted.push(p.ver),
    });
    await offline.start();
    offline.stop();
    expect(restarted).toEqual([3]);
  });
});

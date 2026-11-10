/**
 * The agent request signer: the key is made and kept locally (never sent),
 * registration sends the public key and a directory signature the server can
 * check, the refresh keeps it fresh, and signed requests verify with the
 * agent verifier against the published directory. Signing never breaks a
 * request. The Shield360 app is a fake fetch.
 */
import { createPublicKey, verify, generateKeyPairSync } from 'crypto';
import { mkdtempSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { agentSigner, agentVerifier } from '../index';
import { directorySignatureBase, loadOrCreateKey } from '../signer';
import { jwkThumbprint } from '../web-bot-auth';

const BASE = 'https://app.shield360.test';
const AUTHORITY = 'acme.agents.shield360.test';
const SIGNATURE_AGENT = `https://${AUTHORITY}/.well-known/http-message-signatures-directory`;

type Registered = { publicKey: string; label?: string; directorySignature: { created: number; expires: number; signature: string } };

/** A fake Shield360 app: the signer route, the key route (checking the directory signature as the server does) and the directory. */
function app(opts: { signerStatus?: number } = {}) {
  const registered: Registered[] = [];
  const calls: { url: string; method: string; headers: Headers; body?: string }[] = [];
  const f = (async (input: string | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    const headers = new Headers(init.headers ?? (typeof input === 'string' ? undefined : input.headers));
    calls.push({ url, method: init.method ?? 'GET', headers, body: init.body as string | undefined });
    if (url === `${BASE}/api/agent-signing/sdk/signer`) {
      if (opts.signerStatus && opts.signerStatus !== 200) return new Response(JSON.stringify({ err: 'Set a signer name first.' }), { status: opts.signerStatus });
      return new Response(JSON.stringify({ name: 'acme', authority: AUTHORITY, directoryUrl: SIGNATURE_AGENT, signatureAgent: SIGNATURE_AGENT, refreshAfterSeconds: 21600 }), { status: 200 });
    }
    if (url === `${BASE}/api/agent-signing/sdk/keys`) {
      const body = JSON.parse(String(init.body)) as Registered;
      const { created, expires, signature } = body.directorySignature;
      const keyId = jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: body.publicKey });
      const ok = verify(null, Buffer.from(directorySignatureBase(AUTHORITY, created, expires, keyId)), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: body.publicKey }, format: 'jwk' }), Buffer.from(signature, 'base64'));
      if (!ok) return new Response(JSON.stringify({ err: 'bad signature' }), { status: 400 });
      registered.push(body);
      return new Response(JSON.stringify({ keyId, signatureAgent: SIGNATURE_AGENT, directoryUrl: SIGNATURE_AGENT, refreshAfterSeconds: 21600 }), { status: registered.length === 1 ? 201 : 200 });
    }
    if (url === SIGNATURE_AGENT) {
      return new Response(JSON.stringify({ keys: registered.map((r) => ({ kty: 'OKP', crv: 'Ed25519', x: r.publicKey })) }), { status: 200 });
    }
    return new Response('ok', { status: 200 });
  }) as unknown as typeof fetch;
  return { fetch: f, registered, calls };
}

const tmpKeyFile = () => join(mkdtempSync(join(tmpdir(), 's360-signer-')), 'nested', 'key.json');

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

describe('the signing key', () => {
  it('is made on first use in a 0600 file and reused after', () => {
    const file = tmpKeyFile();
    const a = loadOrCreateKey({ keyFile: file }, {});
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ kty: 'OKP', crv: 'Ed25519', d: expect.any(String) });
    expect(loadOrCreateKey({ keyFile: file }, {}).keyId).toBe(a.keyId);
  });

  it('can come from the options or SHIELD360_AGENT_SIGNING_KEY, as PEM or JWK', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const jwk = JSON.stringify(privateKey.export({ format: 'jwk' }));
    const fromPem = loadOrCreateKey({ privateKey: pem }, {});
    expect(loadOrCreateKey({}, { SHIELD360_AGENT_SIGNING_KEY: jwk }).keyId).toBe(fromPem.keyId);
  });

  it('refuses a key that is not Ed25519', () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(() => loadOrCreateKey({ privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() }, {})).toThrow(/Ed25519/);
  });
});

describe('registering', () => {
  it('sends the public key and a directory signature, never the private key', async () => {
    const a = app();
    const signer = agentSigner({ apiKey: 'k', baseUrl: BASE, keyFile: tmpKeyFile(), label: 'worker-1', fetch: a.fetch });
    const info = await signer.ready();
    signer.close();
    expect(info.signatureAgent).toBe(SIGNATURE_AGENT);
    expect(a.registered).toHaveLength(1);
    expect(a.registered[0].label).toBe('worker-1');
    const posted = a.calls.find((c) => c.url.endsWith('/sdk/keys'));
    expect(posted?.headers.get('authorization')).toBe('Bearer k');
    expect(posted?.body).not.toMatch(/"d"/);
    const { created, expires } = a.registered[0].directorySignature;
    expect(expires - created).toBe(2 * 86_400);
  });

  it('registers once for concurrent callers, and refreshes on the schedule', async () => {
    jest.useFakeTimers();
    const a = app();
    const signer = agentSigner({ apiKey: 'k', baseUrl: BASE, keyFile: tmpKeyFile(), fetch: a.fetch });
    await Promise.all([signer.ready(), signer.ready(), signer.headers('https://api.example.com/')]);
    expect(a.registered).toHaveLength(1);
    await jest.advanceTimersByTimeAsync(21_600 * 1000);
    expect(a.registered).toHaveLength(2);
    signer.close();
  });
});

describe('signing requests', () => {
  it('produces requests the agent verifier accepts against the published directory', async () => {
    const a = app();
    const signer = agentSigner({ apiKey: 'k', baseUrl: BASE, keyFile: tmpKeyFile(), fetch: a.fetch });
    const headers = await signer.headers({ url: 'https://api.servflo.ai/v1/jobs?x=1', method: 'POST' });
    signer.close();
    expect(headers['Signature-Agent']).toBe(`"${SIGNATURE_AGENT}"`);
    expect(headers['Signature-Input']).toMatch(/^sig1=\("@authority" "signature-agent"\);created=\d+;expires=\d+;keyid="[A-Za-z0-9_-]{43}";alg="ed25519";nonce="[A-Za-z0-9+/]{86}==";tag="web-bot-auth"$/);
    const verifier = agentVerifier({ audience: 'api.servflo.ai', fetch: a.fetch });
    const r = await verifier.check(new Request('https://api.servflo.ai/v1/jobs?x=1', { method: 'POST', headers }));
    expect(r).toMatchObject({ status: 'verified', via: 'web-bot-auth', operator: { domain: AUTHORITY } });
    // Each signature has its own nonce.
    expect((await signer.headers('https://api.servflo.ai/'))['Signature-Input']).not.toBe(headers['Signature-Input']);
  });

  it('signs through fetch and keeps the caller\'s headers', async () => {
    const a = app();
    const signer = agentSigner({ apiKey: 'k', baseUrl: BASE, keyFile: tmpKeyFile(), fetch: a.fetch });
    await signer.fetch('https://api.servflo.ai/v1/jobs', { method: 'POST', headers: { 'X-Trace': '1' }, body: '{}' });
    signer.close();
    const sent = a.calls.find((c) => c.url === 'https://api.servflo.ai/v1/jobs');
    expect(sent?.headers.get('x-trace')).toBe('1');
    expect(sent?.headers.get('signature-input')).toContain('web-bot-auth');
  });

  it('sends requests unsigned, warning once, when the signer cannot be set up', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const a = app({ signerStatus: 409 });
    const signer = agentSigner({ apiKey: 'k', baseUrl: BASE, keyFile: tmpKeyFile(), fetch: a.fetch });
    expect(await signer.headers('https://api.servflo.ai/')).toEqual({});
    const res = await signer.fetch('https://api.servflo.ai/v1/jobs');
    signer.close();
    expect(res.status).toBe(200);
    expect(a.calls.find((c) => c.url === 'https://api.servflo.ai/v1/jobs')?.headers.get('signature')).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('409');
  });

  it('needs an API key', () => {
    expect(() => agentSigner({ apiKey: '' })).toThrow(/apiKey/);
  });
});

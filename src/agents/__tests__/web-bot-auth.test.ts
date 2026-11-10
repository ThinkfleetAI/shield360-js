/**
 * Web Bot Auth on the agent verifier: signatures in both Signature-Agent forms
 * (the draft's dictionary and Cloudflare's bare string), every failure reason,
 * the key directory's rules and the receiver policy. The signatures here are
 * built from hand-written signature bases, not from the code under test.
 * Interop with Cloudflare's own web-bot-auth library was checked separately
 * (see the PR).
 */
import { generateKeyPairSync, KeyObject, sign } from 'crypto';
import { IncomingMessage } from 'http';
import { Socket } from 'net';
import { agentVerifier, AgentCheck, AgentVerifierOptions } from '../index';
import { directoryUrl, jwkThumbprint } from '../web-bot-auth';
import { parseDictionary, serializeInnerList } from '../structured';

const T0 = Date.UTC(2026, 10, 9, 12, 0, 0);
const NOW = Math.floor(T0 / 1000);
const SIGNER = 'https://signer.example.com';
const WELL_KNOWN = `${SIGNER}/.well-known/http-message-signatures-directory`;

type Key = { privateKey: KeyObject; jwk: { kty: string; crv: string; x: string }; keyId: string };

function makeKey(): Key {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  return { privateKey, jwk, keyId: jwkThumbprint(jwk) };
}

type Net = { calls: string[]; fetch: typeof fetch };

function directory(keys: Record<string, unknown>[], status = 200): Net {
  const calls: string[] = [];
  const f = (async (url: string) => {
    calls.push(String(url));
    if (status !== 200) return new Response('', { status, headers: status === 302 ? { location: 'https://elsewhere.example/' } : {} });
    return new Response(JSON.stringify({ keys }), { status: 200, headers: { 'content-type': 'application/http-message-signatures-directory+json' } });
  }) as unknown as typeof fetch;
  return { calls, fetch: f };
}

type SignOpts = {
  key: Key;
  form?: 'legacy' | 'dictionary';
  authority?: string;
  created?: number;
  expires?: number;
  nonce?: string | null;
  agent?: string;
  /** Extra covered components and their values, in order, after the required two. */
  extra?: [string, string][];
  tag?: string;
};

/** Signed headers for a request to `authority`, the signature base written out by hand. */
function signed(o: SignOpts): Record<string, string> {
  const form = o.form ?? 'legacy';
  const authority = o.authority ?? 'api.servflo.ai';
  const created = o.created ?? NOW;
  const expires = o.expires ?? NOW + 60;
  const nonce = o.nonce === undefined ? 'n-1' : o.nonce;
  const agent = o.agent ?? SIGNER;
  const agentHeader = form === 'legacy' ? `"${agent}"` : `sig1="${agent}"`;
  const agentComponent = form === 'legacy' ? '"signature-agent"' : '"signature-agent";key="sig1"';
  const components = ['"@authority"', agentComponent, ...(o.extra ?? []).map(([c]) => c)];
  const params = `;created=${created};expires=${expires};keyid="${o.key.keyId}";alg="ed25519"${nonce ? `;nonce="${nonce}"` : ''};tag="${o.tag ?? 'web-bot-auth'}"`;
  const sigParams = `(${components.join(' ')})${params}`;
  const base = [`"@authority": ${authority}`, `${agentComponent}: "${agent}"`, ...(o.extra ?? []).map(([c, v]) => `${c}: ${v}`), `"@signature-params": ${sigParams}`].join('\n');
  const signature = sign(null, Buffer.from(base), o.key.privateKey).toString('base64');
  return { host: authority, 'signature-agent': agentHeader, 'signature-input': `sig1=${sigParams}`, signature: `sig1=:${signature}:` };
}

function verifier(net: Net, over: Partial<AgentVerifierOptions> = {}) {
  return agentVerifier({ audience: 'api.servflo.ai', clock: () => T0, fetch: net.fetch, ...over });
}

function incoming(headers: Record<string, string>, method = 'GET', url = '/'): IncomingMessage {
  const req = new IncomingMessage(new Socket());
  req.headers = headers;
  req.method = method;
  req.url = url;
  return req;
}

describe('Web Bot Auth: signatures that verify', () => {
  it("verifies Cloudflare's bare-string Signature-Agent and fetches the well-known directory", async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    const r = await verifier(net).check(signed({ key }));
    expect(r).toMatchObject<Partial<AgentCheck>>({
      status: 'verified',
      decision: 'allow',
      blocked: false,
      via: 'web-bot-auth',
      agent: { id: 'signer.example.com', name: 'signer.example.com' },
      operator: { id: 'signer.example.com', name: 'signer.example.com', domain: 'signer.example.com' },
      issuer: SIGNER,
      signature: { agent: SIGNER, keyId: key.keyId },
      expiresAt: new Date((NOW + 60) * 1000).toISOString(),
    });
    expect(r.onBehalfOf).toBeUndefined();
    expect(net.calls).toEqual([WELL_KNOWN]);
  });

  it("verifies the draft's dictionary form", async () => {
    const key = makeKey();
    const r = await verifier(directory([key.jwk])).check(signed({ key, form: 'dictionary' }));
    expect(r.status).toBe('verified');
  });

  it('covers the method, path and query of a Node request', async () => {
    const key = makeKey();
    const headers = signed({ key, form: 'dictionary', extra: [['"@method"', 'POST'], ['"@path"', '/v1/jobs'], ['"@query"', '?page=2']] });
    const net = directory([key.jwk]);
    expect((await verifier(net).check(incoming(headers, 'POST', '/v1/jobs?page=2'))).status).toBe('verified');
    // The same signature on another path does not verify.
    const again = signed({ key, form: 'dictionary', nonce: 'n-2', extra: [['"@method"', 'POST'], ['"@path"', '/v1/jobs'], ['"@query"', '?page=2']] });
    const r = await verifier(net).check(incoming(again, 'POST', '/v1/admin?page=2'));
    expect(r).toMatchObject({ status: 'invalid', decision: 'deny', reason: 'bad_signature', via: 'web-bot-auth' });
  });

  it('reads a fetch Request, whose host comes from its URL', async () => {
    const key = makeKey();
    const { host: _host, ...headers } = signed({ key });
    const r = await verifier(directory([key.jwk])).check(new Request('https://api.servflo.ai/v1/jobs', { headers }));
    expect(r.status).toBe('verified');
  });

  it('caches the directory', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    const v = verifier(net);
    await v.check(signed({ key, nonce: 'a' }));
    await v.check(signed({ key, nonce: 'b' }));
    expect(net.calls).toHaveLength(1);
  });

  it('reads the directory from a Signature-Agent URL with a path', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    const r = await verifier(net).check(signed({ key, agent: 'https://signer.example.com/keys.json' }));
    expect(r.status).toBe('verified');
    expect(net.calls).toEqual(['https://signer.example.com/keys.json']);
  });
});

describe('Web Bot Auth: signatures that do not verify', () => {
  const cases: [string, (k: Key) => SignOpts, string][] = [
    ['expired', (key) => ({ key, created: NOW - 600, expires: NOW - 300 }), 'expired'],
    ['created in the future', (key) => ({ key, created: NOW + 600, expires: NOW + 900 }), 'not_yet_valid'],
    ['valid for more than a day', (key) => ({ key, created: NOW - 10, expires: NOW + 86_400 }), 'lifetime_too_long'],
    ['expires before it was created', (key) => ({ key, created: NOW + 10, expires: NOW }), 'malformed'],
    ['signed for another site', (key) => ({ key, authority: 'shop.example.org' }), 'wrong_audience'],
    ['an http signer', (key) => ({ key, agent: 'http://signer.example.com' }), 'untrusted_signature_agent'],
    ['a signer at an IP address', (key) => ({ key, agent: 'https://10.0.0.5' }), 'untrusted_signature_agent'],
    ['a signer on a private name', (key) => ({ key, agent: 'https://keys.internal' }), 'untrusted_signature_agent'],
    ['a component it cannot rebuild', (key) => ({ key, extra: [['"@status"', '200']] }), 'unsupported_component'],
  ];
  it.each(cases)('%s', async (_name, opts, reason) => {
    const key = makeKey();
    const net = directory([key.jwk]);
    const r = await verifier(net).check(signed(opts(key)));
    expect(r).toMatchObject({ status: 'invalid', decision: 'deny', reason, via: 'web-bot-auth' });
  });

  it('refuses a signature presented twice, with or without a nonce', async () => {
    const key = makeKey();
    const v = verifier(directory([key.jwk]));
    for (const nonce of ['once', null]) {
      const h = signed({ key, nonce });
      expect((await v.check(h)).status).toBe('verified');
      expect(await v.check(h)).toMatchObject({ status: 'invalid', reason: 'replayed' });
    }
  });

  it('refuses a key the directory does not list, or lists as expired', async () => {
    const key = makeKey();
    const other = makeKey();
    expect(await verifier(directory([other.jwk])).check(signed({ key }))).toMatchObject({ status: 'invalid', reason: 'unknown_key' });
    expect(await verifier(directory([{ ...key.jwk, exp: NOW - 3600 }])).check(signed({ key }))).toMatchObject({ status: 'invalid', reason: 'unknown_key' });
  });

  it('refuses a signature by a different key than the one named', async () => {
    const key = makeKey();
    const thief = makeKey();
    const h = signed({ key: { ...thief, keyId: key.keyId } });
    expect(await verifier(directory([key.jwk])).check(h)).toMatchObject({ status: 'invalid', reason: 'bad_signature' });
  });

  it('requires the signature to cover the Signature-Agent', async () => {
    const key = makeKey();
    const h = signed({ key });
    h['signature-input'] = h['signature-input'].replace(' "signature-agent"', '');
    expect(await verifier(directory([key.jwk])).check(h)).toMatchObject({ status: 'invalid', reason: 'malformed' });
  });

  it('never takes a private key from a directory', async () => {
    const key = makeKey();
    const priv = key.privateKey.export({ format: 'jwk' });
    expect(await verifier(directory([priv as Record<string, unknown>])).check(signed({ key }))).toMatchObject({ status: 'invalid', reason: 'unknown_key' });
  });
});

describe('Web Bot Auth: when the directory cannot be read', () => {
  it('treats the call as unsigned: allowed unless the policy requires an agent', async () => {
    const key = makeKey();
    for (const status of [500, 302]) {
      const net = directory([key.jwk], status);
      expect(await verifier(net).check(signed({ key }))).toMatchObject({ status: 'absent', decision: 'allow', reason: 'directory_unreachable' });
      const strict = verifier(net, { policy: { requireAgent: true, mode: 'enforce' } });
      expect(await strict.check(signed({ key, nonce: 'x' }))).toMatchObject({ status: 'absent', decision: 'deny', blocked: true });
    }
  });
});

describe('Web Bot Auth: outbound fetches', () => {
  it('starts at most 30 directory fetches a minute, whatever signers callers name', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    let t = T0;
    const v = verifier(net, { clock: () => t });
    for (let i = 0; i < 40; i++) await v.check(signed({ key, agent: `https://signer${i}.example.com`, nonce: `n${i}` }));
    expect(net.calls).toHaveLength(30);
    // Over the budget, a call reads as unsigned, never as denied.
    expect(await v.check(signed({ key, agent: 'https://late.example.com', nonce: 'late' }))).toMatchObject({ status: 'absent', reason: 'directory_unreachable' });
    t += 61_000;
    const later = signed({ key, agent: 'https://late.example.com', nonce: 'later', created: Math.floor(t / 1000), expires: Math.floor(t / 1000) + 60 });
    expect((await v.check(later)).status).toBe('verified');
  });
});

describe('Web Bot Auth and the receiver policy', () => {
  it('applies the operators list to the signer host', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    expect((await verifier(net, { policy: { operators: ['signer.example.com'] } }).check(signed({ key }))).decision).toBe('allow');
    const denied = await verifier(net, { policy: { operators: ['acme.com'], mode: 'enforce' } }).check(signed({ key, nonce: 'z' }));
    expect(denied).toMatchObject({ status: 'verified', decision: 'deny', blocked: true, reason: 'operator_not_allowed' });
  });

  it('denies a signature when the policy wants a person behind the agent', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    expect(await verifier(net, { policy: { requireOnBehalfOf: true } }).check(signed({ key }))).toMatchObject({ decision: 'deny', reason: 'on_behalf_of_required' });
    expect(await verifier(net, { policy: { minAssurance: 'named' } }).check(signed({ key, nonce: 'q' }))).toMatchObject({ decision: 'deny', reason: 'assurance_too_low' });
  });

  it('ignores signatures when switched off, and signatures not tagged web-bot-auth', async () => {
    const key = makeKey();
    const net = directory([key.jwk]);
    expect((await verifier(net, { webBotAuth: false }).check(signed({ key }))).status).toBe('absent');
    expect((await verifier(net).check(signed({ key, tag: 'something-else' }))).status).toBe('absent');
    expect(net.calls).toHaveLength(0);
  });
});

describe('Web Bot Auth helpers', () => {
  it('computes the RFC 9421 Ed25519 test key thumbprint', () => {
    expect(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs' })).toBe('poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U');
  });

  it('round-trips a Signature-Input member byte for byte', () => {
    const v = '("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="k";alg="ed25519";nonce="a/b+c==";tag="web-bot-auth"';
    const m = parseDictionary(`sig1=${v}`).get('sig1');
    expect(m?.kind).toBe('list');
    expect(serializeInnerList(m as never)).toBe(v);
  });

  it('finds the directory of a Signature-Agent', () => {
    expect(directoryUrl('https://Signer.Example.com')).toEqual({ url: WELL_KNOWN, host: 'signer.example.com' });
    expect(directoryUrl('https://signer.example.com:8443')).toBeNull();
    expect(directoryUrl('https://user@signer.example.com')).toBeNull();
    expect(directoryUrl('https://localhost')).toBeNull();
  });
});

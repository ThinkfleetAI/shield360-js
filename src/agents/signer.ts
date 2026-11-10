/**
 * The agent request signer: signs the requests your agent sends with Web Bot
 * Auth (RFC 9421), under your Shield360 environment's signer, so websites and
 * Cloudflare can check they come from your organization.
 *
 *   import { agentSigner } from 'shield360/agents';
 *   const signer = agentSigner({ apiKey: process.env.SHIELD360_API_KEY! });
 *   const res = await signer.fetch('https://api.example.com/v1/orders');
 *
 * The private key is made and kept where the agent runs and never leaves it:
 * only the public key, and the agent's own signature over its key directory,
 * go to Shield360, which publishes them at the signer's address. The signer
 * re-registers every few hours to keep that directory signature fresh.
 *
 * Signing never breaks a request: when the signer cannot be set up, requests
 * go out unsigned and a warning is logged once.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_signer.py
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject, randomBytes, sign } from 'crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { homedir, hostname } from 'os';
import { dirname, join } from 'path';
import { baseUrlOf } from './policy';
import { jwkThumbprint, WEB_BOT_AUTH_TAG } from './web-bot-auth';

/** How long each request signature is valid. */
export const REQUEST_SIGNATURE_SECONDS = 60;
/** How long each directory signature is valid: refreshed long before it ends. */
export const DIRECTORY_SIGNATURE_SECONDS = 2 * 24 * 60 * 60;
const DIRECTORY_TAG = 'http-message-signatures-directory';
const DEFAULT_REFRESH_SECONDS = 6 * 60 * 60;
const RETRY_SECONDS = [30, 120, 600];
const TIMEOUT_MS = 10_000;

export type AgentSignerOptions = {
  /** The environment's Shield360 API key. */
  apiKey: string;
  baseUrl?: string;
  /** How this agent shows in the console's key list: a host or agent name. Default: the host name. */
  label?: string;
  /**
   * The private key, as a PKCS#8 PEM or an Ed25519 private JWK (JSON). Use it
   * to share one key between replicas through your secrets manager. Default:
   * SHIELD360_AGENT_SIGNING_KEY, else the key file.
   */
  privateKey?: string;
  /** Where the key is kept when none is given; made on first use (mode 0600). Default ~/.shield360/agent-signing-key.json. */
  keyFile?: string;
  fetch?: typeof fetch;
  /** Milliseconds since the epoch; for tests. */
  clock?: () => number;
};

export type SignerInfo = { keyId: string; signatureAgent: string; directoryUrl: string };

export type SignableRequest = { url: string; method?: string };

export type AgentSigner = {
  /** Registers the key (once; later calls share it). Rejects when the signer cannot be set up. */
  ready(): Promise<SignerInfo>;
  /** The headers that sign a request to this URL: Signature-Agent, Signature-Input, Signature. Empty when signing is not set up. */
  headers(request: SignableRequest | string): Promise<Record<string, string>>;
  /** fetch, with the request signed. */
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  /** Stops the refresh timer. */
  close(): void;
};

/** host[:port] of a URL as @authority covers it: lower case, default port removed. */
export function authorityOf(url: string): string {
  const u = new URL(url);
  return u.host.toLowerCase();
}

type Key = { privateKey: KeyObject; x: string; keyId: string };

function keyFrom(privateKey: KeyObject): Key {
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) throw new Error('Shield360 agent signer: the signing key must be Ed25519');
  return { privateKey, x: jwk.x, keyId: jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: jwk.x }) };
}

function parsePrivateKey(text: string): KeyObject {
  const t = text.trim();
  if (t.startsWith('{')) return createPrivateKey({ key: JSON.parse(t), format: 'jwk' });
  return createPrivateKey(t);
}

/** The key: given, from SHIELD360_AGENT_SIGNING_KEY, or from the key file (made on first use). */
export function loadOrCreateKey(options: Pick<AgentSignerOptions, 'privateKey' | 'keyFile'>, env: NodeJS.ProcessEnv = process.env): Key {
  const given = options.privateKey ?? env.SHIELD360_AGENT_SIGNING_KEY;
  if (given) return keyFrom(parsePrivateKey(given));
  const file = options.keyFile ?? join(homedir(), '.shield360', 'agent-signing-key.json');
  if (existsSync(file)) return keyFrom(parsePrivateKey(readFileSync(file, 'utf8')));
  const { privateKey } = generateKeyPairSync('ed25519');
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(file, JSON.stringify(privateKey.export({ format: 'jwk' })), { mode: 0o600, flag: 'wx' });
  } catch (err) {
    // Another process made it first: use that one, so every process signs with the same key.
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return keyFrom(parsePrivateKey(readFileSync(file, 'utf8')));
    throw err;
  }
  try {
    chmodSync(file, 0o600);
  } catch {
    // best effort on file systems without modes
  }
  return keyFrom(privateKey);
}

/** The directory signature base (the server checks exactly this; see the app's agent-signing/directory.ts). */
export function directorySignatureBase(authority: string, created: number, expires: number, keyId: string): string {
  return `"@authority";req: ${authority}\n"@signature-params": ("@authority";req);created=${created};expires=${expires};keyid="${keyId}";alg="ed25519";tag="${DIRECTORY_TAG}"`;
}

/**
 * The Web Bot Auth headers for a request, in the form Cloudflare verifies: a
 * bare-string Signature-Agent, covering @authority and signature-agent.
 */
export function signRequest(key: Key, signatureAgent: string, url: string, nowSeconds: number): Record<string, string> {
  const agentHeader = `"${signatureAgent}"`;
  // 64 random bytes, base64: what Cloudflare's verifier requires of a nonce.
  const nonce = randomBytes(64).toString('base64');
  const params = `("@authority" "signature-agent");created=${nowSeconds};expires=${nowSeconds + REQUEST_SIGNATURE_SECONDS};keyid="${key.keyId}";alg="ed25519";nonce="${nonce}";tag="${WEB_BOT_AUTH_TAG}"`;
  const base = `"@authority": ${authorityOf(url)}\n"signature-agent": ${agentHeader}\n"@signature-params": ${params}`;
  const signature = sign(null, Buffer.from(base, 'utf8'), key.privateKey).toString('base64');
  return { 'Signature-Agent': agentHeader, 'Signature-Input': `sig1=${params}`, Signature: `sig1=:${signature}:` };
}

async function call(fetchImpl: typeof fetch, url: string, init: RequestInit): Promise<{ status: number; body: Record<string, unknown> }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  (timer as { unref?: () => void }).unref?.();
  try {
    const res = await fetchImpl(url, { ...init, signal: controller.signal });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    return { status: res.status, body: body && typeof body === 'object' ? body : {} };
  } finally {
    clearTimeout(timer);
  }
}

const LABEL = /^[A-Za-z0-9 ._:@/-]{1,100}$/;

function defaultLabel(): string {
  const host = (process.env.HOSTNAME || hostname() || '').slice(0, 100);
  return LABEL.test(host) ? host : '';
}

export function agentSigner(options: AgentSignerOptions): AgentSigner {
  if (!options?.apiKey) throw new TypeError('agentSigner: apiKey (the environment\'s Shield360 API key) is required');
  const base = baseUrlOf({ apiKey: options.apiKey, baseUrl: options.baseUrl });
  const getFetch = (): typeof fetch => options.fetch ?? globalThis.fetch;
  const now = options.clock ?? Date.now;
  const label = options.label !== undefined ? (LABEL.test(options.label) ? options.label : '') : defaultLabel();
  const auth = { Authorization: `Bearer ${options.apiKey}` };

  let key: Key | undefined;
  let info: SignerInfo | undefined;
  let pending: Promise<SignerInfo> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let failures = 0;
  let warned = false;
  let closed = false;

  const schedule = (seconds: number) => {
    if (closed) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      register().catch(() => undefined);
    }, seconds * 1000);
    (timer as { unref?: () => void }).unref?.();
  };

  async function register(): Promise<SignerInfo> {
    try {
      key = key ?? loadOrCreateKey(options);
      const fetchImpl = getFetch();
      const signer = await call(fetchImpl, `${base}/api/agent-signing/sdk/signer`, { method: 'GET', headers: { ...auth, Accept: 'application/json' } });
      if (signer.status !== 200 || typeof signer.body.authority !== 'string' || typeof signer.body.signatureAgent !== 'string') {
        throw new Error(`Shield360 agent signer: no signer for this environment (HTTP ${signer.status})${typeof signer.body.err === 'string' ? `: ${signer.body.err}` : ''}`);
      }
      const created = Math.floor(now() / 1000);
      const expires = created + DIRECTORY_SIGNATURE_SECONDS;
      const signature = sign(null, Buffer.from(directorySignatureBase(signer.body.authority, created, expires, key.keyId), 'utf8'), key.privateKey).toString('base64');
      const reg = await call(fetchImpl, `${base}/api/agent-signing/sdk/keys`, {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ publicKey: key.x, ...(label ? { label } : {}), directorySignature: { created, expires, signature } }),
      });
      if (reg.status !== 200 && reg.status !== 201) {
        throw new Error(`Shield360 agent signer: the key was not registered (HTTP ${reg.status})${typeof reg.body.err === 'string' ? `: ${reg.body.err}` : ''}`);
      }
      info = { keyId: key.keyId, signatureAgent: String(reg.body.signatureAgent ?? signer.body.signatureAgent), directoryUrl: String(reg.body.directoryUrl ?? signer.body.directoryUrl ?? '') };
      failures = 0;
      const refresh = Number(reg.body.refreshAfterSeconds);
      schedule(Number.isFinite(refresh) && refresh >= 60 ? refresh : DEFAULT_REFRESH_SECONDS);
      return info;
    } catch (err) {
      // Retry sooner while it keeps failing; a registered signer keeps signing meanwhile.
      schedule(RETRY_SECONDS[Math.min(failures++, RETRY_SECONDS.length - 1)]);
      throw err;
    }
  }

  function ready(): Promise<SignerInfo> {
    if (info) return Promise.resolve(info);
    pending = pending ?? register().finally(() => (pending = undefined));
    return pending;
  }

  async function headers(request: SignableRequest | string): Promise<Record<string, string>> {
    const url = typeof request === 'string' ? request : request.url;
    try {
      const i = await ready();
      return signRequest(key as Key, i.signatureAgent, url, Math.floor(now() / 1000));
    } catch (err) {
      if (!warned) console.warn(`${(err as Error).message || 'Shield360 agent signer: signing is not set up'}; requests are sent unsigned`);
      warned = true;
      return {};
    }
  }

  async function signedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = input instanceof Request ? input.url : String(input);
    const extra = await headers(url);
    const merged = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(init?.headers).forEach((v, k) => merged.set(k, v));
    for (const [k, v] of Object.entries(extra)) merged.set(k, v);
    return getFetch()(input instanceof Request ? new Request(input, { ...init, headers: merged }) : input, { ...init, headers: merged });
  }

  return {
    ready,
    headers,
    fetch: signedFetch,
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
    },
  };
}

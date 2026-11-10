/**
 * Web Bot Auth: agents that sign their requests with HTTP Message Signatures
 * (RFC 9421) and publish their public keys in a key directory, as specified by
 * the IETF webbotauth working group (draft-ietf-webbotauth-httpsig-protocol)
 * and verified by Cloudflare for its signed agents.
 *
 * A signature proves which signer sent the request: the host named by its
 * Signature-Agent header, which publishes the key. It does not say for whom
 * the agent acts; that is what a Shield360 passport adds.
 *
 * Both Signature-Agent forms are read: the dictionary the current draft
 * requires (`sig1="https://signer.example"`, covered as
 * `"signature-agent";key="sig1"`) and the bare string Cloudflare still sends
 * (`"https://signer.example"`, covered as `"signature-agent"`). Only Ed25519
 * keys are accepted, as Cloudflare does.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_web_bot_auth.py
 */

import { createHash, createPublicKey, KeyObject, verify as cryptoVerify } from 'crypto';
import { audienceMatches } from './passport';
import { InnerList, Item, Member, parseDictionary, parseItemField, serializeInnerList, serializeMember, StructuredError, Token } from './structured';
import { AgentCheckInput, ReplayStore } from './types';

export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';

/** The longest a signature may be valid (expires - created): the draft's recommended day. */
export const MAX_SIGNATURE_SECONDS = 24 * 60 * 60;

const MAX_HEADER_CHARS = 4096;
const MAX_COMPONENTS = 16;
const MAX_LABELS = 3;
const MAX_DIRECTORY_BYTES = 64 * 1024;
const MAX_DIRECTORY_KEYS = 50;
const MAX_DIRECTORIES = 1000;
const HOUR_MS = 60 * 60 * 1000;
const MISS_REFETCH_MS = 60 * 1000;
const FETCH_TIMEOUT_MS = 5000;
/** Directory fetches a verifier starts in a minute: callers choose the URLs, so they must not drive unbounded outbound traffic. */
const FETCHES_PER_MINUTE = 30;

const DERIVED = new Set(['@authority', '@method', '@path', '@query', '@target-uri', '@scheme']);
const FIELD_NAME = /^[a-z0-9!#$%&'*+\-.^_`|~]+$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,128}$/;

export type WebBotAuthReason =
  | 'malformed'
  | 'unsupported_alg'
  | 'unsupported_component'
  | 'untrusted_signature_agent'
  | 'directory_unreachable'
  | 'unknown_key'
  | 'bad_signature'
  | 'expired'
  | 'not_yet_valid'
  | 'lifetime_too_long'
  | 'wrong_audience'
  | 'replayed'
  | 'replay_check_failed';

export type WebBotAuthSigner = {
  /** The Signature-Agent URL: where the signer publishes its keys. */
  agent: string;
  /** Its host, lower case: who signed. */
  host: string;
  /** The key's JWK thumbprint (RFC 7638 / RFC 8037). */
  keyId: string;
  /** When the signature expires, epoch seconds. */
  expires: number;
};

export type WebBotAuthResult =
  | { status: 'absent' }
  | { status: 'invalid'; reason: WebBotAuthReason; host?: string }
  | { status: 'verified'; signer: WebBotAuthSigner };

/** The parts of a request a signature can cover. */
export type SignedRequest = {
  header(name: string): string | undefined;
  method?: string;
  scheme: string;
  /** host[:port], lower case, default port removed. */
  authority?: string;
  path?: string;
  /** Without the "?"; undefined when the request had no query. */
  query?: string;
};

// ---------------------------------------------------------------------------
// Reading a request

function joinValues(v: unknown): string | undefined {
  if (Array.isArray(v)) {
    const values = v.filter((x) => typeof x === 'string');
    return values.length ? values.map((x) => x.trim()).join(', ') : undefined;
  }
  return typeof v === 'string' ? v.trim() : undefined;
}

function headerGetter(input: AgentCheckInput): (name: string) => string | undefined {
  if (input === null || input === undefined || typeof input !== 'object') return () => undefined;
  const any = input as { headers?: unknown; get?: unknown };
  if (typeof any.get === 'function') return (n) => joinValues((any.get as (n: string) => unknown).call(input, n));
  const h = 'headers' in any && typeof any.headers === 'object' && any.headers !== null ? any.headers : input;
  const hh = h as { get?: unknown };
  if (typeof hh.get === 'function') return (n) => joinValues((hh.get as (n: string) => unknown).call(h, n));
  const rec = h as Record<string, unknown>;
  return (n) => {
    const want = n.toLowerCase();
    const values: unknown[] = [];
    for (const k of Object.keys(rec)) if (k.toLowerCase() === want) values.push(...(Array.isArray(rec[k]) ? (rec[k] as unknown[]) : [rec[k]]));
    return values.length ? joinValues(values) : undefined;
  };
}

function authorityOf(host: string | undefined, scheme: string): string | undefined {
  if (!host) return undefined;
  const h = host.trim().toLowerCase();
  if (!/^[a-z0-9.\-[\]:]{1,260}$/.test(h)) return undefined;
  if ((scheme === 'https' && h.endsWith(':443')) || (scheme === 'http' && h.endsWith(':80'))) return h.replace(/:\d+$/, '');
  return h;
}

/**
 * What a check can see of the request: a fetch Request, a Node
 * IncomingMessage (Express, Fastify's raw), or bare headers (then the method
 * and path come from the check options). The scheme is https unless the
 * request's own URL says otherwise.
 */
export function signedRequest(input: AgentCheckInput, opts: { method?: string; route?: string } = {}): SignedRequest {
  const header = headerGetter(input);
  const any = (input && typeof input === 'object' ? input : {}) as { url?: unknown; method?: unknown };
  let scheme = 'https';
  let host = header('host');
  let path: string | undefined;
  let query: string | undefined;
  const rawUrl = typeof any.url === 'string' ? any.url : undefined;
  if (rawUrl) {
    try {
      const u = new URL(rawUrl, 'https://placeholder.invalid');
      if (rawUrl.includes('://')) {
        scheme = u.protocol.replace(':', '');
        host = host ?? u.host;
      }
      path = u.pathname;
      query = rawUrl.includes('?') ? u.search.slice(1) : undefined;
    } catch {
      path = undefined;
    }
  } else if (opts.route) path = opts.route.split(/[?#]/, 1)[0];
  const method = typeof any.method === 'string' ? any.method : opts.method;
  return { header, method: method?.toUpperCase(), scheme, authority: authorityOf(host, scheme), path, query };
}

// ---------------------------------------------------------------------------
// The key directory

type DirectoryKey = { key: KeyObject; nbf?: number; exp?: number };
type Directory = { keys: Map<string, DirectoryKey>; fetchedAt: number; lastAttempt: number; reachable: boolean; inflight?: Promise<void> };

/** A JWK's SHA-256 thumbprint (RFC 7638; RFC 8037 for OKP), base64url. */
export function jwkThumbprint(jwk: { kty: string; crv: string; x: string }): string {
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)}}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** The keys of a JWKS: Ed25519 public keys, by thumbprint. A private key is never accepted. */
export function directoryKeys(body: unknown): Map<string, DirectoryKey> {
  const keys = new Map<string, DirectoryKey>();
  if (!isObject(body) || !Array.isArray(body.keys)) return keys;
  for (const jwk of body.keys.slice(0, MAX_DIRECTORY_KEYS)) {
    if (!isObject(jwk) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || jwk.x.length > 128 || jwk.d !== undefined) continue;
    try {
      const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
      keys.set(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: jwk.x }), {
        key,
        ...(typeof jwk.nbf === 'number' ? { nbf: jwk.nbf } : {}),
        ...(typeof jwk.exp === 'number' ? { exp: jwk.exp } : {}),
      });
    } catch {
      // not a usable key
    }
  }
  return keys;
}

const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.home\.arpa)$/;

/**
 * Where a Signature-Agent's keys are: the URL itself, or the well-known
 * directory when it names only an origin. Null when it is not an https URL
 * on a public host name (never an IP address or a private name: a
 * Signature-Agent is chosen by the caller, and the receiver fetches it).
 */
export function directoryUrl(agent: string): { url: string; host: string } | null {
  let u: URL;
  try {
    u = new URL(agent);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.port) return null;
  const host = u.hostname.toLowerCase();
  if (!host.includes('.') || host.startsWith('[') || /^[0-9.]+$/.test(host) || PRIVATE_HOST.test(host)) return null;
  const bare = (u.pathname === '/' || u.pathname === '') && !u.search;
  return { url: bare ? `${u.origin}${DIRECTORY_PATH}` : u.href, host };
}

async function fetchDirectory(fetchImpl: typeof fetch, url: string): Promise<unknown | undefined> {
  const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
  const timer = controller ? setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS) : undefined;
  (timer as { unref?: () => void } | undefined)?.unref?.();
  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      headers: { Accept: `${DIRECTORY_MEDIA_TYPE}, application/json` },
      // A directory is answered with 200, never a redirect.
      redirect: 'manual',
      signal: controller?.signal,
    });
    if (res.status !== 200) return undefined;
    const length = Number(res.headers?.get?.('content-length') ?? 0);
    if (length > MAX_DIRECTORY_BYTES) return undefined;
    const text = await res.text();
    if (text.length > MAX_DIRECTORY_BYTES) return undefined;
    return JSON.parse(text);
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Signers' key directories: cached for an hour; an unknown key refetches at
 * most once a minute per directory; at most 1000 directories are kept, and at
 * most 30 fetches start in any minute (beyond that a directory reads as
 * unreachable, so the call is treated as unsigned).
 */
export class DirectoryCache {
  private readonly dirs = new Map<string, Directory>();
  private readonly starts: number[] = [];

  private budget(now: number): boolean {
    while (this.starts.length && now - this.starts[0] >= MISS_REFETCH_MS) this.starts.shift();
    if (this.starts.length >= FETCHES_PER_MINUTE) return false;
    this.starts.push(now);
    return true;
  }

  constructor(
    private readonly fetchImpl: () => typeof fetch,
    private readonly now: () => number,
  ) {}

  /** The key, or "unreachable" when the directory has never answered. */
  async get(url: string, keyId: string): Promise<DirectoryKey | undefined | 'unreachable'> {
    let entry = this.dirs.get(url);
    if (!entry) {
      if (this.dirs.size >= MAX_DIRECTORIES) this.dirs.delete(this.dirs.keys().next().value as string);
      entry = { keys: new Map(), fetchedAt: -Infinity, lastAttempt: -Infinity, reachable: false };
      this.dirs.set(url, entry);
    }
    const now = this.now();
    const known = entry.keys.get(keyId);
    if (known && now - entry.fetchedAt < HOUR_MS) return known;
    if (!entry.inflight && now - entry.lastAttempt < MISS_REFETCH_MS) return known ?? (entry.reachable ? undefined : 'unreachable');
    if (!entry.inflight) {
      if (!this.budget(now)) return known ?? (entry.reachable ? undefined : 'unreachable');
      entry.lastAttempt = now;
      const e = entry;
      entry.inflight = (async () => {
        const body = await fetchDirectory(this.fetchImpl(), url);
        if (body === undefined) return;
        e.keys = directoryKeys(body);
        e.reachable = true;
        e.fetchedAt = this.now();
      })().finally(() => {
        e.inflight = undefined;
      });
    }
    await entry.inflight;
    return entry.keys.get(keyId) ?? known ?? (entry.reachable ? undefined : 'unreachable');
  }
}

// ---------------------------------------------------------------------------
// The signature base (RFC 9421 section 2.5)

class Unsupported extends Error {}

function componentValue(req: SignedRequest, c: Item): string {
  if (typeof c.value !== 'string') throw new StructuredError('component');
  const name = c.value;
  const params = [...c.params.keys()];
  if (name.startsWith('@')) {
    if (!DERIVED.has(name) || params.length) throw new Unsupported(name);
    const v =
      name === '@authority'
        ? req.authority
        : name === '@method'
          ? req.method
          : name === '@scheme'
            ? req.scheme
            : name === '@path'
              ? req.path || (req.path === '' ? '/' : undefined)
              : name === '@query'
                ? `?${req.query ?? ''}`
                : req.authority && req.path !== undefined
                  ? `${req.scheme}://${req.authority}${req.path}${req.query !== undefined ? `?${req.query}` : ''}`
                  : undefined;
    if (v === undefined) throw new StructuredError(name);
    return v;
  }
  if (!FIELD_NAME.test(name)) throw new StructuredError(name);
  if (params.some((p) => p !== 'key')) throw new Unsupported(name);
  const raw = req.header(name);
  if (raw === undefined) throw new StructuredError(name);
  const key = c.params.get('key');
  if (key === undefined) return raw;
  if (typeof key !== 'string') throw new StructuredError(name);
  const member = parseDictionary(raw).get(key);
  if (!member) throw new StructuredError(name);
  return serializeMember(member);
}

/** The signature base for a label's covered components and parameters. */
export function signatureBase(req: SignedRequest, list: InnerList): string {
  const lines: string[] = [];
  for (const c of list.items) lines.push(`${serializeMember(c)}: ${componentValue(req, c)}`);
  lines.push(`"@signature-params": ${serializeInnerList(list)}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Verifying

export type WebBotAuthOptions = {
  audiences: string[];
  directories: DirectoryCache;
  replay: ReplayStore;
  skewSeconds: number;
  now: () => number;
};

const covers = (list: InnerList, name: string): Item | undefined => list.items.find((c) => c.value === name);

/** The Signature-Agent URL the covered component names, or null. */
function signatureAgent(req: SignedRequest, component: Item): string | null {
  const raw = req.header('signature-agent');
  if (!raw) return null;
  const key = component.params.get('key');
  let member: Member | undefined;
  if (typeof key === 'string') member = parseDictionary(raw).get(key);
  else member = parseItemField(raw);
  if (!member || member.kind !== 'item' || typeof member.value !== 'string') return null;
  // An earlier draft (and Cloudflare's library) marks a key directory with type=directory; no other type is read.
  for (const [k, v] of member.params) if (k !== 'type' || !(v instanceof Token) || v.value !== 'directory') return null;
  return member.value;
}

async function verifyLabel(req: SignedRequest, list: InnerList, signature: Member | undefined, o: WebBotAuthOptions): Promise<WebBotAuthResult> {
  const p = list.params;
  const created = p.get('created');
  const expires = p.get('expires');
  const keyId = p.get('keyid');
  const alg = p.get('alg');
  const nonce = p.get('nonce');
  if (!Number.isInteger(created) || !Number.isInteger(expires) || typeof keyId !== 'string' || !KEY_ID.test(keyId)) return { status: 'invalid', reason: 'malformed' };
  if (alg !== undefined && alg !== 'ed25519') return { status: 'invalid', reason: 'unsupported_alg' };
  if (nonce !== undefined && (typeof nonce !== 'string' || !nonce || nonce.length > 256)) return { status: 'invalid', reason: 'malformed' };
  if (!signature || signature.kind !== 'item' || !(signature.value instanceof Uint8Array)) return { status: 'invalid', reason: 'malformed' };
  if (list.items.length > MAX_COMPONENTS || list.items.some((c) => typeof c.value !== 'string')) return { status: 'invalid', reason: 'malformed' };

  const agentComponent = covers(list, 'signature-agent');
  if (!agentComponent || (!covers(list, '@authority') && !covers(list, '@target-uri'))) return { status: 'invalid', reason: 'malformed' };
  const agent = signatureAgent(req, agentComponent);
  if (!agent) return { status: 'invalid', reason: 'malformed' };
  const dir = directoryUrl(agent);
  if (!dir) return { status: 'invalid', reason: 'untrusted_signature_agent' };
  const host = dir.host;

  const t = o.now() / 1000;
  const c = created as number;
  const e = expires as number;
  if (e <= c) return { status: 'invalid', reason: 'malformed', host };
  if (c > t + o.skewSeconds) return { status: 'invalid', reason: 'not_yet_valid', host };
  if (e <= t - o.skewSeconds) return { status: 'invalid', reason: 'expired', host };
  if (e - c > MAX_SIGNATURE_SECONDS) return { status: 'invalid', reason: 'lifetime_too_long', host };

  // The signature must be for this receiver: a signature for another site is not replayable here.
  if (!req.authority || !o.audiences.some((a) => audienceMatches(`https://${req.authority}`, [a]))) return { status: 'invalid', reason: 'wrong_audience', host };

  let base: string;
  try {
    base = signatureBase(req, list);
  } catch (err) {
    return { status: 'invalid', reason: err instanceof Unsupported ? 'unsupported_component' : 'malformed', host };
  }

  const found = await o.directories.get(dir.url, keyId);
  if (found === 'unreachable') return { status: 'invalid', reason: 'directory_unreachable', host };
  if (!found || (found.nbf !== undefined && found.nbf > t + o.skewSeconds) || (found.exp !== undefined && found.exp <= t - o.skewSeconds)) {
    return { status: 'invalid', reason: 'unknown_key', host };
  }
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.from(base, 'utf8'), found.key, Buffer.from(signature.value));
  } catch {
    ok = false;
  }
  if (!ok) return { status: 'invalid', reason: 'bad_signature', host };

  // Each signature is accepted once: by its nonce when it has one, otherwise by the signature itself.
  const replayKey = `wba:${keyId}:${typeof nonce === 'string' ? `n:${nonce}` : `s:${Buffer.from(signature.value).toString('base64url')}`}`;
  try {
    if (await o.replay.seen(replayKey, (e + o.skewSeconds) * 1000)) return { status: 'invalid', reason: 'replayed', host };
  } catch {
    return { status: 'invalid', reason: 'replay_check_failed', host };
  }
  return { status: 'verified', signer: { agent, host, keyId, expires: e } };
}

/**
 * Checks a request's Web Bot Auth signatures. "absent" when it carries none
 * (no Signature-Input member tagged web-bot-auth); otherwise the first label
 * that verifies, or the first label's failure. Never throws.
 */
export async function verifyWebBotAuth(req: SignedRequest, o: WebBotAuthOptions): Promise<WebBotAuthResult> {
  const input = req.header('signature-input');
  if (!input) return { status: 'absent' };
  const claimed = input.includes(WEB_BOT_AUTH_TAG);
  if (input.length > MAX_HEADER_CHARS) return claimed ? { status: 'invalid', reason: 'malformed' } : { status: 'absent' };
  let inputs: Map<string, Member>;
  try {
    inputs = parseDictionary(input);
  } catch {
    return claimed ? { status: 'invalid', reason: 'malformed' } : { status: 'absent' };
  }
  const labels = [...inputs].filter(([, m]) => m.kind === 'list' && m.params.get('tag') === WEB_BOT_AUTH_TAG) as [string, InnerList][];
  if (!labels.length) return { status: 'absent' };

  const sigHeader = req.header('signature');
  let signatures = new Map<string, Member>();
  try {
    if (sigHeader && sigHeader.length <= MAX_HEADER_CHARS) signatures = parseDictionary(sigHeader);
  } catch {
    return { status: 'invalid', reason: 'malformed' };
  }

  let first: WebBotAuthResult | undefined;
  for (const [label, list] of labels.slice(0, MAX_LABELS)) {
    let result: WebBotAuthResult;
    try {
      result = await verifyLabel(req, list, signatures.get(label), o);
    } catch {
      result = { status: 'invalid', reason: 'malformed' };
    }
    if (result.status === 'verified') return result;
    first = first ?? result;
  }
  return first ?? { status: 'absent' };
}

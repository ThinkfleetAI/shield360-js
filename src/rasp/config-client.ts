/**
 * Signed RASP config client (README "The signed config").
 *
 * `GET /api/rasp/config?app=` returns `{ config: <compact JWS>, keys }`. The
 * JWS is trusted only when it verifies against a key the app pinned
 * (`configPublicKey` / `SHIELD360_CONFIG_PUBLIC_KEY`: a JWK, a JWKS for
 * rotation, or the bare base64url Ed25519 `x`). The `keys` in the response
 * are never trusted on their own: they came over the same channel as the
 * config. Only with trust on first use (development: `allowUnpinnedConfig`
 * or `SHIELD360_CONFIG_TOFU=dev`, never in production) is the first `kid`
 * seen pinned; a config signed by another kid after that is rejected. A
 * pinned key that does not verify never falls back to trust on first use.
 *
 * ETag polling every 60 s ± 10 s, 5 minutes after a failure; the last
 * verified config is kept in memory and in a cache file that is re-verified
 * when loaded. Never throws and never blocks start-up.
 */
import { createPublicKey, KeyObject, verify as cryptoVerify } from 'crypto';
import * as fs from 'fs';
import { join } from 'path';
import type { AttackType, ConfigPublicKey, Jwk, RaspAllow, RaspMode } from './types';
import type { VirtualPatch } from './vpatch';

export const JWS_TYPE = 'shield360-rasp+jws';
export const SKEW_S = 60;
export const POLL_MS = 60_000;
export const JITTER_MS = 10_000;
export const BACKOFF_MS = 5 * 60_000;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_TOKEN = 256 * 1024;

// Captured at load, before any later file-system hook, so the cache never
// trips RASP itself.
const readFile = fs.readFileSync.bind(fs);
const writeFile = fs.writeFileSync.bind(fs);
const mkdir = fs.mkdirSync.bind(fs);
const rename = fs.renameSync.bind(fs);

export type RaspClaims = {
  v: number;
  app: string;
  iat?: number;
  exp: number;
  version: string;
  killSwitch?: boolean;
  snippets?: boolean;
  reportTargets?: boolean;
  mode?: RaspMode;
  attacks?: Partial<Record<AttackType, RaspMode>>;
  allow?: Partial<RaspAllow>;
  rules?: VirtualPatch[] | null;
  sinks?: unknown[] | null;
  /** Custom rules (README "Custom rules"); null = none. */
  customRules?: unknown[] | null;
  /** Decoy paths as sent (README "Deception"; deception.ts reads them); absent or null = off. */
  deception?: unknown;
  /** Passive IAST switch and sampling rate (README "Passive IAST"). */
  iast?: 'on' | 'off';
  iastSampleRate?: number;
};

export type PinnedKey = { kid?: string; x: string; key: KeyObject };

const b64url = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const B64URL = /^[A-Za-z0-9_-]+$/;

function fromJwk(jwk: unknown): PinnedKey | null {
  try {
    const j = jwk as Jwk;
    if (!j || j.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.x !== 'string' || !B64URL.test(j.x) || b64url(j.x).length !== 32) return null;
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: j.x }, format: 'jwk' });
    return { kid: typeof j.kid === 'string' && j.kid ? j.kid : undefined, x: j.x, key };
  } catch {
    return null;
  }
}

/**
 * Parses a pinned key: a JWK, a JWKS, or the bare base64url Ed25519 `x`
 * (objects or JSON text). Unusable entries are left out; [] when none is usable.
 */
export function parsePublicKeys(input: ConfigPublicKey | undefined | null): PinnedKey[] {
  if (input == null || input === '') return [];
  let value: unknown = input;
  if (typeof value === 'string') {
    const s = value.trim();
    if (s.startsWith('{') || s.startsWith('[')) {
      try {
        value = JSON.parse(s);
      } catch {
        return [];
      }
    } else {
      const k = fromJwk({ kty: 'OKP', crv: 'Ed25519', x: s });
      return k ? [k] : [];
    }
  }
  const list = Array.isArray(value) ? value : value && typeof value === 'object' && Array.isArray((value as { keys?: unknown }).keys) ? (value as { keys: unknown[] }).keys : [value];
  return list
    .slice(0, 16)
    .map(fromJwk)
    .filter((k): k is PinnedKey => k !== null);
}

export type VerifyResult = { ok: true; claims: RaspClaims; kid?: string } | { ok: false; reason: string };

function header(token: string): { alg?: unknown; typ?: unknown; kid?: unknown } | null {
  try {
    const h = JSON.parse(b64url(token.split('.')[0] || '').toString('utf8'));
    return h && typeof h === 'object' ? h : null;
  } catch {
    return null;
  }
}

/** The `kid` in a JWS header, or undefined. */
export function jwsKid(token: string): string | undefined {
  const h = typeof token === 'string' ? header(token) : null;
  return h && typeof h.kid === 'string' ? h.kid : undefined;
}

/**
 * Verifies a compact JWS against the given keys only: `alg` EdDSA, `typ`
 * shield360-rasp+jws, an Ed25519 signature by the pinned key whose kid
 * matches the header (any pinned key when the header names none listed), `v` 1, `app` equal to ours, `exp` in the future
 * (60 s skew).
 */
export function verifyConfigJws(token: unknown, keys: PinnedKey[], app: string, nowS = Date.now() / 1000): VerifyResult {
  try {
    if (typeof token !== 'string' || token.length > MAX_TOKEN) return { ok: false, reason: 'malformed' };
    const parts = token.split('.');
    if (parts.length !== 3 || !parts.every((p) => B64URL.test(p))) return { ok: false, reason: 'malformed' };
    const h = header(token);
    if (!h) return { ok: false, reason: 'malformed' };
    if (h.alg !== 'EdDSA') return { ok: false, reason: 'alg' };
    if (h.typ !== JWS_TYPE) return { ok: false, reason: 'typ' };
    const kid = typeof h.kid === 'string' ? h.kid : undefined;
    let candidates = kid ? keys.filter((k) => k.kid === kid) : [];
    if (!candidates.length) candidates = keys;
    if (!candidates.length) return { ok: false, reason: 'no_key' };
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = b64url(parts[2]);
    if (!candidates.some((k) => cryptoVerify(null, signed, k.key, sig))) return { ok: false, reason: 'signature' };
    const claims = JSON.parse(b64url(parts[1]).toString('utf8')) as RaspClaims;
    if (!claims || typeof claims !== 'object' || claims.v !== 1) return { ok: false, reason: 'version' };
    if (claims.app !== app) return { ok: false, reason: 'app' };
    if (typeof claims.exp !== 'number' || claims.exp + SKEW_S <= nowS) return { ok: false, reason: 'expired' };
    if (typeof claims.version !== 'string' || !claims.version) return { ok: false, reason: 'version' };
    return { ok: true, claims, kid };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

export type PollResult = 'updated' | 'unchanged' | 'rejected' | 'failed';

export type ConfigClientOptions = {
  url: string;
  apiKey: string;
  app: string;
  /** Pinned keys (parsePublicKeys). */
  pinned: PinnedKey[];
  /** Development only (the caller already refused it in production): pin the first kid the server sends. */
  allowUnpinned?: boolean;
  cacheDir: string;
  /** A verified config, or undefined when the one in force expired. */
  onConfig: (claims: RaspClaims | undefined) => void;
  /** Why a config was refused (once per reason). */
  onWarning?: (reason: string) => void;
  fetchImpl?: typeof fetch;
  now?: () => number;
  random?: () => number;
};

type CacheFile = { config: string; tofu?: Jwk[] };

export class RaspConfigClient {
  private etag?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly base: string;
  /** Keys pinned on first use (allowUnpinned only). */
  private tofu: PinnedKey[] = [];
  private readonly warned = new Set<string>();
  current?: RaspClaims;
  stopped = false;

  constructor(private readonly o: ConfigClientOptions) {
    this.base = o.url.replace(/\/+$/, '');
  }

  /** The keys a config must verify against right now. */
  private trusted(): PinnedKey[] {
    return this.o.pinned.length ? this.o.pinned : this.o.allowUnpinned ? this.tofu : [];
  }

  private nowMs(): number {
    return (this.o.now ?? Date.now)();
  }

  cacheFile(): string {
    return join(this.o.cacheDir, `${this.o.app.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'default'}.json`);
  }

  private warn(reason: string): void {
    if (this.warned.has(reason)) return;
    this.warned.add(reason);
    try {
      this.o.onWarning?.(reason);
    } catch {
      // never
    }
  }

  private apply(claims: RaspClaims | undefined): void {
    // A stopped client (RASP re-initialized for another app or key) never
    // applies anything: a poll still in flight when it stopped is dropped.
    if (this.stopped) return;
    this.current = claims;
    try {
      this.o.onConfig(claims);
    } catch {
      // fail open
    }
  }

  /** Loads the cached config and re-verifies it. Pinned keys are never read from the cache. */
  loadCache(): boolean {
    try {
      const saved = JSON.parse(readFile(this.cacheFile(), 'utf8')) as CacheFile;
      if (!this.o.pinned.length && this.o.allowUnpinned && !this.tofu.length) this.tofu = parsePublicKeys({ keys: saved.tofu ?? [] });
      const r = verifyConfigJws(saved.config, this.trusted(), this.o.app, this.nowMs() / 1000);
      if (!r.ok) return false;
      this.apply(r.claims);
      return true;
    } catch {
      return false;
    }
  }

  private saveCache(config: string): void {
    if (this.stopped) return;
    try {
      mkdir(this.o.cacheDir, { recursive: true, mode: 0o700 });
      const body: CacheFile = { config };
      if (!this.o.pinned.length && this.tofu.length) body.tofu = this.tofu.map((k) => ({ kty: 'OKP', crv: 'Ed25519', x: k.x, ...(k.kid ? { kid: k.kid } : {}) }));
      const file = this.cacheFile();
      const tmp = `${file}.${process.pid}.tmp`;
      writeFile(tmp, JSON.stringify(body), { mode: 0o600 });
      rename(tmp, file);
    } catch {
      // the cache is best effort
    }
  }

  /** Drops the config in force once it has expired (the platform could not be reached for its whole lifetime). */
  private expire(): void {
    if (this.current && this.current.exp + SKEW_S <= this.nowMs() / 1000) {
      this.etag = undefined;
      this.apply(undefined);
    }
  }

  /** One poll. Never throws. */
  async poll(): Promise<PollResult> {
    const result = await this.fetchOnce();
    this.expire();
    return result;
  }

  private async fetchOnce(): Promise<PollResult> {
    try {
      if (!this.o.pinned.length && !this.o.allowUnpinned) {
        this.warn('unpinned');
        return 'rejected';
      }
      const send = this.o.fetchImpl ?? globalThis.fetch;
      const headers: Record<string, string> = { Authorization: `Bearer ${this.o.apiKey}`, Accept: 'application/json' };
      if (this.etag && this.current) headers['If-None-Match'] = this.etag;
      const init: RequestInit = { headers };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await send(`${this.base}/api/rasp/config?app=${encodeURIComponent(this.o.app)}`, init);
      if (res.status === 304) return 'unchanged';
      if (!res.ok) return 'failed';
      const body = (await res.json()) as { config?: unknown; keys?: unknown };
      const token = typeof body?.config === 'string' ? body.config : '';
      if (!this.o.pinned.length && this.o.allowUnpinned && !this.tofu.length) {
        // Trust on first use (development only): pin the key the response names.
        const kid = jwsKid(token);
        const offered = parsePublicKeys({ keys: Array.isArray(body?.keys) ? (body.keys as Jwk[]) : [] });
        const first = offered.find((k) => k.kid === kid) ?? (offered.length === 1 ? offered[0] : undefined);
        if (first) {
          this.tofu = [first];
          this.warn('trust_on_first_use');
        }
      }
      const r = verifyConfigJws(token, this.trusted(), this.o.app, this.nowMs() / 1000);
      if (!r.ok) {
        this.warn(r.reason);
        return 'rejected';
      }
      this.etag = res.headers.get('etag') ?? undefined;
      this.apply(r.claims);
      this.saveCache(token);
      return 'updated';
    } catch {
      return 'failed';
    }
  }

  /** The delay before the next poll after a result. */
  nextDelay(r: PollResult): number {
    if (r === 'failed' || r === 'rejected') return BACKOFF_MS;
    const random = this.o.random ?? Math.random;
    return POLL_MS + Math.round((random() * 2 - 1) * JITTER_MS);
  }

  start(): void {
    this.loadCache();
    const loop = async () => {
      if (this.stopped) return;
      const r = await this.poll();
      if (this.stopped) return;
      this.timer = setTimeout(() => void loop(), this.nextDelay(r));
      this.timer.unref?.();
    };
    // Off the start-up path.
    this.timer = setTimeout(() => void loop(), 0);
    this.timer.unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }
}

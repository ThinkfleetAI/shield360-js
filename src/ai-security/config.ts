/**
 * The app's AI security policy from the platform, signed.
 *
 * GET /api/ai-security/config?app=<service name> answers, for the API key's
 * environment, a compact JWS (EdDSA, Ed25519, typ
 * "shield360-ai-security+jws") whose claims are { app, policy, ver, iat,
 * exp }, signed with the environment's attestation key, plus that key's
 * public JWK. The SDK verifies the signature and refuses a policy for
 * another app or one already expired.
 *
 * Pinning is required. The token must verify under a key the developer
 * pinned: `configPublicKey` (a JWK, a PEM, or a JWKS { keys: [...] } so a
 * rotation can list the old and the new key) or the env
 * SHIELD360_CONFIG_PUBLIC_KEY (the same, as text). The key published beside
 * the token is never trusted on its own. Without a pin the SDK does not
 * apply the platform's policy: it keeps the policy from code (monitoring by
 * default) and reports it once. Trust on first use (pin the first key seen)
 * exists only behind `allowUnpinnedConfig: true`, for development.
 *
 * A verified answer can be cached to a file (`cacheFile`) and is re-verified
 * under the pinned keys when read back, so a restart while the platform is
 * unreachable still starts with the last policy. A cached answer never pins
 * a key.
 *
 * Fetched in the background every refreshSeconds (60 s), never on the
 * request path. When nothing valid can be read the policy from code
 * applies: fail open to monitoring.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_config.py
 */

import { createPublicKey, verify } from 'crypto';
import { promises as fs } from 'fs';

export const CONFIG_JWS_TYPE = 'shield360-ai-security+jws';
const MAX_JWS = 256 * 1024;

export type SignedPolicy = { app: string; policy: unknown; ver: number; iat: number; exp: number; kid: string };

export type ConfigAnswer = { jws?: unknown; publicKey?: unknown };

type Parsed = { kid: string; claims: Record<string, unknown>; input: string; signature: Buffer };

function parse(token: unknown): Parsed | null {
  if (typeof token !== 'string' || token.length > MAX_JWS) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!header || header.alg !== 'EdDSA' || header.typ !== CONFIG_JWS_TYPE || typeof header.kid !== 'string') return null;
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return null;
    return { kid: header.kid, claims, input: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
  } catch {
    return null;
  }
}

/** A public Ed25519 key from a JWK object or a PEM string; null when it is not one. */
export function publicKeyFrom(value: unknown): ReturnType<typeof createPublicKey> | null {
  try {
    if (typeof value === 'string' && value.includes('BEGIN PUBLIC KEY')) return createPublicKey(value);
    if (value && typeof value === 'object') {
      const jwk = value as { kty?: unknown; crv?: unknown; x?: unknown };
      if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
      return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x as string }, format: 'jwk' });
    }
  } catch {
    // not a key
  }
  return null;
}

type PublicKey = ReturnType<typeof createPublicKey>;
export type PinnedKey = { kid: string | null; key: PublicKey };

/**
 * The keys a value pins: one JWK or PEM, a JWKS ({ keys: [...] }), or the
 * JSON text of either. Keys that are not Ed25519 are skipped.
 */
export function pinnedKeysFrom(value: unknown): PinnedKey[] {
  let v = value;
  if (typeof v === 'string') {
    const t = v.trim();
    if (!t) return [];
    if (t.startsWith('{') || t.startsWith('[')) {
      try {
        v = JSON.parse(t);
      } catch {
        return [];
      }
    }
  }
  const list = Array.isArray(v) ? v : v && typeof v === 'object' && Array.isArray((v as { keys?: unknown }).keys) ? (v as { keys: unknown[] }).keys : [v];
  const out: PinnedKey[] = [];
  for (const item of list.slice(0, 20)) {
    const key = publicKeyFrom(item);
    if (!key) continue;
    const kid = item && typeof item === 'object' && typeof (item as { kid?: unknown }).kid === 'string' ? (item as { kid: string }).kid : null;
    out.push({ kid, key });
  }
  return out;
}

/** The kid in a token's header, unverified (to pick the pinned key to try first). */
function kidOf(token: unknown): string | null {
  return parse(token)?.kid ?? null;
}

/** The claims of a policy token signed by this key, for this app, not expired; otherwise null. */
export function verifyPolicy(token: unknown, key: ReturnType<typeof createPublicKey>, app: string, nowMs: number): SignedPolicy | null {
  const parsed = parse(token);
  if (!parsed) return null;
  try {
    if (!verify(null, Buffer.from(parsed.input), key, parsed.signature)) return null;
  } catch {
    return null;
  }
  const c = parsed.claims;
  if (c.app !== app || typeof c.exp !== 'number' || typeof c.iat !== 'number' || typeof c.ver !== 'number') return null;
  if (c.exp * 1000 < nowMs) return null;
  return { app, policy: c.policy, ver: c.ver, iat: c.iat, exp: c.exp, kid: parsed.kid };
}

export type ConfigClientOptions = {
  url: string;
  apiKey: string;
  app: string;
  /** The pinned signing key(s): a JWK, a PEM or a JWKS. Falls back to env SHIELD360_CONFIG_PUBLIC_KEY. */
  publicKey?: unknown;
  /** Development only: with no pin, trust the first key the platform sends. */
  allowUnpinned?: boolean;
  /** Where to keep the last verified answer across restarts. */
  cacheFile?: string;
  refreshSeconds?: number;
  timeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  onPolicy: (signed: SignedPolicy) => void;
};

export class ConfigClient {
  private keys: PinnedKey[];
  private readonly tofu: boolean;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastVer = -1;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;

  constructor(private readonly o: ConfigClientOptions) {
    const env = typeof process !== 'undefined' ? process.env?.SHIELD360_CONFIG_PUBLIC_KEY : undefined;
    this.keys = pinnedKeysFrom(o.publicKey ?? env ?? '');
    this.tofu = this.keys.length === 0 && o.allowUnpinned === true;
    this.fetchImpl = o.fetch || fetch;
    this.now = o.now || Date.now;
  }

  /** Reads the cache (if any), fetches once, then refreshes in the background. */
  async start(): Promise<void> {
    if (!this.usable) return;
    await this.readCache();
    await this.refresh();
    const every = Math.max(10, this.o.refreshSeconds ?? 60) * 1000;
    this.timer = setInterval(() => void this.refresh(), every);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Whether the client can verify anything: a pinned key, or trust on first use allowed. */
  get usable(): boolean {
    return this.keys.length > 0 || this.tofu;
  }

  private accept(answer: ConfigAnswer, pin = true): boolean {
    let candidates = this.keys;
    if (!candidates.length) {
      if (!this.tofu) return false;
      candidates = pinnedKeysFrom(answer.publicKey).slice(0, 1);
      if (!candidates.length) return false;
    }
    const kid = kidOf(answer.jws);
    const ordered = [...candidates.filter((k) => k.kid && k.kid === kid), ...candidates.filter((k) => !k.kid || k.kid !== kid)];
    let signed: SignedPolicy | null = null;
    let used: PinnedKey | null = null;
    for (const k of ordered) {
      signed = verifyPolicy(answer.jws, k.key, this.o.app, this.now());
      if (signed) {
        used = k;
        break;
      }
    }
    if (!signed || !used) return false;
    // Trust on first use (development only): pinned from now on. A cached answer never pins.
    if (pin && !this.keys.length) this.keys = [used];
    if (signed.ver !== this.lastVer) {
      this.lastVer = signed.ver;
      this.o.onPolicy(signed);
    }
    return true;
  }

  async refresh(): Promise<boolean> {
    if (!this.usable) return false;
    const base = this.o.url.replace(/\/+$/, '');
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.o.timeoutMs ?? 3000);
    t.unref?.();
    try {
      const res = await this.fetchImpl(`${base}/api/ai-security/config?app=${encodeURIComponent(this.o.app)}`, {
        headers: { Authorization: `Bearer ${this.o.apiKey}` },
        signal: ctl.signal,
      });
      if (!res.ok) return false;
      const answer = (await res.json()) as ConfigAnswer;
      if (!this.accept(answer)) return false;
      await this.writeCache(answer);
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(t);
    }
  }

  private async readCache(): Promise<void> {
    if (!this.o.cacheFile) return;
    try {
      const raw = await fs.readFile(this.o.cacheFile, 'utf8');
      this.accept(JSON.parse(raw) as ConfigAnswer, false);
    } catch {
      // no cache yet
    }
  }

  private async writeCache(answer: ConfigAnswer): Promise<void> {
    if (!this.o.cacheFile) return;
    try {
      await fs.writeFile(this.o.cacheFile, JSON.stringify({ jws: answer.jws, publicKey: answer.publicKey }), { mode: 0o600 });
    } catch {
      // caching is best effort
    }
  }
}

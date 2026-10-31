/**
 * Reading an agent passport: the compact JWS, its claims, the issuer's keys and
 * the audience. Pure functions plus the key cache; nothing here throws on
 * hostile input.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_passport.py
 */

import { createPublicKey, KeyObject, verify as cryptoVerify } from 'crypto';
import { AgentIdentity, AgentMandate, Assurance, ASSURANCE_LEVELS, PASSPORT_TYP } from './types';

/** Longer than any real passport; anything bigger is refused unparsed. */
export const MAX_TOKEN_LENGTH = 8192;
const B64URL = /^[A-Za-z0-9_-]+$/;
const SCOPE = /^[A-Za-z0-9_.:-]{1,64}$/;
const MAX_SCOPES = 32;

export type PassportClaims = {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  agent: AgentIdentity;
  operator: { id: string; name: string; domain: string | null };
  act?: { sub: string; domain: string | null; assurance: Assurance; mandate?: AgentMandate };
  scope?: string;
  decision?: { id: string; policyVersion: string };
};

export type ParsedPassport = {
  kid: string;
  claims: PassportClaims;
  signingInput: Buffer;
  signature: Buffer;
};

export type ParseResult = { ok: true; passport: ParsedPassport } | { ok: false; reason: 'malformed' | 'unsupported_alg' };

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isText = (v: unknown, max = 1024): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const isOptionalText = (v: unknown, max = 1024): boolean => v === undefined || v === null || (typeof v === 'string' && v.length <= max);

const optText = (v: unknown, max = 256): string | null => (typeof v === 'string' && v && v.length <= max ? v : null);

/** An act's assurance: absent means "named" (older passports); anything unknown counts as the weakest. */
export function assuranceOf(v: unknown): Assurance {
  if (v === undefined || v === null) return 'named';
  return (ASSURANCE_LEVELS as readonly unknown[]).includes(v) ? (v as Assurance) : 'unverified';
}

/** The agent claim: required id and name; the optional profile fields are passed through when well-typed. */
function agentOf(a: Record<string, unknown>): AgentIdentity {
  const out: AgentIdentity = { id: a.id as string, name: a.name as string };
  if (typeof a.purpose === 'string' && a.purpose) out.purpose = a.purpose;
  if (a.status === 'enrolled' || a.status === 'not_enrolled') out.status = a.status;
  for (const k of ['environment', 'risk', 'reviewedAt', 'enrolledAt'] as const) {
    if (k in a && (a[k] === null || typeof a[k] === 'string')) out[k] = optText(a[k], 128);
  }
  if (isObject(a.owner)) out.owner = { domain: optText(a.owner.domain) };
  return out;
}

function actOf(act: Record<string, unknown>): NonNullable<PassportClaims['act']> {
  const out: NonNullable<PassportClaims['act']> = {
    sub: act.sub as string,
    domain: optText(act.domain),
    assurance: assuranceOf(act.assurance),
  };
  const m = act.mandate;
  if (isObject(m) && isText(m.id, 256) && isText(m.expiresAt, 64)) out.mandate = { id: m.id, expiresAt: m.expiresAt };
  return out;
}

function decodeJson(part: string): unknown {
  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
}

/** Step 1: three base64url parts, typ and alg, and claims of the right shape. */
export function parsePassport(token: string): ParseResult {
  const malformed = { ok: false, reason: 'malformed' } as const;
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return malformed;
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => B64URL.test(p))) return malformed;

  const header = decodeJson(parts[0]);
  if (!isObject(header)) return malformed;
  if (typeof header.typ !== 'string' || header.typ.toLowerCase() !== PASSPORT_TYP) return malformed;
  // Extensions the verifier does not understand must not be ignored (RFC 7515 4.1.11).
  if (header.crit !== undefined) return malformed;
  if (header.alg !== 'EdDSA') return { ok: false, reason: 'unsupported_alg' };
  if (!isText(header.kid, 256)) return malformed;

  const c = decodeJson(parts[1]);
  if (!isObject(c)) return malformed;
  const agent = c.agent;
  const operator = c.operator;
  const act = c.act;
  const decision = c.decision;
  if (
    !isText(c.iss, 512) ||
    !isText(c.sub, 512) ||
    !isText(c.aud, 512) ||
    !isText(c.jti, 256) ||
    typeof c.iat !== 'number' ||
    !Number.isFinite(c.iat) ||
    typeof c.exp !== 'number' ||
    !Number.isFinite(c.exp) ||
    !isObject(agent) ||
    !isText(agent.id, 256) ||
    !isText(agent.name, 512) ||
    !isOptionalText(agent.purpose, 2048) ||
    !isObject(operator) ||
    !isText(operator.id, 256) ||
    !isText(operator.name, 512) ||
    !isOptionalText(operator.domain, 256) ||
    (act !== undefined && act !== null && (!isObject(act) || !isText(act.sub, 256) || !isOptionalText(act.domain, 256))) ||
    (c.scope !== undefined && c.scope !== null && typeof c.scope !== 'string') ||
    (decision !== undefined && decision !== null && !isObject(decision))
  ) {
    return malformed;
  }

  const signature = Buffer.from(parts[2], 'base64url');
  if (signature.length !== 64) return malformed;

  const claims: PassportClaims = {
    iss: c.iss,
    sub: c.sub,
    aud: c.aud,
    iat: c.iat,
    exp: c.exp,
    jti: c.jti,
    agent: agentOf(agent),
    operator: { id: operator.id as string, name: operator.name as string, domain: typeof operator.domain === 'string' && operator.domain ? operator.domain : null },
    ...(isObject(act) ? { act: actOf(act) } : {}),
    ...(typeof c.scope === 'string' ? { scope: c.scope } : {}),
    ...(isObject(decision) ? { decision: { id: String(decision.id ?? ''), policyVersion: String(decision.policyVersion ?? '') } } : {}),
  };
  return {
    ok: true,
    passport: { kid: header.kid, claims, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), signature },
  };
}

/** The scopes a passport presents: well-formed ones only, at most 32. */
export function scopesOf(scope: string | undefined): string[] {
  if (!scope) return [];
  const out: string[] = [];
  for (const s of scope.split(/\s+/)) {
    if (SCOPE.test(s) && !out.includes(s)) out.push(s);
    if (out.length >= MAX_SCOPES) break;
  }
  return out;
}

export function verifySignature(p: ParsedPassport, key: KeyObject): boolean {
  try {
    return cryptoVerify(null, p.signingInput, key, p.signature);
  } catch {
    return false;
  }
}

/** An issuer base URL without its trailing slash. */
export function normaliseIssuer(iss: string): string {
  return iss.replace(/\/+$/, '');
}

type Audience = { host: string; origin?: string };

/**
 * What an audience names: a host name as is (lower case), or an origin and its
 * host. `strict` refuses origins that are not https (passport audiences).
 */
export function parseAudience(value: string, strict: boolean): Audience | null {
  if (typeof value !== 'string') return null;
  const v = value.trim().toLowerCase();
  if (!v) return null;
  if (v.includes('://')) {
    let url: URL;
    try {
      url = new URL(v);
    } catch {
      return null;
    }
    if (url.protocol !== 'https:' && (strict || url.protocol !== 'http:')) return null;
    if (url.username || url.password || (url.pathname && url.pathname !== '/') || url.search || url.hash) return null;
    return url.host ? { host: url.host, origin: url.origin } : null;
  }
  return /^[a-z0-9.-]+(:\d{1,5})?$/.test(v) ? { host: v.replace(/\.$/, '') } : null;
}

/**
 * Step 5: the passport's aud names one of the receiver's audiences. Hosts
 * compare case-insensitively; a bare host on either side matches an origin
 * with that host; two origins must be identical.
 */
export function audienceMatches(aud: string, audiences: string[]): boolean {
  const a = parseAudience(aud, true);
  if (!a) return false;
  return audiences.some((value) => {
    const b = parseAudience(value, false);
    if (!b) return false;
    if (a.origin && b.origin) return a.origin === b.origin;
    return a.host === b.host;
  });
}

const HOUR_MS = 60 * 60 * 1000;
const MISS_REFETCH_MS = 60 * 1000;
const FETCH_TIMEOUT_MS = 5000;

type IssuerKeys = { keys: Map<string, KeyObject>; fetchedAt: number; lastAttempt: number; inflight?: Promise<void> };

/** Fetches with a timeout; resolves to undefined on any failure. */
export async function fetchJson(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<{ status: number; body: unknown } | undefined> {
  const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
  const timer = controller ? setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS) : undefined;
  (timer as { unref?: () => void } | undefined)?.unref?.();
  try {
    const res = await fetchImpl(url, { ...init, signal: controller?.signal });
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = undefined;
    }
    return { status: res.status, body };
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function keyFromJwk(jwk: unknown): { kid: string; key: KeyObject } | undefined {
  if (!isObject(jwk) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !isText(jwk.x, 128) || !isText(jwk.kid, 256)) return undefined;
  if (jwk.d !== undefined) return undefined; // never accept a private key as a verification key
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    return { kid: jwk.kid, key };
  } catch {
    return undefined;
  }
}

/**
 * The issuers' public keys: cached for an hour; an unknown kid refetches at
 * most once a minute per issuer. A stale key is still used when a refetch fails
 * (published keys stay published after rotation).
 */
export class KeyCache {
  private readonly issuers = new Map<string, IssuerKeys>();

  constructor(
    private readonly fetchImpl: () => typeof fetch,
    private readonly now: () => number,
  ) {}

  async get(issuer: string, kid: string): Promise<KeyObject | undefined> {
    let entry = this.issuers.get(issuer);
    if (!entry) {
      entry = { keys: new Map(), fetchedAt: -Infinity, lastAttempt: -Infinity };
      this.issuers.set(issuer, entry);
    }
    const now = this.now();
    const known = entry.keys.get(kid);
    if (known && now - entry.fetchedAt < HOUR_MS) return known;
    // An unknown kid (or a stale set) refetches at most once a minute per issuer.
    if (!entry.inflight) {
      if (now - entry.lastAttempt < MISS_REFETCH_MS) return known;
      entry.lastAttempt = now;
    }
    await this.refresh(issuer, kid, entry);
    return entry.keys.get(kid) ?? known;
  }

  private refresh(issuer: string, kid: string, entry: IssuerKeys): Promise<void> {
    if (entry.inflight) return entry.inflight;
    entry.inflight = (async () => {
      const got = await fetchJson(this.fetchImpl(), `${issuer}/api/agent-passports/keys?kid=${encodeURIComponent(kid)}`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
      if (!got || got.status !== 200 || !isObject(got.body) || !Array.isArray(got.body.keys)) return;
      for (const jwk of got.body.keys.slice(0, 50)) {
        const k = keyFromJwk(jwk);
        if (k) entry.keys.set(k.kid, k.key);
      }
      entry.fetchedAt = this.now();
    })().finally(() => {
      entry.inflight = undefined;
    });
    return entry.inflight;
  }
}

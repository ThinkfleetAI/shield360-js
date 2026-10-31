/**
 * Deception (README "Deception"): decoy paths from the signed config's
 * `deception` block. A request for a decoy never reaches the app: it gets the
 * not-found answer and its client address is marked suspicious for
 * `ttlSeconds`; later requests from that address are reported, and blocked
 * when the decision is `blocked`.
 *
 * The config reader and the matcher are pure; the suspicious-address table is
 * in memory, per process. Every adapter calls `checkDeception` first, before
 * capture, and it fails open: any error lets the request through.
 */
import { eventRouteOf } from './context';
import { deceptionConfig, deceptionMode, reportDeception } from './engine';
import { RaspBlockedError } from './types';

export type DeceptionConfig = { paths: string[]; action: 'block' | 'monitor'; ttlSeconds: number };

export const MAX_DECOYS = 64;
export const MAX_DECOY_LENGTH = 256;
export const DEFAULT_TTL_S = 900;
export const MAX_TTL_S = 86_400;
export const MAX_SUSPICIOUS = 10_000;
export const HIT_RULE = 'deception.hit';
export const SUSPICIOUS_RULE = 'deception.suspicious';
export const DECEPTION_SINK = 'http.deception';

/** Reads the signed config's `deception` value ("Deception", "Config"); null when deception is off. */
export function parseDeception(v: unknown): DeceptionConfig | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (!Array.isArray(o.paths)) return null;
  const paths: string[] = [];
  for (const p of o.paths) {
    if (paths.length >= MAX_DECOYS) break;
    if (typeof p !== 'string' || p.length > MAX_DECOY_LENGTH || !p.startsWith('/')) continue;
    const trimmed = p.endsWith('/') ? p.slice(0, -1) : p;
    if (trimmed === '' || trimmed === '/') continue;
    paths.push(trimmed);
  }
  if (!paths.length) return null;
  const ttl = o.ttlSeconds;
  return {
    paths,
    action: o.action === 'block' ? 'block' : 'monitor',
    ttlSeconds: typeof ttl === 'number' && Number.isFinite(ttl) && ttl >= 1 ? Math.min(Math.floor(ttl), MAX_TTL_S) : DEFAULT_TTL_S,
  };
}

const NON_ASCII = /[\u0080-\uffff]/;
const hex = (c: number): number => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

/**
 * The decoy a request target hits, or null ("Deception", "Matching"). The
 * path (before the first `?`) is percent-decoded once and compared byte for
 * byte with each decoy's UTF-8. Both sides are kept as binary strings (one
 * character per byte): Node's `req.url` already holds the target's bytes that
 * way (it reads them as latin1); a character above U+00FF, which only a
 * caller's own string can hold, counts as its UTF-8 bytes.
 */
export function matchDecoy(target: string, decoys: readonly string[]): string | null {
  const q = target.indexOf('?');
  const raw = q >= 0 ? target.slice(0, q) : target;
  let path = raw;
  if (raw.includes('%') || NON_ASCII.test(raw)) {
    path = '';
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      if (c === 37) {
        const h = hex(raw.charCodeAt(i + 1));
        const l = hex(raw.charCodeAt(i + 2));
        if (h < 0 || l < 0) return null;
        path += String.fromCharCode(h * 16 + l);
        i += 2;
      } else if (c <= 0xff) {
        path += raw[i];
      } else {
        const cp = raw.codePointAt(i) as number;
        path += Buffer.from(String.fromCodePoint(cp), 'utf8').toString('latin1');
        if (cp > 0xffff) i++;
      }
    }
  }
  for (const d of decoys) {
    const b = NON_ASCII.test(d) ? Buffer.from(d, 'utf8').toString('latin1') : d;
    if (path === b || path.startsWith(`${b}/`)) return d;
  }
  return null;
}

type Mark = { ip: string; until: number; prev?: Mark; next?: Mark };

/**
 * Suspicious client addresses, at most `cap` entries, kept in expiry order
 * (soonest first; equal expiries in marking order), so a TTL lowered by a new
 * config never leaves an expired mark behind a live one. Marking a new
 * address when full first drops every expired mark, then the mark closest to
 * expiring. Single threaded, so no locking.
 */
export class SuspiciousTable {
  private readonly marks = new Map<string, Mark>();
  private head?: Mark;
  private tail?: Mark;

  constructor(
    private readonly cap = MAX_SUSPICIOUS,
    private readonly now: () => number = Date.now,
  ) {}

  private unlink(m: Mark): void {
    if (m.prev) m.prev.next = m.next;
    else this.head = m.next;
    if (m.next) m.next.prev = m.prev;
    else this.tail = m.prev;
    m.prev = m.next = undefined;
    this.marks.delete(m.ip);
  }

  /** Marks (or marks again, restarting the time) an address for `ttlSeconds`. */
  mark(ip: string, ttlSeconds: number): void {
    const now = this.now();
    const until = now + ttlSeconds * 1000;
    const old = this.marks.get(ip);
    if (old) this.unlink(old);
    else if (this.marks.size >= this.cap) {
      while (this.head && this.head.until <= now) this.unlink(this.head);
      if (this.marks.size >= this.cap && this.head) this.unlink(this.head);
    }
    // After the last mark that expires no later: an append while the TTL stays the same.
    let after = this.tail;
    while (after && after.until > until) after = after.prev;
    const m: Mark = { ip, until, prev: after, next: after ? after.next : this.head };
    if (m.next) m.next.prev = m;
    else this.tail = m;
    if (after) after.next = m;
    else this.head = m;
    this.marks.set(ip, m);
  }

  /** Whether an address is marked; an expired mark is dropped. Never extends a mark. */
  isMarked(ip: string): boolean {
    const m = this.marks.get(ip);
    if (!m) return false;
    if (m.until <= this.now()) {
      this.unlink(m);
      return false;
    }
    return true;
  }

  get size(): number {
    return this.marks.size;
  }

  /** The marked addresses, soonest to expire first (tests). */
  keys(): string[] {
    const out: string[] = [];
    for (let m = this.head; m; m = m.next) out.push(m.ip);
    return out;
  }
}

let table = new SuspiciousTable();

/** The process's table (tests). */
export function suspiciousTable(): SuspiciousTable {
  return table;
}

/** Replaces the process's table (tests: a small cap, a fake clock). */
export function setSuspiciousTable(t: SuspiciousTable): void {
  table = t;
}

/** A request as deception sees it: the raw target (path and query as received) and the client address `request.ip` uses. */
export type DeceptionRequest = { framework: string; method: string; url: string; ip?: string };

/** What the adapter does: go on, answer its not-found, or answer the block response. */
export type DeceptionOutcome = { notFound?: true; blocked?: RaspBlockedError };

const PASS: DeceptionOutcome = {};

/**
 * Runs deception for a request ("Deception", "Decision"). Call it only while
 * RASP is active, before anything else. Never throws: an error lets the
 * request through as if deception were off.
 */
export function checkDeception(r: DeceptionRequest): DeceptionOutcome {
  try {
    const cfg = deceptionConfig();
    if (!cfg) return PASS;
    const mode = deceptionMode();
    if (!mode) return PASS;
    const block = cfg.action === 'block' && mode === 'block';
    const extra = { framework: r.framework, method: r.method };
    const decoy = matchDecoy(r.url, cfg.paths);
    if (decoy !== null) {
      if (r.ip) table.mark(r.ip, cfg.ttlSeconds);
      reportDeception(HIT_RULE, block, { ...extra, route: decoy });
      return { notFound: true };
    }
    if (!r.ip || !table.isMarked(r.ip)) return PASS;
    const q = r.url.indexOf('?');
    const eventId = reportDeception(SUSPICIOUS_RULE, block, { ...extra, route: eventRouteOf(q >= 0 ? r.url.slice(0, q) : r.url) });
    return block ? { blocked: new RaspBlockedError('deception', SUSPICIOUS_RULE, eventId) } : PASS;
  } catch {
    return PASS;
  }
}

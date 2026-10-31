/**
 * RAG retrieval checks (OWASP LLM08 vector and embedding weaknesses).
 *
 * Tenant isolation: a retrieved chunk whose tenant metadata names another
 * tenant than the requesting end customer's is flagged (rag_cross_tenant).
 * In enforce mode it is dropped before the model sees it (or the retrieval
 * is refused, action block). In monitor mode it is kept, and its
 * identifiers are remembered so the output check can tell when they come
 * back in the answer (cross_tenant). Developers name the metadata field
 * (rag.tenantField, default tenant_id) or pass tenantOf(chunk).
 *
 * Hub chunks: a lightweight, streaming version of adversarial hubness
 * detection, after Cisco AI Defense's adversarial-hubness-detector
 * (https://github.com/cisco-ai-defense/adversarial-hubness-detector,
 * Apache-2.0): a poisoned chunk written to match everything turns up in the
 * results of many unrelated queries. Over a sliding window of recent
 * retrievals, each chunk's hub rate (share of retrievals it appears in) is
 * compared with the others' by a robust z-score (median and MAD), and the
 * queries it answered are grouped by word overlap so "unrelated" means
 * several groups. Flagged once per chunk per hour (rag_hub); never dropped,
 * because popular content is not proof of poisoning.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_rag.py
 */

import { createHash } from 'crypto';

export type Chunk = { text: string; id?: string; metadata?: Record<string, unknown> };

export type TenantVerdict = { index: number; tenant: string | null; foreign: boolean };

/** The tenant a chunk names, or null when it names none. */
export function chunkTenant(chunk: Chunk, field: string, tenantOf?: (chunk: Chunk) => unknown): string | null {
  try {
    const raw = tenantOf ? tenantOf(chunk) : readField(chunk.metadata, field);
    if (typeof raw === 'string' && raw.trim()) return raw.trim();
    if (typeof raw === 'number' && Number.isFinite(raw)) return String(raw);
  } catch {
    // a failing callback names no tenant
  }
  return null;
}

/** metadata.a.b for "a.b". */
function readField(metadata: Record<string, unknown> | undefined, field: string): unknown {
  let v: unknown = metadata;
  for (const part of field.split('.')) {
    if (!v || typeof v !== 'object') return undefined;
    v = (v as Record<string, unknown>)[part];
  }
  return v;
}

export function tenantVerdicts(chunks: readonly Chunk[], tenant: string | null, field: string, tenantOf?: (chunk: Chunk) => unknown): TenantVerdict[] {
  return chunks.map((c, index) => {
    const t = chunkTenant(c, field, tenantOf);
    return { index, tenant: t, foreign: !!tenant && !!t && t !== tenant };
  });
}

export const chunkId = (c: Chunk) =>
  (typeof c.id === 'string' && c.id) || (typeof c.metadata?.id === 'string' && (c.metadata.id as string)) || createHash('sha256').update(c.text || '').digest('hex').slice(0, 16);

// ---------------------------------------------------------------------------
// Hubness.

const STOP = new Set('a an and are as at be by for from how i in is it of on or that the this to was what when where which who why with you your me my do does can'.split(' '));

function queryTerms(query: string): Set<string> {
  const words = (query.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) || []).filter((w) => !STOP.has(w));
  return new Set(words.slice(0, 32));
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0;
  let both = 0;
  a.forEach((w) => {
    if (b.has(w)) both++;
  });
  return both / (a.size + b.size - both);
}

export type HubFinding = { chunk: string; rate: number; z: number; groups: number; retrievals: number };

export type HubnessOptions = {
  /** Retrievals kept (default 500). */
  window?: number;
  /** Retrievals needed before anything is judged (default 50). */
  minRetrievals?: number;
  /** Robust z-score a hub must reach (default 5). */
  minZ?: number;
  /** Share of retrievals a hub must appear in (default 0.1). */
  minRate?: number;
  /** Unrelated query groups a hub must have answered (default 5). */
  minGroups?: number;
  now?: () => number;
};

type Retrieval = { group: number; chunks: string[] };

export class HubnessMonitor {
  private readonly ring: Retrieval[] = [];
  private readonly counts = new Map<string, number>();
  private readonly groupsOf = new Map<string, Map<number, number>>();
  private readonly groups: Set<string>[] = [];
  private readonly flagged = new Map<string, number>();
  private readonly o: Required<HubnessOptions>;

  constructor(opts: HubnessOptions = {}) {
    this.o = { window: 500, minRetrievals: 50, minZ: 5, minRate: 0.1, minGroups: 5, now: Date.now, ...opts };
  }

  private groupOf(query: string): number {
    const terms = queryTerms(query);
    let best = -1;
    let bestScore = 0.3;
    for (let i = 0; i < this.groups.length; i++) {
      const s = jaccard(terms, this.groups[i]);
      if (s >= bestScore) {
        best = i;
        bestScore = s;
      }
    }
    if (best >= 0) return best;
    if (this.groups.length < 500) {
      this.groups.push(terms);
      return this.groups.length - 1;
    }
    return this.groups.length - 1;
  }

  /** Records one retrieval; returns the chunks it newly shows to be hubs. */
  observe(query: string, chunkIds: readonly string[]): HubFinding[] {
    const ids = Array.from(new Set(chunkIds)).slice(0, 100);
    const group = this.groupOf(query || '');
    this.ring.push({ group, chunks: ids });
    for (const id of ids) {
      this.counts.set(id, (this.counts.get(id) || 0) + 1);
      const g = this.groupsOf.get(id) || new Map<number, number>();
      g.set(group, (g.get(group) || 0) + 1);
      this.groupsOf.set(id, g);
    }
    if (this.ring.length > this.o.window) {
      const old = this.ring.shift() as Retrieval;
      for (const id of old.chunks) {
        const n = (this.counts.get(id) || 1) - 1;
        if (n <= 0) {
          this.counts.delete(id);
          this.groupsOf.delete(id);
        } else {
          this.counts.set(id, n);
          const g = this.groupsOf.get(id);
          if (g) {
            const k = (g.get(old.group) || 1) - 1;
            if (k <= 0) g.delete(old.group);
            else g.set(old.group, k);
          }
        }
      }
    }
    if (this.ring.length < this.o.minRetrievals) return [];
    const total = this.ring.length;
    const rates = Array.from(this.counts.values()).map((c) => c / total);
    const median = quantile(rates, 0.5);
    const mad = quantile(rates.map((r) => Math.abs(r - median)), 0.5);
    const scale = 1.4826 * mad + 1 / total;
    const out: HubFinding[] = [];
    const now = this.o.now();
    for (const id of ids) {
      const rate = (this.counts.get(id) || 0) / total;
      const z = (rate - median) / scale;
      const groups = this.groupsOf.get(id)?.size || 0;
      if (rate < this.o.minRate || z < this.o.minZ || groups < this.o.minGroups) continue;
      const last = this.flagged.get(id);
      if (last && now - last < 3_600_000) continue;
      this.flagged.set(id, now);
      out.push({ chunk: id, rate: Math.round(rate * 1000) / 1000, z: Math.round(z * 10) / 10, groups, retrievals: total });
    }
    return out;
  }
}

function quantile(values: number[], q: number): number {
  if (!values.length) return 0;
  const s = values.slice().sort((a, b) => a - b);
  const pos = (s.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return s[lo] + (s[hi] - s[lo]) * (pos - lo);
}

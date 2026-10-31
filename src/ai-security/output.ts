/**
 * Output scanning (OWASP LLM02 sensitive information disclosure, LLM05
 * improper output handling, LLM07 system prompt leakage): what a model
 * answered, checked before the app returns it.
 *
 *   pii / secret     built-in kinds (e-mail, SSN, payment card, phone; API
 *                    keys, tokens, private keys, connection strings)
 *   custom_kind      the organisation's own kinds of data
 *   cross_tenant     identifiers of another tenant that reached this
 *                    request's context (RAG tenant check, tagContext)
 *   exfil_link       markdown/HTML images to domains not on the allow-list
 *                    (renderers fetch them unasked), and links or images
 *                    carrying data in their query string or path
 *   system_prompt_leak  runs of the request's own system prompt (distinctive
 *                    6-word shingles) appearing in the answer
 *   canary_leak      the configured canary marker appearing in the answer
 *
 * Findings carry a masked token and a keyed fingerprint, never the value.
 * redact replaces each finding's span with its token (or "[link removed]");
 * block withholds the answer. A leaked system prompt is withheld in enforce
 * mode whatever the action: a redacted prompt still leaks its structure.
 *
 * OutputStreamScanner checks a streamed answer as it arrives with bounded
 * memory: it holds back the last HOLDBACK characters so a value split across
 * chunks can still be redacted, and scans a sliding window.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_output.py
 */

import { makeFinding } from '../guard/findings';
import { findCustomKinds } from './custom-kinds';
import type { AiSecurityPolicy, CustomDataKindDef } from './policy';

export type OutputFindingKind = 'pii' | 'secret' | 'custom_kind' | 'cross_tenant' | 'exfil_link' | 'system_prompt_leak' | 'canary_leak';

export type OutputFinding = {
  kind: OutputFindingKind;
  /** The label: email, payment_card, api_key, a custom kind's id, image, query_data... */
  label: string;
  start: number;
  end: number;
  masked: string;
  fingerprint?: string;
};

export type OutputScanOptions = {
  policy: AiSecurityPolicy['output'];
  customKinds?: readonly CustomDataKindDef[];
  /** The request's system prompt, for the leakage check. */
  systemPrompt?: string | null;
  /** Lower-cased identifier -> other tenant. */
  foreign?: ReadonlyMap<string, string>;
};

export type OutputScanResult = {
  findings: OutputFinding[];
  /** The text with every finding replaced by its token. */
  redacted: string;
  /** Whether enforce mode must withhold the answer whatever the action. */
  mustBlock: boolean;
};

type Pattern = { label: string; kind: 'pii' | 'secret'; re: RegExp; check?: (v: string) => boolean };

const luhn = (v: string) => {
  const d = v.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
};

const issuableSsn = (v: string) => {
  const [a, b, c] = v.split('-');
  return a !== '000' && a !== '666' && a[0] !== '9' && b !== '00' && c !== '0000';
};

// High-precision shapes only: an output check that flags every hex string is switched off by the people it annoys.
const PATTERNS: Pattern[] = [
  { label: 'openai-api-key', kind: 'secret', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { label: 'anthropic-api-key', kind: 'secret', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { label: 'aws-access-key', kind: 'secret', re: /(?<![A-Za-z0-9/+=])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9/+=])/g },
  { label: 'gcp-api-key', kind: 'secret', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { label: 'github-token', kind: 'secret', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g },
  { label: 'github-fine-grained', kind: 'secret', re: /\bgithub_pat_[A-Za-z0-9_]{22,}/g },
  { label: 'stripe-key', kind: 'secret', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}/g },
  { label: 'slack-token', kind: 'secret', re: /\bxox[bpoas]-[A-Za-z0-9-]{10,}/g },
  { label: 'private-key', kind: 'secret', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  { label: 'connection-string', kind: 'secret', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s:@/]+:[^\s@/]+@[^\s]+/g },
  { label: 'jwt', kind: 'secret', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { label: 'email', kind: 'pii', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g },
  { label: 'ssn', kind: 'pii', re: /(?<![0-9-])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9-])/g, check: issuableSsn },
  { label: 'credit-card', kind: 'pii', re: /(?<![0-9])(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{3,4}(?![0-9])/g, check: luhn },
  { label: 'phone-us', kind: 'pii', re: /(?<![0-9])(?:\+1[ .-]?)?\(?[2-9][0-9]{2}\)?[ .-][0-9]{3}[ .-][0-9]{4}(?![0-9])/g },
];

// ---------------------------------------------------------------------------
// Links.

const MD_IMAGE = /!\[[^\]\n]{0,200}\]\(\s*<?(https?:\/\/[^\s)>]+)>?[^)\n]{0,200}\)/gi;
const HTML_IMAGE = /<img\b[^>\n]{0,300}?\bsrc\s*=\s*["']?(https?:\/\/[^\s"'>]+)/gi;
const ANY_URL = /\bhttps?:\/\/[^\s<>"'()\]]+/gi;

export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return allowed.some((d) => (d.startsWith('*.') ? h === d.slice(2) || h.endsWith(d.slice(1)) : h === d));
}

/** Whether a URL carries data: a long query value or path segment that looks encoded, or a sensitive value. */
export function urlCarriesData(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const values: string[] = [];
  parsed.searchParams.forEach((v) => values.push(v));
  if (parsed.hash.length > 1) values.push(decodeSafe(parsed.hash.slice(1)));
  for (const seg of parsed.pathname.split('/')) values.push(decodeSafe(seg));
  return values.some((v) => {
    if (v.length >= 40 && /^[A-Za-z0-9+/=_-]+$/.test(v)) return true; // base64 / hex blob
    if (v.length >= 24 && /\s/.test(v) && /[a-z]{3,}/i.test(v)) return true; // prose in a URL
    return PATTERNS.some((p) => {
      p.re.lastIndex = 0;
      const m = p.re.exec(v);
      return !!m && (!p.check || p.check(m[0]));
    });
  });
}

function decodeSafe(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

// ---------------------------------------------------------------------------
// System prompt shingles.

const SHINGLE = 6;
const STOP = new Set(
  'a an and are as at be by for from has have i if in into is it its of on or that the their them then there these they this to was were will with you your we our us not no do does can should must may'.split(' '),
);

const words = (text: string) => text.toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];

/** The distinctive 6-word shingles of a system prompt: those with at least two words that are not stop words. */
export function promptShingles(prompt: string, max = 5000): Set<string> {
  const w = words(prompt);
  const out = new Set<string>();
  for (let i = 0; i + SHINGLE <= w.length && out.size < max; i++) {
    const s = w.slice(i, i + SHINGLE);
    if (s.filter((x) => !STOP.has(x)).length >= 2) out.add(s.join(' '));
  }
  return out;
}

/** How many of the prompt's shingles appear in a text (each counted once). */
function leakedShingles(text: string, shingles: Set<string>): number {
  if (!shingles.size) return 0;
  const w = words(text);
  const seen = new Set<string>();
  for (let i = 0; i + SHINGLE <= w.length; i++) {
    const s = w.slice(i, i + SHINGLE).join(' ');
    if (shingles.has(s)) seen.add(s);
  }
  return seen.size;
}

/** A leak: at least 3 shingles and at least a tenth of the prompt's (or 25, whichever is less). */
export function isLeak(matched: number, total: number): boolean {
  if (total === 0 || matched < 3) return false;
  return matched >= Math.min(25, Math.max(3, Math.ceil(total * 0.1)));
}

// ---------------------------------------------------------------------------
// The scan.

function finding(kind: OutputFindingKind, label: string, start: number, end: number, value: string): OutputFinding {
  if (kind === 'exfil_link') return { kind, label, start, end, masked: '[link removed]' };
  const f = makeFinding(kind === 'custom_kind' ? `custom_${label}` : kind === 'cross_tenant' ? 'cross_tenant' : label, value);
  return { kind, label, start, end, masked: f.masked, ...(f.fingerprint ? { fingerprint: f.fingerprint } : {}) };
}

const MAX_SCAN = 200_000;

export function scanOutput(text: string, opts: OutputScanOptions): OutputScanResult {
  const p = opts.policy;
  const t = typeof text === 'string' ? (text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text) : '';
  const out: OutputFinding[] = [];
  let mustBlock = false;
  if (!t) return { findings: out, redacted: typeof text === 'string' ? text : '', mustBlock };

  for (const pat of PATTERNS) {
    if ((pat.kind === 'pii' && !p.pii) || (pat.kind === 'secret' && !p.secrets)) continue;
    pat.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pat.re.exec(t)) && out.length < 200) {
      if (pat.check && !pat.check(m[0])) continue;
      out.push(finding(pat.kind, pat.label, m.index, m.index + m[0].length, m[0]));
    }
  }
  if (p.customKinds && opts.customKinds?.length) {
    for (const f of findCustomKinds(t, opts.customKinds).slice(0, 100)) out.push(finding('custom_kind', f.id, f.start, f.end, t.slice(f.start, f.end)));
  }
  if (p.crossTenant && opts.foreign?.size) {
    const lower = t.toLowerCase();
    opts.foreign.forEach((_tenant, id) => {
      let at = lower.indexOf(id);
      while (at >= 0 && out.length < 300) {
        out.push(finding('cross_tenant', 'identifier', at, at + id.length, t.slice(at, at + id.length)));
        at = lower.indexOf(id, at + id.length);
      }
    });
  }
  if (p.exfilLinks) {
    const images = new Set<number>();
    for (const re of [MD_IMAGE, HTML_IMAGE]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(t))) {
        const url = m[1];
        const start = m.index + m[0].indexOf(url);
        images.add(start);
        let host = '';
        try {
          host = new URL(url).hostname;
        } catch {
          continue;
        }
        const allowed = p.allowedDomains.length > 0 && hostAllowed(host, p.allowedDomains);
        if (allowed) continue;
        if (p.allowedDomains.length > 0 || urlCarriesData(url)) out.push(finding('exfil_link', 'image', start, start + url.length, url));
      }
    }
    ANY_URL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ANY_URL.exec(t))) {
      if (images.has(m.index)) continue;
      const url = m[0].replace(/[.,;:!?]+$/, '');
      let host = '';
      try {
        host = new URL(url).hostname;
      } catch {
        continue;
      }
      if (p.allowedDomains.length > 0 && hostAllowed(host, p.allowedDomains)) continue;
      if (urlCarriesData(url)) out.push(finding('exfil_link', 'query_data', m.index, m.index + url.length, url));
    }
  }
  if (p.canary) {
    const at = t.indexOf(p.canary);
    if (at >= 0) {
      out.push({ kind: 'canary_leak', label: 'canary', start: at, end: at + p.canary.length, masked: '[canary]' });
      mustBlock = true;
    }
  }
  if (p.systemPromptLeak && opts.systemPrompt) {
    const shingles = promptShingles(opts.systemPrompt);
    const n = leakedShingles(t, shingles);
    if (isLeak(n, shingles.size)) {
      out.push({ kind: 'system_prompt_leak', label: `${n}/${shingles.size}`, start: 0, end: 0, masked: '[system prompt]' });
      mustBlock = true;
    }
  }
  return { findings: out, redacted: redact(text, out), mustBlock };
}

/** Replaces finding spans with their tokens; overlapping spans merge, the earliest finding's token wins. */
export function redact(text: string, findings: readonly OutputFinding[]): string {
  const spans = findings
    .filter((f) => f.end > f.start)
    .slice()
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: { start: number; end: number; masked: string }[] = [];
  for (const f of spans) {
    const last = merged[merged.length - 1];
    if (last && f.start < last.end) last.end = Math.max(last.end, f.end);
    else merged.push({ start: f.start, end: f.end, masked: f.masked });
  }
  let s = text;
  for (let i = merged.length - 1; i >= 0; i--) s = s.slice(0, merged[i].start) + merged[i].masked + s.slice(merged[i].end);
  return s;
}

// ---------------------------------------------------------------------------
// Streaming.

/** Characters held back before release, so a value split across chunks is still caught whole. */
export const HOLDBACK = 256;
/** Characters of already-released text kept for context (prompt shingles, links that started earlier). */
export const WINDOW = 2048;
/** Pending characters beyond the holdback before a scan runs: fewer scans of the window, at most this much more delay. */
export const RELEASE_STEP = 128;

export type StreamVerdict = { text: string; findings: OutputFinding[]; blocked: boolean };

/**
 * Scans a streamed answer incrementally. push() returns what may be released
 * now (redacted when asked); end() returns the rest. Memory is bounded by
 * WINDOW + HOLDBACK + one chunk; the prompt-leak count needs only the
 * shingles already seen. When blocking, nothing more is released once a
 * finding that blocks appears.
 */
export class OutputStreamScanner {
  private pending = '';
  private released = '';
  /** Characters released so far, for stable finding ids. */
  private offset = 0;
  private readonly shingles: Set<string>;
  private readonly leaked = new Set<string>();
  private tailWords: string[] = [];
  /** A word cut by the chunk boundary, completed by the next chunk. */
  private partial = '';
  private reported = new Set<string>();
  blocked = false;
  readonly findings: OutputFinding[] = [];

  constructor(
    private readonly opts: OutputScanOptions,
    private readonly enforce: { redact: boolean; block: boolean },
  ) {
    this.shingles = opts.policy.systemPromptLeak && opts.systemPrompt ? promptShingles(opts.systemPrompt) : new Set();
  }

  push(chunk: string): StreamVerdict {
    if (this.blocked) return { text: '', findings: [], blocked: true };
    this.pending += chunk || '';
    this.countShingles(chunk || '');
    if (this.pending.length <= HOLDBACK + RELEASE_STEP) return this.verdict('', []);
    return this.release(this.pending.length - HOLDBACK);
  }

  end(): StreamVerdict {
    if (this.blocked) return { text: '', findings: [], blocked: true };
    this.countShingles(' ');
    return this.release(this.pending.length);
  }

  private countShingles(chunk: string) {
    if (!this.shingles.size) return;
    const text = this.partial + chunk;
    const cut = text.match(/[\p{L}\p{N}]+$/u);
    this.partial = cut ? cut[0].slice(-64) : '';
    const w = this.tailWords.concat(words(cut ? text.slice(0, text.length - cut[0].length) : text));
    for (let i = 0; i + SHINGLE <= w.length; i++) {
      const s = w.slice(i, i + SHINGLE).join(' ');
      if (this.shingles.has(s)) this.leaked.add(s);
    }
    this.tailWords = w.slice(-(SHINGLE - 1));
  }

  private release(upTo: number): StreamVerdict {
    // Scan the released tail plus everything pending, so a match straddling the cut is seen whole.
    const ctx = this.released.slice(-WINDOW);
    const scanText = ctx + this.pending;
    const { findings } = scanOutput(scanText, { ...this.opts, systemPrompt: null });
    const fresh: OutputFinding[] = [];
    for (const f of findings) {
      // Only findings that end in the part being released are judged now; later ones wait for more text.
      const start = f.start - ctx.length;
      const end = f.end - ctx.length;
      if (end <= 0) continue; // seen and handled in an earlier window
      if (start >= upTo && upTo < this.pending.length) continue;
      const id = `${f.kind}:${f.label}:${f.masked}:${start + this.offset}`;
      if (this.reported.has(id)) continue;
      this.reported.add(id);
      fresh.push({ ...f, start, end });
    }
    if (isLeak(this.leaked.size, this.shingles.size) && !this.reported.has('leak')) {
      this.reported.add('leak');
      fresh.push({ kind: 'system_prompt_leak', label: `${this.leaked.size}/${this.shingles.size}`, start: 0, end: 0, masked: '[system prompt]' });
    }
    const blocks = fresh.some((f) => f.kind === 'system_prompt_leak' || f.kind === 'canary_leak');
    if (fresh.length && this.enforce.block) this.blocked = true;
    if (blocks && (this.enforce.block || this.enforce.redact)) this.blocked = true;
    if (this.blocked) {
      this.findings.push(...fresh);
      this.pending = '';
      return { text: '', findings: fresh, blocked: true };
    }
    // Extend the cut so no finding is split: a value that crosses it is released whole (redacted) now.
    let cut = upTo;
    for (const f of fresh) if (f.start < cut && f.end > cut) cut = Math.min(this.pending.length, f.end);
    const part = this.pending.slice(0, cut);
    const inPart = fresh.filter((f) => f.start >= 0 && f.end <= cut);
    const text = this.enforce.redact ? redact(part, inPart) : part;
    this.pending = this.pending.slice(cut);
    this.released = (this.released + part).slice(-WINDOW);
    this.offset += part.length;
    this.findings.push(...fresh);
    return this.verdict(text, fresh);
  }

  private verdict(text: string, findings: OutputFinding[]): StreamVerdict {
    return { text, findings, blocked: this.blocked };
  }
}

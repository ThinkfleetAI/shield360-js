/**
 * Virtual patches (README "Virtual patches"): rules that match the documented
 * request shape of a public advisory. The one place RASP matches request
 * signatures; every other check is structural. Run once per request, when
 * its input is captured, before the handler.
 *
 * The built-in list is `data/default-rules.json`, a byte-identical copy of
 * `sdk/rasp/rules/default-rules.json` (a test says so). The signed config's
 * `rules` replace it when present.
 */
import type { Finding, RaspMode } from './types';
import builtIn from './data/default-rules.json';

export type MatchClause = {
  target: string;
  op: 'present' | 'equals' | 'contains_any' | 'regex';
  values?: string[];
  value?: string;
  ignoreCase?: boolean;
};

export type VirtualPatch = {
  id: string;
  title?: string;
  cves?: string[];
  severity?: string;
  example?: boolean;
  runtimes?: string[];
  runtimeVersions?: Record<string, [string, string][]>;
  action?: RaspMode;
  match: MatchClause[];
};

/** The request as the rules see it. Header names are lower-case. */
export type VpRequest = {
  method: string;
  path: string;
  /** The raw query string, without `?`. */
  query: string;
  headers: Record<string, string | string[] | undefined>;
  /** The raw Cookie header. */
  cookie: string;
  /** The raw body text, or the JSON of a parsed body; '' when unknown. */
  body: string;
};

export const MAX_VP_TEXT = 64 * 1024;
const MAX_PATTERN = 1024;
export const BUILT_IN_RULES: VirtualPatch[] = (builtIn as unknown as { rules: VirtualPatch[] }).rules;
export const BUILT_IN_VERSION: string = (builtIn as { version: string }).version;

function cmpVersion(a: string, b: string): number {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

/** Whether the rule applies in this runtime and version (`[from, to)` ranges). */
export function ruleApplies(rule: VirtualPatch, runtime: string, version: string): boolean {
  if (Array.isArray(rule.runtimes) && !rule.runtimes.includes(runtime)) return false;
  const ranges = rule.runtimeVersions?.[runtime];
  if (Array.isArray(ranges)) return ranges.some((r) => Array.isArray(r) && cmpVersion(version, String(r[0])) >= 0 && cmpVersion(version, String(r[1])) < 0);
  return true;
}

/** Whether a rule reads the body (it can only be judged once the body is known). */
export function needsBody(rule: VirtualPatch): boolean {
  return rule.match.some((c) => c && (c.target === 'body' || c.target === 'request'));
}

function targetText(req: VpRequest, target: string): string | undefined {
  if (target === 'method') return req.method;
  if (target === 'path') return req.path;
  if (target === 'query') return req.query;
  if (target === 'cookie') return req.cookie;
  if (target === 'body') return req.body.slice(0, MAX_VP_TEXT);
  if (target === 'request') return `${req.path}?${req.query}\n${req.cookie}\n${req.body.slice(0, MAX_VP_TEXT)}`;
  if (target.startsWith('header:')) {
    const v = req.headers[target.slice(7).toLowerCase()];
    return v === undefined ? undefined : Array.isArray(v) ? v.join(', ') : String(v);
  }
  return undefined;
}

const regexCache = new Map<string, RegExp | null>();

/** Compiles a rule pattern; refuses backreferences and lookaround (contract) and overlong patterns. */
function compile(p: string): RegExp | null {
  if (!regexCache.has(p)) {
    let re: RegExp | null = null;
    if (p.length <= MAX_PATTERN && !/\\[1-9]|\\k<|\(\?<?[=!]/.test(p)) {
      try {
        re = new RegExp(p);
      } catch {
        re = null;
      }
    }
    if (regexCache.size > 512) regexCache.clear();
    regexCache.set(p, re);
  }
  return regexCache.get(p) ?? null;
}

export function clauseMatches(req: VpRequest, c: MatchClause): boolean {
  if (!c || typeof c.target !== 'string') return false;
  const text = targetText(req, c.target);
  if (c.op === 'present') return text !== undefined;
  if (text === undefined) return false;
  const values = Array.isArray(c.values) ? c.values.filter((v): v is string => typeof v === 'string') : [];
  if (c.op === 'equals') return values.some((v) => v.toLowerCase() === text.toLowerCase());
  if (c.op === 'contains_any') {
    if (c.ignoreCase) {
      const t = text.toLowerCase();
      return values.some((v) => v !== '' && t.includes(v.toLowerCase()));
    }
    return values.some((v) => v !== '' && text.includes(v));
  }
  if (c.op === 'regex' && typeof c.value === 'string') {
    const re = compile(c.value);
    return re ? re.test(text.slice(0, MAX_VP_TEXT)) : false;
  }
  return false;
}

export type VpPhase = 'all' | 'head' | 'body';

/**
 * The first rule the request matches, as a finding. `head` judges only rules
 * that do not read the body; `body` only rules that do; `all` both.
 */
export function matchVirtualPatches(
  req: VpRequest,
  rules: VirtualPatch[],
  phase: VpPhase = 'all',
  runtime = 'node',
  version: string = process.versions.node,
): Finding | null {
  for (const r of rules) {
    if (!r || typeof r.id !== 'string' || !Array.isArray(r.match) || !r.match.length) continue;
    if (phase !== 'all' && needsBody(r) !== (phase === 'body')) continue;
    if (!ruleApplies(r, runtime, version)) continue;
    if (r.match.every((c) => clauseMatches(req, c))) {
      const action: RaspMode = r.action === 'off' || r.action === 'monitor' ? r.action : 'block';
      return { attack: 'virtual_patch', rule: r.id, cve: Array.isArray(r.cves) ? r.cves[0] : undefined, action };
    }
  }
  return null;
}

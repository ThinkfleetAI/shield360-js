/**
 * Passive IAST rules (README "Passive IAST"). Pure: each takes what a
 * detector already computed (the sink text, its tokens, the inputs) and says
 * whether a request input reaches the sink verbatim in a place the app did
 * not parameterize, even though the value is harmless and the attack check
 * found nothing. The detectors call these through iast-scope.ts only when
 * passive IAST is armed for the current check, so the rules never run, and
 * never lex, when it is off.
 */
import { occurrences, overlapping, SQL_KEYWORDS, type Token } from './lexers';
import type { RaspInput } from './types';

export const VULN_RULES = [
  'vuln.sql_concat',
  'vuln.cmd_shell',
  'vuln.cmd_arg',
  'vuln.path_from_input',
  'vuln.ssrf_host',
  'vuln.code_eval',
  'vuln.include_from_input',
  'vuln.deser_input',
  'vuln.xml_external',
] as const;
export type VulnRule = (typeof VULN_RULES)[number];

/** Where in the sink argument the input sits. */
export type VulnPosition = 'string' | 'number' | 'identifier' | 'tokens' | 'word' | 'argument' | 'segment' | 'host' | 'url' | 'specifier' | 'data';

export type Vuln = { rule: VulnRule; input: RaspInput; position: VulnPosition };

/** Shortest input considered. */
export const IAST_MIN_LENGTH = 3;
/** Letters-only inputs shorter than this are common words that also appear hard-coded ('active', 'name'). */
export const IAST_MIN_WORD_LENGTH = 8;
/** Digits-only inputs shorter than this are small numbers that also appear hard-coded (`LIMIT 100`). */
export const IAST_MIN_NUMBER_LENGTH = 4;

const BORING_WORDS = new Set('true false null none nil undefined yes no on off asc desc'.split(' '));

/**
 * Whether an input value is specific enough that finding it verbatim in a
 * sink means it came from the request, not a coincidence with a literal the
 * app wrote itself. Conservative on purpose (README "Thresholds").
 */
export function qualifies(value: string): boolean {
  const v = value;
  if (v.length < IAST_MIN_LENGTH) return false;
  if (BORING_WORDS.has(v.toLowerCase())) return false;
  if (/^[A-Za-z]+$/.test(v) && v.length < IAST_MIN_WORD_LENGTH) return false;
  if (/^[0-9.+-]+$/.test(v) && v.length < IAST_MIN_NUMBER_LENGTH) return false;
  if (v.split('').every((c) => c === v[0])) return false;
  // Only spaces and punctuation.
  if (!/[\p{L}\p{N}]/u.test(v)) return false;
  return true;
}

const candidates = (inputs: RaspInput[]) => inputs.filter((i) => i.source === 'request' && qualifies(i.value));

const isComment = (t: Token) => t.kind === 'comment' || t.kind === 'version_comment';

// ---- SQL ----------------------------------------------------------------

/**
 * vuln.sql_concat: an input sits in the query text inside a string literal,
 * as a whole number literal, as a whole identifier (not a keyword), or as a
 * run of whole tokens the attack check let through (a sort list such as
 * `created_at desc`). Never inside a comment (sqlcommenter tags), never when
 * the input is the whole query (a SQL console).
 */
export function vulnSql(query: string, inputs: RaspInput[], tokens: () => Token[]): Vuln | null {
  const trimmed = query.trim();
  for (const inp of candidates(inputs)) {
    const v = inp.value;
    if (v === query || v.trim() === trimmed) continue;
    for (const idx of occurrences(query, v)) {
      const over = overlapping(tokens(), idx, v.length);
      if (!over.length || over.some(isComment)) continue;
      const end = idx + v.length;
      if (over.length === 1) {
        const t = over[0];
        if (t.kind === 'string' && idx > t.s && end <= t.e) return { rule: 'vuln.sql_concat', input: inp, position: 'string' };
        const whole = t.s === idx && t.e === end;
        if (whole && t.kind === 'number') return { rule: 'vuln.sql_concat', input: inp, position: 'number' };
        if (whole && t.kind === 'name') return { rule: 'vuln.sql_concat', input: inp, position: 'identifier' };
        if (whole && t.kind === 'word' && !SQL_KEYWORDS.has(t.text.toLowerCase())) return { rule: 'vuln.sql_concat', input: inp, position: 'identifier' };
        continue;
      }
      if (over[0].s === idx && over[over.length - 1].e === end) return { rule: 'vuln.sql_concat', input: inp, position: 'tokens' };
    }
  }
  return null;
}

// ---- Command ----------------------------------------------------------------

/**
 * vuln.cmd_shell: an input sits inside one word of a shell-interpreted
 * command (the attack check fires when it spans two or more tokens).
 */
export function vulnShell(command: string, inputs: RaspInput[], tokens: Token[]): Vuln | null {
  const trimmed = command.trim();
  for (const inp of candidates(inputs)) {
    const v = inp.value;
    if (v.trim() === trimmed) continue;
    for (const idx of occurrences(command, v)) {
      const over = overlapping(tokens, idx, v.length);
      if (over.length === 1 && over[0].kind === 'word') return { rule: 'vuln.cmd_shell', input: inp, position: 'word' };
    }
  }
  return null;
}

/**
 * vuln.cmd_arg: an argument (not the executable) of an argv spawn without a
 * shell equals or contains an input. The caller skips `sh -c <script>`
 * spawns, whose script is checked as shell text.
 */
export function vulnArgv(argv: string[], inputs: RaspInput[]): Vuln | null {
  for (const inp of candidates(inputs)) {
    for (let k = 1; k < argv.length; k++) {
      const a = argv[k];
      if (typeof a === 'string' && a.includes(inp.value)) return { rule: 'vuln.cmd_arg', input: inp, position: 'argument' };
    }
  }
  return null;
}

// ---- Path ----------------------------------------------------------------

/**
 * vuln.path_from_input: an input (normalized like the path) forms whole path
 * segments: it starts at the start of a segment and ends at the end of one,
 * or right before a `.` in it (`/data/<input>.json`).
 */
export function vulnPath(normalizedPath: string, inputs: RaspInput[], norm: (p: string) => string): Vuln | null {
  const np = normalizedPath;
  for (const inp of candidates(inputs)) {
    const ni = norm(inp.value);
    if (!ni || ni === '/') continue;
    for (const idx of occurrences(np, ni)) {
      const end = idx + ni.length;
      const startOk = idx === 0 || np[idx - 1] === '/' || ni.startsWith('/');
      const endOk = end === np.length || np[end] === '/' || np[end] === '.' || ni.endsWith('/');
      if (startOk && endOk) return { rule: 'vuln.path_from_input', input: inp, position: 'segment' };
    }
  }
  return null;
}

// ---- SSRF ----------------------------------------------------------------

/**
 * The `host[:port]` of a URL as written (lower-cased), and the offset just
 * past the host itself (after any userinfo), or null without an authority.
 */
function authorityOf(url: string, host: string): { authority: string; hostEnd: number } | null {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.exec(url);
  if (!m) return null;
  const rest = url.slice(m[0].length);
  const end = rest.search(/[/?#\\]/);
  const auth = end < 0 ? rest : rest.slice(0, end);
  const hostStart = m[0].length + auth.lastIndexOf('@') + 1;
  const bracket = url[hostStart] === '[' ? 2 : 0;
  return { authority: auth.slice(auth.lastIndexOf('@') + 1).toLowerCase(), hostEnd: hostStart + host.length + bracket };
}

/**
 * vuln.ssrf_host: the URL's host is an input (equal to the host or to
 * `host:port`), or an input is a prefix of the URL that covers its scheme
 * and host (a base URL or whole URL from the request). An input that merely
 * mentions the host somewhere in longer text does not count.
 */
export function vulnSsrf(url: string, raw: { scheme: string; host: string }, inputs: RaspInput[]): Vuln | null {
  const host = raw.host;
  const auth = host ? authorityOf(url, host) : null;
  const authority = auth?.authority ?? '';
  // The prefix must reach past the destination host itself, not a copy of it in the userinfo.
  const hostEnd = host ? (auth ? auth.hostEnd : url.length + 1) : url.indexOf(':') + 1;
  for (const inp of candidates(inputs)) {
    const v = inp.value.toLowerCase();
    if (host && (v === host || v === authority || v === `[${host}]`)) return { rule: 'vuln.ssrf_host', input: inp, position: 'host' };
    if (url.startsWith(inp.value) && inp.value.length >= hostEnd && (host || inp.value.length > hostEnd)) return { rule: 'vuln.ssrf_host', input: inp, position: 'url' };
  }
  return null;
}

// ---- Code, include, deserialization, XML ------------------------------------

/**
 * vuln.code_eval: an input sits inside a string literal of evaluated code,
 * or is a whole identifier or number in it (the attack check fires when it
 * spans two or more tokens or is the whole code). Never inside a comment.
 */
export function vulnCode(code: string, inputs: RaspInput[], tokens: () => Token[]): Vuln | null {
  for (const inp of candidates(inputs)) {
    const v = inp.value;
    if (v === code) continue;
    for (const idx of occurrences(code, v)) {
      const over = overlapping(tokens(), idx, v.length);
      if (over.length !== 1) continue;
      const t = over[0];
      const end = idx + v.length;
      if (t.kind === 'string' && idx > t.s && end <= t.e) return { rule: 'vuln.code_eval', input: inp, position: 'string' };
      if (t.s === idx && t.e === end && (t.kind === 'word' || t.kind === 'number')) return { rule: 'vuln.code_eval', input: inp, position: t.kind === 'word' ? 'identifier' : 'number' };
    }
  }
  return null;
}

/** vuln.include_from_input: a module specifier contains an input (the attack check covers equal and path-like inputs). */
export function vulnInclude(specifier: string, inputs: RaspInput[]): Vuln | null {
  for (const inp of candidates(inputs)) {
    if (inp.value !== specifier && specifier.includes(inp.value)) return { rule: 'vuln.include_from_input', input: inp, position: 'specifier' };
  }
  return null;
}

/**
 * vuln.deser_input / vuln.xml_external: the data handed to an unsafe
 * deserializer, or to an XML parser that resolves external entities, is
 * tainted (the caller decides with the contract's taintedData), at least
 * 3 characters long, by an input that qualifies.
 */
export function vulnData(rule: 'vuln.deser_input' | 'vuln.xml_external', data: string, inp: RaspInput | undefined): Vuln | null {
  if (!inp || inp.source !== 'request' || data.length < IAST_MIN_LENGTH || !qualifies(inp.value)) return null;
  return { rule, input: inp, position: 'data' };
}

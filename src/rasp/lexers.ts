/**
 * One-pass lexers used by the structural checks: SQL, shell and a generic
 * C-like lexer for code. No regex backtracking; every loop advances.
 */

export type Token = { s: number; e: number; kind: string; text: string };
export type SqlDialect = 'mysql' | 'postgres' | 'sqlite' | 'mssql' | 'oracle' | 'db2' | 'generic';

/** Every SQL dialect the lexer knows (README "SQL"). */
export const SQL_DIALECTS: readonly SqlDialect[] = ['mysql', 'postgres', 'sqlite', 'mssql', 'oracle', 'db2', 'generic'];

const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';
const isDigit = (c: string) => c >= '0' && c <= '9';
const isIdStart = (c: string) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
const isIdChar = (c: string) => isIdStart(c) || isDigit(c) || c === '$';
const isHex = (c: string) => isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

/**
 * SQL keywords that are not data: OpenRASP's anti-detect list (README
 * "SQL", rule 1). sqli.userinput ignores them; passive IAST never takes one
 * for an identifier from input.
 */
export const SQL_KEYWORDS: ReadonlySet<string> = new Set(
  'add all alter analyze and any as asc avg begin between by case create count delete desc do dumpfile else elseif end exists false file float flush follows from group having identified if in insert interval into join last like limit loop not null on or order procedure regexp return rlike select then true union update values xor'.split(
    ' ',
  ),
);

const SQL_OPS = ['->>', '<=', '>=', '<>', '!=', '||', '&&', '::', ':=', '->', '<<', '>>'];

/** Tokenises SQL per the contract's lexer. */
export function sqlTokens(q: string, dialect: SqlDialect = 'generic'): Token[] {
  const out: Token[] = [];
  const n = q.length;
  const hashComment = dialect === 'mysql' || dialect === 'generic';
  const bracketIdent = dialect === 'mssql' || dialect === 'generic';
  const dollarQuote = dialect === 'postgres' || dialect === 'generic';
  const oracle = dialect === 'oracle';
  const db2 = dialect === 'db2';
  // E'' (backslash escapes) is not a prefix in Oracle or DB2.
  const ePrefix = !oracle && !db2;
  // Oracle and DB2 identifiers may contain '#' after the first character.
  const idChar = oracle || db2 ? (c: string) => isIdChar(c) || c === '#' : isIdChar;
  let i = 0;
  const push = (s: number, e: number, kind: string) => out.push({ s, e, kind, text: q.slice(s, e) });

  // Reads a quoted run starting at i (q[i] is the quote); returns the end index.
  const quoted = (start: number, close: string, backslash: boolean): number => {
    let j = start + 1;
    while (j < n) {
      const c = q[j];
      if (backslash && c === '\\') {
        j += 2;
        continue;
      }
      if (c === close) {
        if (q[j + 1] === close) {
          j += 2;
          continue;
        }
        return j + 1;
      }
      j++;
    }
    return n;
  };
  // A name part: identifier or quoted identifier; returns end or -1.
  const namePart = (j: number): number => {
    const c = q[j];
    if (c !== undefined && isIdStart(c)) {
      let k = j + 1;
      while (k < n && idChar(q[k])) k++;
      return k;
    }
    if (c === '"' || c === '`') return quoted(j, c, false);
    if (c === '[' && bracketIdent) return quoted(j, ']', false);
    return -1;
  };
  // Oracle alternative quoting q'X…X' (also nq'…'), the quote at j; returns end or -1.
  // The delimiter X is one character (a code point, so possibly multibyte) other than whitespace.
  const altQuoted = (j: number): number => {
    const d = q[j + 1];
    if (d === undefined || isSpace(d)) return -1;
    const pair = d >= '\uD800' && d <= '\uDBFF' && (q[j + 2] ?? '') >= '\uDC00' && (q[j + 2] ?? '') <= '\uDFFF';
    const open = pair ? q.slice(j + 1, j + 3) : d;
    const close = open === '[' ? ']' : open === '{' ? '}' : open === '(' ? ')' : open === '<' ? '>' : open;
    const k = q.indexOf(close + "'", j + 1 + open.length);
    return k < 0 ? n : k + close.length + 1;
  };
  // A block comment starting at i; nests in db2, postgres and mssql.
  const nestedComments = dialect === 'db2' || dialect === 'postgres' || dialect === 'mssql';
  const blockComment = (i: number): number => {
    if (!nestedComments) {
      const k = q.indexOf('*/', i + 2);
      return k < 0 ? n : k + 2;
    }
    let depth = 1;
    let k = i + 2;
    while (k < n) {
      if (q[k] === '/' && q[k + 1] === '*') {
        depth++;
        k += 2;
      } else if (q[k] === '*' && q[k + 1] === '/') {
        k += 2;
        if (--depth === 0) return k;
      } else k++;
    }
    return n;
  };

  while (i < n) {
    const c = q[i];
    if (isSpace(c)) {
      i++;
      continue;
    }
    const start = i;
    // comments
    if (c === '-' && q[i + 1] === '-') {
      const k = q.indexOf('\n', i);
      i = k < 0 ? n : k;
      push(start, i, 'comment');
      continue;
    }
    if (c === '#' && hashComment) {
      const k = q.indexOf('\n', i);
      i = k < 0 ? n : k;
      push(start, i, 'comment');
      continue;
    }
    if (c === '/' && q[i + 1] === '*') {
      i = blockComment(i);
      push(start, i, q[start + 2] === '!' ? 'version_comment' : 'comment');
      continue;
    }
    // strings, with E'' / N'' prefixes
    if (c === "'") {
      i = quoted(i, "'", dialect === 'mysql');
      push(start, i, 'string');
      continue;
    }
    if (oracle) {
      // q'…' / nq'…' alternative quoting
      const p = c === 'N' || c === 'n' ? i + 1 : i;
      if ((q[p] === 'q' || q[p] === 'Q') && q[p + 1] === "'") {
        const k = altQuoted(p + 1);
        if (k > 0) {
          i = k;
          push(start, i, 'string');
          continue;
        }
      }
    }
    if (db2) {
      // X'' hex, G'' graphic, GX'' / UX'' / BX'' hex strings
      const x = (ch: string | undefined) => ch === 'X' || ch === 'x';
      const g = c === 'G' || c === 'g';
      const p = (g || c === 'U' || c === 'u' || c === 'B' || c === 'b') && x(q[i + 1]) ? i + 1 : i;
      if ((p > i || g || x(c)) && q[p + 1] === "'") {
        i = quoted(p + 1, "'", false);
        push(start, i, 'string');
        continue;
      }
    }
    if ((((c === 'E' || c === 'e') && ePrefix) || c === 'N' || c === 'n') && q[i + 1] === "'") {
      i = quoted(i + 1, "'", dialect === 'mysql' || c === 'E' || c === 'e');
      push(start, i, 'string');
      continue;
    }
    // dollar quotes and $n placeholders
    if (c === '$') {
      if (isDigit(q[i + 1] ?? '')) {
        let k = i + 1;
        while (k < n && isDigit(q[k])) k++;
        i = k;
        push(start, i, 'placeholder');
        continue;
      }
      if (dollarQuote) {
        let k = i + 1;
        while (k < n && (isIdStart(q[k]) || isDigit(q[k]))) k++;
        if (q[k] === '$') {
          const tag = q.slice(i, k + 1);
          const end = q.indexOf(tag, k + 1);
          i = end < 0 ? n : end + tag.length;
          push(start, i, 'string');
          continue;
        }
      }
    }
    // placeholders
    if (c === '?') {
      i++;
      push(start, i, 'placeholder');
      continue;
    }
    if ((c === ':' || c === '@') && isIdStart(q[i + 1] ?? '') && !(c === ':' && q[i - 1] === ':')) {
      let k = i + 1;
      while (k < n && idChar(q[k])) k++;
      i = k;
      push(start, i, 'placeholder');
      continue;
    }
    if (oracle && c === ':' && isDigit(q[i + 1] ?? '') && q[i - 1] !== ':') {
      // Oracle positional bind :1
      let k = i + 1;
      while (k < n && isDigit(q[k])) k++;
      i = k;
      push(start, i, 'placeholder');
      continue;
    }
    if (c === '@' && q[i + 1] === '@' && isIdStart(q[i + 2] ?? '')) {
      let k = i + 2;
      while (k < n && isIdChar(q[k])) k++;
      i = k;
      push(start, i, 'word');
      continue;
    }
    if (c === '%' && q[i + 1] === 's') {
      i += 2;
      push(start, i, 'placeholder');
      continue;
    }
    if (c === '%' && q[i + 1] === '(') {
      const k = q.indexOf(')', i + 2);
      if (k > 0 && q[k + 1] === 's') {
        i = k + 2;
        push(start, i, 'placeholder');
        continue;
      }
    }
    // numbers
    if (isDigit(c) || (c === '.' && isDigit(q[i + 1] ?? ''))) {
      let k = i;
      if (c === '0' && (q[i + 1] === 'x' || q[i + 1] === 'X')) {
        k = i + 2;
        while (k < n && isHex(q[k])) k++;
      } else {
        while (k < n && isDigit(q[k])) k++;
        if (q[k] === '.') {
          k++;
          while (k < n && isDigit(q[k])) k++;
        }
        if ((q[k] === 'e' || q[k] === 'E') && (isDigit(q[k + 1] ?? '') || ((q[k + 1] === '+' || q[k + 1] === '-') && isDigit(q[k + 2] ?? '')))) {
          k += 2;
          while (k < n && isDigit(q[k])) k++;
        }
      }
      i = k;
      push(start, i, 'number');
      continue;
    }
    // identifiers and qualified names (one token)
    const first = namePart(i);
    if (first > 0) {
      let k = first;
      while (q[k] === '.') {
        const next = namePart(k + 1);
        if (next < 0) break;
        k = next;
      }
      i = k;
      push(start, i, isIdStart(c) && k === first ? 'word' : 'name');
      continue;
    }
    // operators
    const op = SQL_OPS.find((o) => q.startsWith(o, i));
    i += op ? op.length : 1;
    push(start, i, 'op');
  }
  return out;
}

const SHELL_OPS = ['&&', '||', '>>', '<<', '$(', ';', '&', '|', '>', '<', '(', ')', '`', '\n'];

/** Shell tokens; `sq[i]` marks characters inside single quotes. */
export function shellTokens(cmd: string): { tokens: Token[]; inSingle: Uint8Array } {
  const out: Token[] = [];
  const inSingle = new Uint8Array(cmd.length);
  const n = cmd.length;
  let i = 0;
  let wordStart = -1;
  let dq = false;
  const endWord = (e: number) => {
    if (wordStart >= 0 && e > wordStart) out.push({ s: wordStart, e, kind: 'word', text: cmd.slice(wordStart, e) });
    wordStart = -1;
  };
  while (i < n) {
    const c = cmd[i];
    if (!dq) {
      if (c === ' ' || c === '\t') {
        endWord(i);
        i++;
        continue;
      }
      const op = SHELL_OPS.find((o) => cmd.startsWith(o, i));
      if (op) {
        endWord(i);
        out.push({ s: i, e: i + op.length, kind: 'op', text: op });
        i += op.length;
        continue;
      }
      if (wordStart < 0) wordStart = i;
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === "'") {
        const k = cmd.indexOf("'", i + 1);
        const end = k < 0 ? n : k + 1;
        inSingle.fill(1, i, end);
        i = end;
        continue;
      }
      if (c === '"') {
        dq = true;
        i++;
        continue;
      }
      i++;
      continue;
    }
    // inside double quotes
    if (c === '\\') {
      if (wordStart < 0) wordStart = i;
      i += 2;
      continue;
    }
    if (c === '"') {
      if (wordStart < 0) wordStart = i;
      dq = false;
      i++;
      continue;
    }
    if (c === '`' || (c === '$' && cmd[i + 1] === '(')) {
      endWord(i);
      const len = c === '`' ? 1 : 2;
      out.push({ s: i, e: i + len, kind: 'op', text: cmd.slice(i, i + len) });
      i += len;
      continue;
    }
    if (wordStart < 0) wordStart = i;
    i++;
  }
  endWord(n);
  return { tokens: out, inSingle };
}

/** A generic C-like lexer: identifiers, numbers, quoted strings, comments, punctuation. */
export function codeTokens(src: string): Token[] {
  const out: Token[] = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    if (isSpace(c)) {
      i++;
      continue;
    }
    const s = i;
    if (c === '/' && src[i + 1] === '/') {
      const k = src.indexOf('\n', i);
      i = k < 0 ? n : k;
      out.push({ s, e: i, kind: 'comment', text: src.slice(s, i) });
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const k = src.indexOf('*/', i + 2);
      i = k < 0 ? n : k + 2;
      out.push({ s, e: i, kind: 'comment', text: src.slice(s, i) });
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      let k = i + 1;
      while (k < n && src[k] !== c) k += src[k] === '\\' ? 2 : 1;
      i = Math.min(n, k + 1);
      out.push({ s, e: i, kind: 'string', text: src.slice(s, i) });
      continue;
    }
    if (isDigit(c)) {
      let k = i + 1;
      while (k < n && (isIdChar(src[k]) || src[k] === '.')) k++;
      i = k;
      out.push({ s, e: i, kind: 'number', text: src.slice(s, i) });
      continue;
    }
    if (isIdStart(c) || c === '$' || c.charCodeAt(0) > 127) {
      let k = i + 1;
      while (k < n && (isIdChar(src[k]) || src.charCodeAt(k) > 127)) k++;
      i = k;
      out.push({ s, e: i, kind: 'word', text: src.slice(s, i) });
      continue;
    }
    i++;
    out.push({ s, e: i, kind: 'op', text: c });
  }
  return out;
}

/** Tokens overlapping [idx, idx+len). */
export function overlapping(tokens: Token[], idx: number, len: number): Token[] {
  const end = idx + len;
  const out: Token[] = [];
  for (const t of tokens) {
    if (t.s >= end) break;
    if (t.e > idx) out.push(t);
  }
  return out;
}

/** Start offsets of `needle` in `hay`, at most `max`. */
export function occurrences(hay: string, needle: string, max = 8): number[] {
  const out: number[] = [];
  if (!needle) return out;
  let from = 0;
  while (out.length < max) {
    const i = hay.indexOf(needle, from);
    if (i < 0) break;
    out.push(i);
    from = i + 1;
  }
  return out;
}

/** Structural template-source check; data arguments are deliberately never inspected. */
import { codeTokens, occurrences, overlapping, type Token } from './lexers';
import type { Finding, RaspInput } from './types';

/** How a pair's region ends: first close, first close outside quotes, or matching bracket. */
export type CloseMode = 'first' | 'quoted' | 'bracket';

/** One engine's syntax (README "Template source"). Order inside each list matters: the first match wins. */
export interface EngineSyntax {
  pairs: [string, string, CloseMode][];
  /** Comments and raw/verbatim blocks: literal text to the close. A space matches any run of whitespace and `-`, `+`, `~`. */
  literal: [string, string][];
  /** Prefix + identifier start, ending at the first close outside quotes (`<#if x>`, `<%def>`). */
  tags: [string, string][];
  /** Prefix + identifier (dots allowed), optionally followed by `(args)`; not after a word character. */
  directives: string[];
  /** At line start after spaces/tabs: a comment line, or a code line (a doubled prefix stays literal). */
  lineComment: string[];
  lineCode: string[];
  /** After whitespace: prefix + attribute name + `=` + quoted value; the value is a region. */
  attrs: string[];
  /** An opener right after this character (itself not escaped) is literal. */
  escape: string;
  /** A pair opener followed by whitespace is literal (Smarty auto_literal). */
  spaceLiteral: boolean;
  /** Pug line code, buffered expressions and tag attributes. */
  pug: boolean;
}

// SHIELD: byte-for-byte the contract table sdk/rasp/rules/template-engines.json (a test compares).
const BASE: EngineSyntax = {
  pairs: [], literal: [], tags: [], directives: [], lineComment: [], lineCode: [], attrs: [],
  escape: '', spaceLiteral: false, pug: false,
};
const syntax = (s: Partial<EngineSyntax>): EngineSyntax => ({ ...BASE, ...s });
const JINJA: [string, string, CloseMode][] = [['{{', '}}', 'quoted'], ['{%', '%}', 'quoted']];

export const TEMPLATE_ENGINES = {
  handlebars: syntax({ pairs: [['{{{', '}}}', 'quoted'], ['{{', '}}', 'quoted']], literal: [['{{!--', '--}}'], ['{{!', '}}']], escape: '\\' }),
  ejs: syntax({ pairs: [['<%', '%>', 'first']], literal: [['<%#', '%>']] }),
  lodash: syntax({ pairs: [['<%', '%>', 'first'], ['${', '}', 'first']], literal: [['<%#', '%>']] }),
  pug: syntax({ pairs: [['#{', '}', 'bracket'], ['!{', '}', 'bracket']], pug: true }),
  nunjucks: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% raw %}', '{% endraw %}']] }),
  jinja2: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% raw %}', '{% endraw %}']] }),
  minijinja: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% raw %}', '{% endraw %}']] }),
  tera: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% raw %}', '{% endraw %}']] }),
  twig: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% verbatim %}', '{% endverbatim %}']] }),
  pebble: syntax({ pairs: JINJA, literal: [['{#', '#}'], ['{% verbatim %}', '{% endverbatim %}']] }),
  django: syntax({
    pairs: [['{{', '}}', 'first'], ['{%', '%}', 'first']],
    literal: [['{#', '#}'], ['{% comment %}', '{% endcomment %}'], ['{% verbatim %}', '{% endverbatim %}']],
  }),
  liquid: syntax({ pairs: JINJA, literal: [['{% comment %}', '{% endcomment %}'], ['{% raw %}', '{% endraw %}']] }),
  scriban: syntax({ pairs: [['{{', '}}', 'quoted']], literal: [['{%{', '}%}']] }),
  gotemplate: syntax({ pairs: [['{{', '}}', 'quoted']], literal: [['{{/*', '*/'], ['{{- /*', '*/']] }),
  mako: syntax({
    pairs: [['${', '}', 'bracket'], ['<%', '%>', 'first']], literal: [['<%doc>', '</%doc>'], ['<%text>', '</%text>']],
    tags: [['<%', '>'], ['</%', '>']], lineComment: ['##'], lineCode: ['%'],
  }),
  freemarker: syntax({
    pairs: [['${', '}', 'bracket'], ['#{', '}', 'bracket']], literal: [['<#--', '-->'], ['<#noparse>', '</#noparse>']],
    tags: [['<#', '>'], ['</#', '>'], ['<@', '>'], ['</@', '>']],
  }),
  velocity: syntax({
    pairs: [['$!{', '}', 'bracket'], ['${', '}', 'bracket']], literal: [['#*', '*#'], ['##', '\n'], ['#[[', ']]#']],
    directives: ['$!', '$', '#'], escape: '\\',
  }),
  thymeleaf: syntax({
    pairs: [['[[', ']]', 'quoted'], ['[(', ')]', 'quoted']],
    literal: [['<!--/*', '*/-->']], attrs: ['th:', 'data-th-'],
  }),
  smarty: syntax({ pairs: [['{', '}', 'quoted']], literal: [['{*', '*}'], ['{literal}', '{/literal}']], spaceLiteral: true }),
  blade: syntax({
    pairs: [['{!!', '!!}', 'first'], ['{{', '}}', 'first'], ['@php', '@endphp', 'first']],
    literal: [['{{--', '--}}'], ['@verbatim', '@endverbatim']], directives: ['@'], escape: '@',
  }),
} satisfies Record<string, EngineSyntax>;

export type TemplateEngine = keyof typeof TEMPLATE_ENGINES;

const isSpace = (c: string | undefined) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';
const isIdStart = (c: string | undefined) => !!c && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_');
const isWord = (c: string | undefined) => isIdStart(c) || (!!c && c >= '0' && c <= '9');
const isAttrChar = (c: string | undefined) => isWord(c) || c === ':' || c === '-';

/** Index just past a quoted run starting at `i` (source[i] is the quote). */
function skipQuoted(source: string, i: number): number {
  const quote = source[i];
  let k = i + 1;
  while (k < source.length && source[k] !== quote) k += source[k] === '\\' ? 2 : 1;
  return Math.min(source.length, k + 1);
}

/** First `close` outside quoted strings (engines that lex strings inside an expression). */
function quotedClose(source: string, from: number, close: string): number {
  for (let i = from; i < source.length;) {
    const c = source[i];
    if (c === '"' || c === "'") { i = skipQuoted(source, i); continue; }
    if (source.startsWith(close, i)) return i;
    i++;
  }
  return -1;
}

/** The bracket closing depth zero, skipping quoted strings and nested brackets. */
function bracketClose(source: string, from: number): number {
  let depth = 0;
  for (let i = from; i < source.length;) {
    const c = source[i];
    if (c === '"' || c === "'" || c === '`') { i = skipQuoted(source, i); continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (!depth) return i; depth--; }
    i++;
  }
  return -1;
}

/** End of literal-block `pattern` matched at `i`, or -1; a space matches any run of whitespace, `-`, `+` and `~`. */
function literalAt(source: string, i: number, pattern: string): number {
  let k = i;
  for (const c of pattern) {
    if (c === ' ') {
      while (k < source.length && (isSpace(source[k]) || source[k] === '-' || source[k] === '+' || source[k] === '~')) k++;
    } else if (source[k] === c) k++;
    else return -1;
  }
  return k;
}

/** Code tokens of a region body. Template expressions have no `//` or `/*` comments: both are operators. */
function regionCode(body: string): Token[] {
  const out: Token[] = [];
  for (let pos = 0; pos < body.length;) {
    let resume = -1;
    for (const token of codeTokens(body.slice(pos))) {
      const s = pos + token.s;
      if (token.kind === 'comment') {
        out.push({ s, e: s + 1, kind: 'op', text: '/' }, { s: s + 1, e: s + 2, kind: 'op', text: body[s + 1] });
        resume = s + 2;
        break;
      }
      out.push({ ...token, s, e: pos + token.e });
    }
    if (resume < 0) break;
    pos = resume;
  }
  return out;
}

/** A dotted property path (`user.name`) is one reference, like a single variable name. */
function mergePaths(tokens: Token[]): Token[] {
  const out: Token[] = [];
  for (let i = 0; i < tokens.length; i++) {
    let token = tokens[i];
    while (token.kind === 'word' && tokens[i + 1]?.text === '.' && tokens[i + 1].s === token.e
      && tokens[i + 2]?.kind === 'word' && tokens[i + 2].s === tokens[i + 1].e) {
      token = { ...token, e: tokens[i + 2].e, text: `${token.text}.${tokens[i + 2].text}` };
      i += 2;
    }
    out.push(token);
  }
  return out;
}

/** Template tokens: boundary delimiters plus code tokens of each expression region; literal text yields nothing. */
export function templateTokens(source: string, engine: TemplateEngine): Token[] {
  const s = TEMPLATE_ENGINES[engine];
  const tokens: Token[] = [];
  const region = (start: number, open: number, end: number, close: number) => {
    tokens.push({ s: start, e: start + open, kind: 'delimiter', text: '' });
    for (const token of mergePaths(regionCode(source.slice(start + open, end)))) {
      tokens.push({ ...token, s: token.s + start + open, e: token.e + start + open });
    }
    if (close) tokens.push({ s: end, e: end + close, kind: 'delimiter', text: '' });
  };
  const lineEndAt = (i: number) => { const end = source.indexOf('\n', i); return end < 0 ? source.length : end; };
  scan: for (let i = 0; i < source.length;) {
    const lineStart = i === 0 || source[i - 1] === '\n';
    if (s.pug && lineStart) {
      const lineEnd = lineEndAt(i);
      const line = source.slice(i, lineEnd);
      // Pug's line code and buffered expressions; ordinary tag/text lines stay literal.
      const marker = /^\s*(?:-\s*|(?:[\w.#-]+\s*)?!?=\s*)/.exec(line);
      if (marker) { region(i, marker[0].length, lineEnd, 0); i = lineEnd; continue; }
      // Tag or mixin attributes are JavaScript expressions: `a(href=url)`, `+card(item)`.
      const tag = /^\s*\+?[\w.#:-]+/.exec(line);
      if (tag && source[i + tag[0].length] === '(') {
        const open = i + tag[0].length;
        const close = bracketClose(source, open + 1);
        if (close >= 0) {
          region(open, 1, close, 1);
          i = close + 1;
          const restEnd = lineEndAt(i);
          const rest = /^!?=\s*/.exec(source.slice(i, restEnd));
          if (rest) { region(i, rest[0].length, restEnd, 0); i = restEnd; }
          continue;
        }
      }
    }
    if (lineStart && (s.lineComment.length || s.lineCode.length)) {
      let j = i;
      while (source[j] === ' ' || source[j] === '\t') j++;
      const lineEnd = lineEndAt(i);
      if (s.lineComment.some(p => source.startsWith(p, j))) { i = lineEnd; continue; }
      for (const p of s.lineCode) {
        if (source.startsWith(p, j) && !source.startsWith(p, j + p.length)) {
          region(i, j + p.length - i, lineEnd, 0);
          i = lineEnd;
          continue scan;
        }
      }
    }
    // First match wins: literal blocks, tags, attributes, pairs, directives.
    const literal = s.literal.find(([open]) => literalAt(source, i, open) >= 0);
    const tag = literal ? undefined : s.tags.find(([p]) => source.startsWith(p, i) && isIdStart(source[i + p.length]));
    let attr: string | undefined;
    let quote = -1;
    if (!literal && !tag && (i === 0 || isSpace(source[i - 1]))) {
      for (const p of s.attrs) {
        if (!source.startsWith(p, i)) continue;
        let k = i + p.length;
        while (isAttrChar(source[k])) k++;
        if (k === i + p.length) continue;
        while (isSpace(source[k])) k++;
        if (source[k] !== '=') continue;
        k++;
        while (isSpace(source[k])) k++;
        if (source[k] === '"' || source[k] === "'") { attr = p; quote = k; break; }
      }
    }
    const pair = literal || tag || attr ? undefined : s.pairs.find(([open]) => source.startsWith(open, i));
    const directive = literal || tag || attr || pair ? undefined
      : s.directives.find(p => source.startsWith(p, i) && isIdStart(source[i + p.length]) && !isWord(source[i - 1]));
    const opener = tag?.[0] ?? attr ?? pair?.[0] ?? directive;
    if (!literal && opener === undefined) { i++; continue; }
    const from = literal ? literalAt(source, i, literal[0]) : i + opener!.length;
    // An escaped opener (`\{{`, `@{{`) is literal; a doubled escape (`\\{{`) leaves it live.
    if (s.escape && source[i - 1] === s.escape && source[i - 2] !== s.escape) { i = from; continue; }
    if (literal) {
      i = source.length;
      for (let j = from; j < source.length; j++) {
        const end = literalAt(source, j, literal[1]);
        if (end >= 0) { i = end; break; }
      }
      continue;
    }
    if (tag) {
      const end = quotedClose(source, from, tag[1]);
      if (end < 0) { i = from; continue; }
      region(i, tag[0].length, end, tag[1].length);
      i = end + tag[1].length;
      continue;
    }
    if (attr) {
      const end = source.indexOf(source[quote], quote + 1);
      if (end < 0) { i = from; continue; }
      region(quote, 1, end, 1);
      i = end + 1;
      continue;
    }
    if (directive) {
      tokens.push({ s: i, e: from, kind: 'delimiter', text: '' });
      let k = from;
      while (isWord(source[k]) || source[k] === '.') k++;
      while (source[k - 1] === '.') k--;
      tokens.push({ s: from, e: k, kind: 'word', text: source.slice(from, k) });
      i = k;
      if (source[k] === '(') {
        const close = bracketClose(source, k + 1);
        if (close >= 0) { region(k, 1, close, 1); i = close + 1; }
      }
      continue;
    }
    const [open, closeText, mode] = pair!;
    if (s.spaceLiteral && isSpace(source[from])) { i = from; continue; }
    // Closing delimiters inside quotes end an expression only where the engine itself ignores quotes.
    const end = mode === 'bracket' ? bracketClose(source, from)
      : mode === 'quoted' ? quotedClose(source, from, closeText) : source.indexOf(closeText, from);
    if (end < 0) { i = from; continue; }
    region(i, open.length, end, closeText.length);
    i = end + closeText.length;
  }
  return tokens;
}

/** Input must introduce a template boundary or span multiple expression tokens. */
export function detectTemplate(source: string, inputs: RaspInput[], engine: TemplateEngine): Finding | null {
  if (typeof source !== 'string' || !source || !Object.prototype.hasOwnProperty.call(TEMPLATE_ENGINES, engine)) return null;
  let tokens: Token[] | undefined;
  for (const input of inputs) {
    if (input.value.length < 3) continue;
    for (const idx of occurrences(source, input.value)) {
      tokens ??= templateTokens(source, engine);
      const span = overlapping(tokens, idx, input.value.length);
      if (span.some(token => token.kind === 'delimiter') || span.length >= 2) {
        return { attack: 'code_injection', rule: 'code.template_injection', input };
      }
    }
  }
  return null;
}

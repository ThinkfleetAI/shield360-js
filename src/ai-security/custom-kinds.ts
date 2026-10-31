/**
 * The organisation's own kinds of sensitive data (keywords and format masks,
 * never free-form regular expressions), matched in model output.
 *
 * A copy of the matching half of the reference,
 * src/client/src/lib/platform/collector/custom-data-kinds.ts; the other
 * copies are cli/internal/coding/guard/custom.go and
 * extension/src/shared/custom-kinds.ts. Same definition, same matches: masks
 * are `#` digit, `@` letter, `*` letter or digit, `\x` the character x, and
 * anything else that character without regard to case. A match may not start
 * or end inside a longer word. Linear in the text: no quantifier over a group.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_custom_kinds.py
 */

import type { CustomDataKindDef } from './policy';

type MaskToken = { kind: 'digit' | 'letter' | 'alnum' } | { kind: 'literal'; char: string };

function parseMask(mask: string): MaskToken[] | null {
  const chars = Array.from(mask);
  const tokens: MaskToken[] = [];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '\\') {
      const next = chars[++i];
      if (next === undefined) return null;
      tokens.push({ kind: 'literal', char: next });
    } else if (c === '#') tokens.push({ kind: 'digit' });
    else if (c === '@') tokens.push({ kind: 'letter' });
    else if (c === '*') tokens.push({ kind: 'alnum' });
    else tokens.push({ kind: 'literal', char: c });
  }
  const placeholders = tokens.filter((t) => t.kind !== 'literal').length;
  if (tokens.length < 3 || tokens.length > 64 || placeholders < 3) return null;
  if (placeholders === tokens.length && placeholders < 6) return null;
  return tokens;
}

const WORD = /[\p{L}\p{N}_]/u;
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

function maskSource(tokens: MaskToken[]): string {
  return tokens
    .map((t) => (t.kind === 'literal' ? escapeRegExp(t.char) : t.kind === 'digit' ? '[0-9]' : t.kind === 'letter' ? '[A-Za-z]' : '[A-Za-z0-9]'))
    .join('');
}

const charBefore = (text: string, index: number) =>
  index > 0 ? String.fromCodePoint(text.codePointAt(index - 1 - (/[\udc00-\udfff]/.test(text[index - 1]) && index > 1 ? 1 : 0))!) : '';
const charAt = (text: string, index: number) => (index < text.length ? String.fromCodePoint(text.codePointAt(index)!) : '');

function onBoundaries(text: string, start: number, end: number): boolean {
  if (WORD.test(charAt(text, start)) && WORD.test(charBefore(text, start))) return false;
  if (WORD.test(charBefore(text, end)) && WORD.test(charAt(text, end))) return false;
  return true;
}

const patterns = new WeakMap<CustomDataKindDef, RegExp>();

function patternOf(kind: CustomDataKindDef): RegExp {
  let re = patterns.get(kind);
  if (re) return re;
  const parts =
    kind.match.type === 'keywords'
      ? [...kind.match.keywords].sort((a, b) => b.length - a.length).map((k) => escapeRegExp(k.trim().replace(/\s+/g, ' ')).replace(/ /g, '\\s+'))
      : kind.match.masks.map((m) => parseMask(m)).filter((t): t is MaskToken[] => !!t).map(maskSource);
  re = new RegExp(parts.length ? parts.join('|') : '(?!)', 'giu');
  patterns.set(kind, re);
  return re;
}

export type CustomKindFinding = { id: string; name: string; start: number; end: number };

/** Every custom kind found in text, by span (UTF-16 offsets). */
export function findCustomKinds(text: string, kinds: readonly CustomDataKindDef[]): CustomKindFinding[] {
  const out: CustomKindFinding[] = [];
  if (!text) return out;
  for (const kind of kinds) {
    const re = patternOf(kind);
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const start = m.index;
      const end = start + m[0].length;
      if (onBoundaries(text, start, end)) out.push({ id: kind.id, name: kind.name, start, end });
      else re.lastIndex = start + 1;
    }
  }
  return out.sort((a, b) => a.start - b.start || b.end - a.end);
}

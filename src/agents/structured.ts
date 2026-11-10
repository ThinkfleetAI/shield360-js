/**
 * The part of Structured Field Values (RFC 8941) that HTTP Message Signatures
 * (RFC 9421) needs: parsing a Dictionary whose members are Items or Inner
 * Lists with Parameters, and serialising an Inner List and an Item back, so a
 * signature base can be rebuilt byte for byte. Decimals are parsed but never
 * produced by Web Bot Auth. Anything that is not valid RFC 8941 throws.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_structured.py
 */

export type Bare = number | string | boolean | Token | Uint8Array;
export class Token {
  constructor(readonly value: string) {}
}
export type Params = Map<string, Bare>;
export type Item = { kind: 'item'; value: Bare; params: Params };
export type InnerList = { kind: 'list'; items: Item[]; params: Params };
export type Member = Item | InnerList;

export class StructuredError extends Error {}

class Reader {
  i = 0;
  constructor(readonly s: string) {}
  get done(): boolean {
    return this.i >= this.s.length;
  }
  peek(): string {
    return this.s[this.i] ?? '';
  }
  fail(): never {
    throw new StructuredError(`invalid structured field at ${this.i}`);
  }
  skipSp(): void {
    while (this.peek() === ' ') this.i++;
  }
  skipOws(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.i++;
  }
}

const KEY_FIRST = /[a-z*]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;
const TOKEN_FIRST = /[A-Za-z*]/;
const TOKEN_CHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/;
const BASE64_CHAR = /[A-Za-z0-9+/=]/;

function parseKey(r: Reader): string {
  if (!KEY_FIRST.test(r.peek())) r.fail();
  const start = r.i;
  while (!r.done && KEY_CHAR.test(r.peek())) r.i++;
  return r.s.slice(start, r.i);
}

function parseNumber(r: Reader): number {
  const start = r.i;
  if (r.peek() === '-') r.i++;
  if (!/[0-9]/.test(r.peek())) r.fail();
  let decimal = false;
  while (!r.done) {
    const c = r.peek();
    if (/[0-9]/.test(c)) r.i++;
    else if (c === '.' && !decimal) {
      decimal = true;
      r.i++;
    } else break;
  }
  const text = r.s.slice(start, r.i);
  const digits = text.replace('-', '');
  if (!decimal && digits.length > 15) r.fail();
  if (decimal) {
    const [whole, frac] = digits.split('.');
    if (whole.length > 12 || !frac || frac.length > 3) r.fail();
  }
  return Number(text);
}

function parseString(r: Reader): string {
  r.i++; // opening quote
  let out = '';
  for (;;) {
    if (r.done) r.fail();
    const c = r.s[r.i++];
    if (c === '\\') {
      const next = r.s[r.i++];
      if (next !== '"' && next !== '\\') r.fail();
      out += next;
    } else if (c === '"') return out;
    else {
      const code = c.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) r.fail();
      out += c;
    }
  }
}

function parseToken(r: Reader): Token {
  const start = r.i;
  r.i++;
  while (!r.done && TOKEN_CHAR.test(r.peek())) r.i++;
  return new Token(r.s.slice(start, r.i));
}

function parseBytes(r: Reader): Uint8Array {
  r.i++;
  const start = r.i;
  while (!r.done && r.peek() !== ':') {
    if (!BASE64_CHAR.test(r.peek())) r.fail();
    r.i++;
  }
  if (r.done) r.fail();
  const b64 = r.s.slice(start, r.i);
  r.i++;
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function parseBare(r: Reader): Bare {
  const c = r.peek();
  if (c === '-' || /[0-9]/.test(c)) return parseNumber(r);
  if (c === '"') return parseString(r);
  if (c === ':') return parseBytes(r);
  if (c === '?') {
    r.i++;
    const b = r.s[r.i++];
    if (b === '1') return true;
    if (b === '0') return false;
    r.fail();
  }
  if (TOKEN_FIRST.test(c)) return parseToken(r);
  return r.fail();
}

function parseParams(r: Reader): Params {
  const params: Params = new Map();
  while (r.peek() === ';') {
    r.i++;
    r.skipSp();
    const key = parseKey(r);
    let value: Bare = true;
    if (r.peek() === '=') {
      r.i++;
      value = parseBare(r);
    }
    params.set(key, value);
  }
  return params;
}

function parseItem(r: Reader): Item {
  const value = parseBare(r);
  return { kind: 'item', value, params: parseParams(r) };
}

function parseInnerList(r: Reader): InnerList {
  r.i++; // (
  const items: Item[] = [];
  for (;;) {
    r.skipSp();
    if (r.peek() === ')') {
      r.i++;
      return { kind: 'list', items, params: parseParams(r) };
    }
    items.push(parseItem(r));
    const c = r.peek();
    if (c !== ' ' && c !== ')') r.fail();
  }
}

function parseMember(r: Reader): Member {
  return r.peek() === '(' ? parseInnerList(r) : parseItem(r);
}

/** Parses a Dictionary field value (several field lines joined with ", "). Later duplicates win. */
export function parseDictionary(value: string): Map<string, Member> {
  const r = new Reader(value);
  const dict = new Map<string, Member>();
  r.skipSp();
  if (r.done) return dict;
  for (;;) {
    const key = parseKey(r);
    let member: Member;
    if (r.peek() === '=') {
      r.i++;
      member = parseMember(r);
    } else member = { kind: 'item', value: true, params: parseParams(r) };
    dict.set(key, member);
    r.skipOws();
    if (r.done) return dict;
    if (r.peek() !== ',') r.fail();
    r.i++;
    r.skipOws();
    if (r.done) r.fail();
  }
}

/** Parses an Item field value. */
export function parseItemField(value: string): Item {
  const r = new Reader(value);
  r.skipSp();
  const item = parseItem(r);
  r.skipSp();
  if (!r.done) r.fail();
  return item;
}

function serializeBare(v: Bare): string {
  if (typeof v === 'boolean') return v ? '?1' : '?0';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new StructuredError('number');
    return Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
  }
  if (typeof v === 'string') {
    if (/[^\x20-\x7e]/.test(v)) throw new StructuredError('string');
    return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  if (v instanceof Token) return v.value;
  return `:${Buffer.from(v).toString('base64')}:`;
}

export function serializeParams(params: Params): string {
  let out = '';
  for (const [k, v] of params) out += v === true ? `;${k}` : `;${k}=${serializeBare(v)}`;
  return out;
}

export function serializeItem(item: Item): string {
  return serializeBare(item.value) + serializeParams(item.params);
}

export function serializeInnerList(list: InnerList): string {
  return `(${list.items.map(serializeItem).join(' ')})${serializeParams(list.params)}`;
}

export function serializeMember(member: Member): string {
  return member.kind === 'list' ? serializeInnerList(member) : serializeItem(member);
}

/**
 * Input normalisation: percent-decoded forms, JSON flattening and model-output
 * fragments (README "Sources of untrusted input" and "Implementation notes").
 */
import type { RaspInput } from './types';

export const MAX_INPUTS = 256;
export const MAX_VALUE = 4096;
export const MAX_FRAGMENTS = 32;
export const MAX_RAW_BODY = 8 * 1024;

const HEX = /^[0-9a-fA-F]{2}$/;

/** Lenient percent decoding: %XX to bytes, other % kept, UTF-8 with U+FFFD. */
export function percentDecode(s: string): string {
  if (!s.includes('%')) return s;
  const bytes: number[] = [];
  const enc = Buffer.from(s, 'utf8');
  for (let i = 0; i < enc.length; i++) {
    if (enc[i] === 0x25 && i + 2 < enc.length) {
      const h = String.fromCharCode(enc[i + 1], enc[i + 2]);
      if (HEX.test(h)) {
        bytes.push(parseInt(h, 16));
        i += 2;
        continue;
      }
    }
    bytes.push(enc[i]);
  }
  return Buffer.from(bytes).toString('utf8');
}

/** Adds an input, its decoded and double-decoded forms; caps count and length. */
export function addInput(list: RaspInput[], value: unknown, key: string, source: RaspInput['source'] = 'request'): void {
  if (typeof value !== 'string' || value === '' || list.length >= MAX_INPUTS) return;
  const v = value.length > MAX_VALUE ? value.slice(0, MAX_VALUE) : value;
  list.push({ value: v, key, source });
  if (source !== 'request' || !v.includes('%')) return;
  const once = percentDecode(v);
  if (once !== v && list.length < MAX_INPUTS) {
    list.push({ value: once, key, source });
    const twice = percentDecode(once);
    if (twice !== once && list.length < MAX_INPUTS) list.push({ value: twice, key, source });
  }
}

/** Flattens string leaves of a parsed body (`body.a.b`, arrays by index). */
export function flatten(list: RaspInput[], value: unknown, key: string, depth = 0): void {
  if (list.length >= MAX_INPUTS || depth > 16 || value == null) return;
  if (typeof value === 'string') return addInput(list, value, key);
  if (typeof value === 'number' || typeof value === 'boolean') return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => flatten(list, v, `${key}.${i}`, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    if (Buffer.isBuffer(value)) return;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) flatten(list, v, `${key}.${k}`, depth + 1);
  }
}

/** Splits model text into fragments: fenced code blocks, then lines. */
export function modelFragments(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (f: string) => {
    const t = f.trim();
    if (!t || seen.has(t) || out.length >= MAX_FRAGMENTS) return;
    seen.add(t);
    out.push(t.length > MAX_VALUE ? t.slice(0, MAX_VALUE) : t);
  };
  const lines = text.split('\n');
  let block: string[] | null = null;
  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      if (block) {
        push(block.join('\n'));
        block = null;
      } else block = [];
      continue;
    }
    if (block) block.push(line);
  }
  if (block) push(block.join('\n'));
  for (const line of lines) if (!line.trim().startsWith('```')) push(line);
  return out;
}

/** Adds model text as model_output fragments. */
export function addModelOutput(list: RaspInput[], text: string, key = 'model.completion'): void {
  for (const f of modelFragments(text)) {
    if (list.length >= MAX_INPUTS) return;
    list.push({ value: f, key, source: 'model_output' });
  }
}

/** Adds tool-call argument string leaves as model_output (`model.tool.<path>`). */
export function addToolArguments(list: RaspInput[], args: unknown, path = 'model.tool'): void {
  if (typeof args === 'string') {
    try {
      args = JSON.parse(args);
    } catch {
      return addModelOutput(list, args as string, path);
    }
  }
  const tmp: RaspInput[] = [];
  flatten(tmp, args, path);
  for (const i of tmp) if (list.length < MAX_INPUTS) list.push({ value: i.value, key: i.key, source: 'model_output' });
}

/** Parses a Cookie header into name/value pairs. */
export function parseCookies(header: string | undefined): [string, string][] {
  if (!header) return [];
  const out: [string, string][] = [];
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    out.push([part.slice(0, i).trim(), part.slice(i + 1).trim()]);
  }
  return out;
}

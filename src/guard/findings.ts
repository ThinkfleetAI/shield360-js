/**
 * What a reviewer may see of a sensitive value a guard found: its kind, a
 * token (`[api_key:fp_3f9c2a1b]`, see token()) and a
 * fingerprint that is the same every time the same value turns up, in this app
 * or anywhere else in the organisation. The value itself is never kept or
 * reported.
 *
 * The fingerprint is an HMAC keyed with the organisation's secret, which
 * Shield360 hands to apps with an API key. Unkeyed it could be reversed (there
 * are only a billion SSNs), so without a key none is made.
 *
 * Must stay in sync with: sdk/python/src/shield360/guard/_findings.py and
 * cli/internal/coding/guard/findings.go
 */

import { createHmac } from 'crypto';

export interface Finding {
  kind: string;
  masked: string;
  fingerprint?: string;
}

export const MAX_FINDINGS = 10;

let key: string | null = null;

// Values of findings made before the key arrived, kept in this process only —
// never serialised, gone with the finding — so they can be fingerprinted when
// reported. The app already holds the text they came from.
const awaitingKey = new WeakMap<Finding, { label: string; value: string }>();

/** Sets (or clears) the organisation's fingerprint key. */
export function setFingerprintKey(value: string | null): void {
  key = value || null;
}

// The CLI's kind for each SDK label, so the same value fingerprints the same
// whether a coding agent or an app stopped it.
const CANONICAL: Record<string, string> = {
  'credit-card': 'payment_card',
  'env-secret': 'password',
  'private-key': 'private_key',
  'connection-string': 'connection_string',
  'aws-access-key': 'cloud_credential',
  'openai-api-key': 'api_key',
  'anthropic-api-key': 'api_key',
  'github-token': 'api_key',
  'github-fine-grained': 'api_key',
  'stripe-key': 'api_key',
  'slack-token': 'api_key',
  'gcp-api-key': 'api_key',
};

export const canonicalKind = (label: string) => CANONICAL[label] ?? label;

const digits = (v: string) => v.replace(/\D/g, '');

function assignmentValue(v: string): string {
  const i = v.search(/[:=]/);
  return i < 0 ? v : v.slice(i + 1).replace(/^[\s"']+|[\s"']+$/g, '');
}

function normalise(kind: string, value: string): string {
  if (kind === 'ssn' || kind === 'payment_card' || kind === 'phone-us') return digits(value);
  if (kind === 'password') return assignmentValue(value);
  return value.trim();
}

export function fingerprint(label: string, value: string): string {
  if (!key) return '';
  const kind = canonicalKind(label);
  return createHmac('sha256', key).update(`${kind}:${normalise(kind, value)}`).digest('hex').slice(0, 16);
}

/** Hex characters of the fingerprint a token shows. */
export const TOKEN_PRINT_LENGTH = 8;

/**
 * What is kept of a sensitive value: its kind and, when the organisation's key
 * is known, the start of its keyed fingerprint — `[api_key:fp_3f9c2a1b]`, or
 * `[api_key]` without a key. No character of the value is part of it: a key's
 * prefix and last four or a card's last four help an attacker narrow a guess.
 * Byte-compatible with guard-core's token() and the Go guard's Token().
 */
export function token(kind: string, fp = ''): string {
  return fp.length >= TOKEN_PRINT_LENGTH && /^[0-9a-f]+$/.test(fp) ? `[${kind}:fp_${fp.slice(0, TOKEN_PRINT_LENGTH)}]` : `[${kind}]`;
}

/** The token for a value under the current key; never any character of it. */
export function mask(label: string, value: string): string {
  return token(canonicalKind(label), fingerprint(label, value));
}

export function makeFinding(label: string, value: string): Finding {
  const fp = fingerprint(label, value);
  const f: Finding = { kind: label, masked: token(canonicalKind(label), fp) };
  if (fp) f.fingerprint = fp;
  else awaitingKey.set(f, { label, value });
  return f;
}

/** Fingerprints a finding made before the key arrived, now that it has. */
export function completeFinding(f: Finding): Finding {
  if (f.fingerprint) return f;
  const pending = awaitingKey.get(f);
  if (!pending) return f;
  const fp = fingerprint(pending.label, pending.value);
  if (!fp) return f;
  awaitingKey.delete(f);
  return { ...f, masked: token(canonicalKind(pending.label), fp), fingerprint: fp };
}

/** Findings for `[label, value]` pairs, de-duplicated and capped. */
export function collectFindings(matches: Array<[string, string]>): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const [label, value] of matches) {
    const f = makeFinding(label, value);
    const id = `${f.kind}|${f.fingerprint ?? ''}|${f.masked}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(f);
    if (out.length >= MAX_FINDINGS) break;
  }
  return out;
}

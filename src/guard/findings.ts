/**
 * What a reviewer may see of a sensitive value a guard found: its kind, a
 * masked form (the last four digits of an SSN, the prefix of an API key) and a
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

/** Enough of a value to recognise it, never enough to use it. */
export function mask(label: string, value: string): string {
  const v = value.trim();
  const kind = canonicalKind(label);
  switch (kind) {
    case 'ssn':
      return '***-**-' + digits(v).slice(-4);
    case 'payment_card':
      return '•••• ' + digits(v).slice(-4);
    case 'phone-us':
      return '***-***-' + digits(v).slice(-4);
    case 'private_key':
      return v;
    case 'email': {
      const at = v.indexOf('@');
      return at > 0 ? v[0] + '***' + v.slice(at) : '***';
    }
    case 'ipv4': {
      const parts = v.split('.');
      return parts.length === 4 ? `${parts[0]}.${parts[1]}.x.x` : 'x.x.x.x';
    }
    case 'connection_string': {
      const m = /^([a-z+]+:\/\/[^:/@\s]+:)[^@\s]*(@.*)?$/i.exec(v);
      if (m) return m[1] + '****@' + (m[2] || '@').slice(1).split('/')[0];
      return v.split('://')[0] + '://****';
    }
    case 'password': {
      const i = v.search(/[:=]/);
      const name = i > 0 ? v.slice(0, i).replace(/^[\s"']+|[\s"']+$/g, '') : '';
      return name ? `${name} = ••••••••` : '••••••••';
    }
    case 'bearer-token':
    case 'basic-auth':
      return `${v.split(/\s+/)[0] || ''} …${v.slice(-4)}`;
    default: {
      // Keys and tokens: the public prefix names the service, the last four
      // tell two keys apart.
      let prefix = v.slice(0, 12);
      const cut = Math.max(prefix.lastIndexOf('-'), prefix.lastIndexOf('_'));
      prefix = cut >= 2 ? prefix.slice(0, cut + 1) : prefix.slice(0, 4);
      if (v.length <= prefix.length + 4) return prefix + '…';
      return prefix + '…' + v.slice(-4);
    }
  }
}

export function makeFinding(label: string, value: string): Finding {
  const f: Finding = { kind: label, masked: mask(label, value) };
  const fp = fingerprint(label, value);
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
  return { ...f, fingerprint: fp };
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

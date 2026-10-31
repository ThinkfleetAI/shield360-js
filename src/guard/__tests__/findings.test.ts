import { createHmac } from 'crypto';
import { PII } from '../pii';
import { GuardPhase } from '../base';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { fingerprint, mask, setFingerprintKey, token } from '../findings';

// Test values are assembled at run time so secret scanners don't flag this file.
const SSN = '123-45-' + '6789';
const CARD = '4111 1111 ' + '1111 1111';
const OPENAI = 'sk-' + 'proj-' + 'abcdefghijklmnopqrstuvwxyz0123';

afterEach(() => setFingerprintKey(null));

describe('findings', () => {
  it('masks to the kind alone without a key: no character of the value', () => {
    expect(mask('ssn', SSN)).toBe('[ssn]');
    expect(mask('credit-card', CARD)).toBe('[payment_card]');
    expect(mask('openai-api-key', OPENAI)).toBe('[api_key]');
    expect(mask('email', 'ana@acme.test')).toBe('[email]');
  });

  it('masks to the kind and the start of the keyed fingerprint with a key', () => {
    setFingerprintKey('org-secret');
    const fp = fingerprint('openai-api-key', OPENAI);
    expect(mask('openai-api-key', OPENAI)).toBe(`[api_key:fp_${fp.slice(0, 8)}]`);
  });

  it('matches the shared token vectors', () => {
    // The vectors live beside this SDK in the monorepo (sdk/guard-core) and inside the SDK's public mirror (guard-core/).
    const candidates = [join(__dirname, '../../../../guard-core/testdata/tokens.json'), join(__dirname, '../../../guard-core/testdata/tokens.json')];
    const path = candidates.find((p) => existsSync(p));
    if (!path) throw new Error(`shared token vectors not found at ${candidates.join(' or ')}`);
    const file = JSON.parse(readFileSync(path, 'utf8'));
    for (const v of file.cases) expect(token(v.kind, v.fingerprint)).toBe(v.token);
  });

  it('fingerprints only with a key, the same way as the CLI and Python', () => {
    expect(fingerprint('ssn', SSN)).toBe('');
    setFingerprintKey('org-secret');
    const expected = createHmac('sha256', 'org-secret').update('ssn:123456789').digest('hex').slice(0, 16);
    expect(fingerprint('ssn', SSN)).toBe(expected);
    expect(fingerprint('credit-card', CARD)).toBe(
      createHmac('sha256', 'org-secret').update('payment_card:4111111111111111').digest('hex').slice(0, 16),
    );
  });

  it('PII results carry findings, not values', () => {
    setFingerprintKey('org-secret');
    const r = new PII({ action: 'deny' }).run(`SSN ${SSN}, card ${CARD}`, GuardPhase.PREFLIGHT);
    const masked = Object.fromEntries((r.findings || []).map((f) => [f.kind, f.masked]));
    expect(masked.ssn).toBe(`[ssn:fp_${fingerprint('ssn', SSN).slice(0, 8)}]`);
    expect(JSON.stringify(r.findings)).not.toContain(SSN);
    expect(JSON.stringify(r.findings)).not.toContain(CARD);
  });
});

describe('findings made before the key arrives', () => {
  it('are fingerprinted once the key is known, without the value ever being serialized', async () => {
    const { completeFinding, makeFinding } = await import('../findings');
    const early = makeFinding('ssn', SSN);
    expect(early.fingerprint).toBeUndefined();
    expect(JSON.stringify(early)).not.toContain(SSN);
    setFingerprintKey('org-secret');
    expect(early.masked).toBe('[ssn]');
    const done = completeFinding(early);
    expect(done.fingerprint).toBe(fingerprint('ssn', SSN));
    expect(done.masked).toBe(`[ssn:fp_${done.fingerprint!.slice(0, 8)}]`);
  });
});

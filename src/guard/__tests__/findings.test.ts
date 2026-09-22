import { createHmac } from 'crypto';
import { PII } from '../pii';
import { GuardPhase } from '../base';
import { fingerprint, mask, setFingerprintKey } from '../findings';

// Test values are assembled at run time so secret scanners don't flag this file.
const SSN = '123-45-' + '6789';
const CARD = '4111 1111 ' + '1111 1111';
const OPENAI = 'sk-' + 'proj-' + 'abcdefghijklmnopqrstuvwxyz0123';

afterEach(() => setFingerprintKey(null));

describe('findings', () => {
  it('masks enough to recognise, never enough to use', () => {
    expect(mask('ssn', SSN)).toBe('***-**-6789');
    expect(mask('credit-card', CARD)).toBe('•••• 1111');
    const key = mask('openai-api-key', OPENAI);
    expect(key.startsWith('sk-proj-') && key.endsWith('0123') && !key.includes('abcdef')).toBe(true);
    expect(mask('email', 'ana@acme.test')).toBe('a***@acme.test');
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
    expect(masked.ssn).toBe('***-**-6789');
    expect(JSON.stringify(r.findings)).not.toContain(SSN);
    expect(JSON.stringify(r.findings)).not.toContain(CARD);
  });
});

describe('findings made before the key arrives', () => {
  it('are fingerprinted once the key is known, without the value ever being serialised', async () => {
    const { completeFinding, makeFinding } = await import('../findings');
    const early = makeFinding('ssn', SSN);
    expect(early.fingerprint).toBeUndefined();
    expect(JSON.stringify(early)).not.toContain(SSN);
    setFingerprintKey('org-secret');
    expect(completeFinding(early).fingerprint).toBe(fingerprint('ssn', SSN));
  });
});

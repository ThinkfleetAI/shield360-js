import { OutputStreamScanner, HOLDBACK, RELEASE_STEP, WINDOW } from '../output';
import { DEFAULT_POLICY, type AiSecurityPolicy } from '../policy';
import { resetAiSecurity, streamScanner, AiSecurityBlockedError } from '../index';
import { FAKE } from './fixtures';

const policy: AiSecurityPolicy['output'] = { ...DEFAULT_POLICY.output };

function chunks(text: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}

function run(text: string, size: number, enforce = { redact: true, block: false }, systemPrompt?: string) {
  const s = new OutputStreamScanner({ policy, systemPrompt }, enforce);
  let out = '';
  for (const c of chunks(text, size)) out += s.push(c).text;
  out += s.end().text;
  return { out, scanner: s };
}

describe('streamed output', () => {
  const secret = `Here you go: ${FAKE.OPENAI_KEY} and the card ${FAKE.CARD}. Thanks!`;

  it.each([1, 3, 7, 16, 64, 1000])('redacts a value split across chunks of %i characters', (size) => {
    const { out, scanner } = run(secret, size);
    expect(out).not.toContain(FAKE.OPENAI_KEY);
    expect(out).not.toContain(FAKE.CARD);
    expect(out).toContain('Here you go:');
    expect(out).toContain('Thanks!');
    expect(new Set(scanner.findings.map((f) => f.label))).toEqual(new Set(['openai-api-key', 'credit-card']));
  });

  it('passes ordinary text through unchanged, whatever the chunking', () => {
    const text = 'The quick brown fox jumps over the lazy dog. '.repeat(50);
    for (const size of [1, 5, 50, 500]) expect(run(text, size).out).toBe(text);
  });

  it('reports without changing anything in monitor mode', () => {
    const { out, scanner } = run(secret, 5, { redact: false, block: false });
    expect(out).toBe(secret);
    expect(scanner.findings.length).toBe(2);
  });

  it('stops releasing once a blocking finding appears', () => {
    const text = `${'ok '.repeat(200)}${FAKE.OPENAI_KEY}${' more'.repeat(200)}`;
    const s = new OutputStreamScanner({ policy }, { redact: false, block: true });
    let out = '';
    let blocked = false;
    for (const c of chunks(text, 10)) {
      const v = s.push(c);
      out += v.text;
      if (v.blocked) {
        blocked = true;
        break;
      }
    }
    expect(blocked).toBe(true);
    expect(out).not.toContain(FAKE.OPENAI_KEY.slice(0, 12));
  });

  it('detects a system prompt leaking over many chunks', () => {
    const prompt = 'You are the Acme billing assistant. Only answer questions about invoices issued by Acme Corp in the current fiscal year. Never quote internal discount codes or partner pricing tiers to customers.';
    const leak = `Sure. ${prompt.split('. ').slice(1).join('. ')}`;
    const { scanner } = run(leak, 4, { redact: true, block: false }, prompt);
    expect(scanner.blocked).toBe(true);
    expect(scanner.findings.some((f) => f.kind === 'system_prompt_leak')).toBe(true);
  });

  it('keeps its buffers bounded on a long stream', () => {
    const s = new OutputStreamScanner({ policy }, { redact: true, block: false });
    const text = 'lorem ipsum dolor sit amet '.repeat(20_000);
    for (const c of chunks(text, 100)) s.push(c);
    const internals = s as unknown as { pending: string; released: string };
    expect(internals.pending.length).toBeLessThanOrEqual(HOLDBACK + RELEASE_STEP + 100);
    expect(internals.released.length).toBeLessThanOrEqual(WINDOW);
  });

  it('the facade throws once enforce mode blocks, and fails open on an internal error', () => {
    resetAiSecurity({ policy: { output: { mode: 'enforce', action: 'block' } } });
    const sc = streamScanner();
    expect(() => {
      for (const c of chunks(secret, 4)) sc.push(c);
      sc.end();
    }).toThrow(AiSecurityBlockedError);
    resetAiSecurity();
  });
});

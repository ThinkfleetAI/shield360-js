/**
 * Detection quality of the AI security pack, on attack and benign corpora.
 * Rates are printed so a change that moves them is visible in the test log.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { scanForInjection, INJECTION_RULES_VERSION, type InjectionSource } from '../injection';
import { scanToolDescription, TOOL_RULES_VERSION } from '../mcp';
import { scanOutput } from '../output';
import { assessTurns } from '../jailbreak';
import { DEFAULT_POLICY, type AiSecurityPolicy } from '../policy';
import { fill, haveInjectionCorpus, INJECTION_DIR, rate, readJson } from './fixtures';

type Sample = { id: string; split: string; label: 'malicious' | 'benign'; category: string; source: InjectionSource; text: string };
type Expectation = { id: string; score: number; detected: boolean; rules: string[]; spans: [number, number][][]; snippets: string[]; fingerprints: string[] };

const describeCorpus = haveInjectionCorpus ? describe : describe.skip;

describeCorpus('injection detector copy', () => {
  const corpus: Sample[] = haveInjectionCorpus ? JSON.parse(readFileSync(join(INJECTION_DIR, 'testdata/corpus.json'), 'utf8')).samples : [];
  const golden: { version: string; results: Expectation[] } = haveInjectionCorpus
    ? JSON.parse(readFileSync(join(INJECTION_DIR, 'testdata/expected.json'), 'utf8'))
    : { version: '', results: [] };

  it('loads the shared rules byte for byte', () => {
    const go = readFileSync(join(INJECTION_DIR, 'rules.json'));
    const ours = readFileSync(join(__dirname, '../injection-rules.json'));
    expect(ours.equals(go)).toBe(true);
    expect(golden.version).toBe(INJECTION_RULES_VERSION);
  });

  it('agrees with the Go detector on every corpus sample', () => {
    const byId = new Map(golden.results.map((r) => [r.id, r]));
    const off: string[] = [];
    for (const s of corpus) {
      const res = scanForInjection(s.text, { source: s.source, fingerprintKey: 'corpus-test-key' });
      const got = {
        id: s.id,
        score: res.score,
        detected: res.detected,
        rules: res.matches.map((m) => m.rule),
        spans: res.matches.map((m) => m.spans),
        snippets: res.matches.map((m) => m.snippet),
        fingerprints: res.matches.map((m) => m.fingerprint || ''),
      };
      if (JSON.stringify(got) !== JSON.stringify(byId.get(s.id))) off.push(s.id);
    }
    expect(off).toEqual([]);
  });

  it('indirect injection: detection and false positives on untrusted sources', () => {
    const untrusted = corpus.filter((s) => s.source !== 'prompt');
    const bad = untrusted.filter((s) => s.label === 'malicious');
    const good = untrusted.filter((s) => s.label === 'benign');
    const hit = bad.filter((s) => scanForInjection(s.text, { source: s.source }).detected).length;
    const fp = good.filter((s) => scanForInjection(s.text, { source: s.source }).detected).length;
    console.log(`indirect injection (rules ${INJECTION_RULES_VERSION}): detection ${rate(hit, bad.length)}, false positives ${rate(fp, good.length)}`);
    expect(fp).toBe(0);
    expect(hit / bad.length).toBeGreaterThanOrEqual(0.9);
  });

  it('jailbreaks: detection and false positives on single prompts', () => {
    const prompts = corpus.filter((s) => s.source === 'prompt');
    const bad = prompts.filter((s) => s.label === 'malicious' && ['roleplay', 'jailbreak', 'obfuscation', 'override', 'multilingual', 'leak'].includes(s.category));
    const good = prompts.filter((s) => s.label === 'benign');
    const hit = bad.filter((s) => scanForInjection(s.text).detected).length;
    const fp = good.filter((s) => scanForInjection(s.text).detected).length;
    console.log(`jailbreak single-turn: detection ${rate(hit, bad.length)}, false positives ${rate(fp, good.length)}`);
    expect(fp).toBe(0);
    expect(hit / bad.length).toBeGreaterThanOrEqual(0.9);
  });
});

describe('multi-turn jailbreak corpus', () => {
  it('detects escalation and leaves ordinary conversations alone', () => {
    const { samples } = readJson<{ samples: { label: string; turns: string[] }[] }>('conversations.json');
    const bad = samples.filter((s) => s.label === 'escalating');
    const good = samples.filter((s) => s.label === 'benign');
    const missed = bad.filter((s) => !assessTurns(s.turns).detected);
    const flagged = good.filter((s) => assessTurns(s.turns).detected);
    console.log(`jailbreak multi-turn: detection ${rate(bad.length - missed.length, bad.length)}, false positives ${rate(flagged.length, good.length)}`);
    expect(flagged.map((s) => s.turns[0])).toEqual([]);
    expect(missed.map((s) => s.turns[0])).toEqual([]);
  });
});

describe('tool poisoning corpus', () => {
  const { samples } = readJson<{ samples: { label: string; split: string; text: string }[] }>('tool-descriptions.json');
  const others = ['send_email', 'read_file', 'search', 'git_push'];
  const measure = (split: string) => {
    const set = samples.filter((s) => s.split === split);
    const bad = set.filter((s) => s.label === 'malicious');
    const good = set.filter((s) => s.label === 'benign');
    const missed = bad.filter((s) => !scanToolDescription(s.text, others).detected);
    const flagged = good.filter((s) => scanToolDescription(s.text, others).detected);
    console.log(`tool poisoning [${split}] (tool rules ${TOOL_RULES_VERSION}): detection ${rate(bad.length - missed.length, bad.length)}, false positives ${rate(flagged.length, good.length)}`);
    return { missed, flagged };
  };
  it('detects poisoned descriptions and passes ordinary ones (tuning split)', () => {
    const { missed, flagged } = measure('tuning');
    expect(flagged.map((s) => s.text)).toEqual([]);
    expect(missed.map((s) => s.text)).toEqual([]);
  });
  it('reports the held-out split (not tuned on)', () => {
    const { flagged } = measure('holdout');
    expect(flagged.length).toBeLessThanOrEqual(1);
  });
});

describe('output corpus', () => {
  const policy: AiSecurityPolicy['output'] = { ...DEFAULT_POLICY.output };
  it('finds sensitive values and links, and nothing in ordinary answers', () => {
    const { samples } = readJson<{ samples: { label: string; kind?: string; text: string }[] }>('outputs.json');
    const bad = samples.filter((s) => s.label === 'sensitive');
    const good = samples.filter((s) => s.label === 'benign');
    const missed = bad.filter((s) => !scanOutput(fill(s.text), { policy }).findings.some((f) => f.kind === s.kind));
    const flagged = good.filter((s) => scanOutput(s.text, { policy }).findings.length > 0);
    console.log(`output scanning: detection ${rate(bad.length - missed.length, bad.length)}, false positives ${rate(flagged.length, good.length)}`);
    expect(flagged.map((s) => s.text)).toEqual([]);
    expect(missed.map((s) => s.text)).toEqual([]);
  });
});

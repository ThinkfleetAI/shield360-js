/**
 * The shared RASP corpus (sdk/rasp/testdata): every benign case must fire
 * nothing (false-positive rate per section, must be 0), every entry of
 * attack-examples.json must be detected as it says, and the embedded data
 * files must stay byte-identical to the contract's copies.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { sqlTokens, type SqlDialect } from '../lexers';
import { TEMPLATE_ENGINES } from '../template';
import { loadJson, RASP_DIR, runCase, SECTIONS, type Section } from './corpus';

const benign = loadJson('testdata/benign.json');
const attacks = { cases: [...loadJson('testdata/attack-examples.json').cases, ...loadJson('testdata/template-attack-examples.json').cases] };
const lexer = loadJson('testdata/sql-lexer.json');

describe('RASP benign corpus', () => {
  const rates: Record<string, string> = {};

  afterAll(() => {
    // The report the contract asks each SDK for: false positives per section.
    console.log(`RASP false-positive rates (TypeScript):\n${Object.entries(rates).map(([s, r]) => `  ${s}: ${r}`).join('\n')}`);
  });

  it('is the generated corpus, version 1, with every section', () => {
    expect(benign.version).toBe(1);
    for (const s of SECTIONS) expect(Array.isArray(benign[s]) && benign[s].length > 0).toBe(true);
  });

  it.each(SECTIONS.map((s) => [s]))('%s: no false positives', (section) => {
    const cases: any[] = benign[section];
    const fired = cases.map((c) => ({ name: c.name, f: runCase(section as Section, c) })).filter((x) => x.f);
    rates[section] = `${fired.length}/${cases.length} (${((100 * fired.length) / cases.length).toFixed(2)}%)`;
    expect(fired.map((x) => `${x.name}: ${x.f?.rule}`)).toEqual([]);
  });
});

describe('RASP attack examples', () => {
  it('is the reviewed file (empty until the owner adds cases)', () => {
    expect(Array.isArray(attacks.cases)).toBe(true);
  });

  const cases: any[] = Array.isArray(attacks.cases) ? attacks.cases : [];
  const named = cases.map((c) => [String(c.name ?? c.check), c] as [string, any]);
  if (named.length) {
    it.each(named)('detects %s', (_name, c) => {
      const f = runCase(c.check as Section, c);
      expect(f?.attack).toBe(c.expect.attack);
      if (c.expect.rule) expect(f?.rule).toBe(c.expect.rule);
    });
  }
});

describe('SQL lexer conformance', () => {
  const cases: any[] = lexer.cases;
  it.each(cases.map((c) => [c.name, c]))('%s', (_name, c) => {
    expect(sqlTokens(c.query, c.dialect as SqlDialect).map((t) => [t.kind, t.text])).toEqual(c.tokens);
  });
});

describe('embedded RASP data', () => {
  const embedded = (f: string) => readFileSync(join(__dirname, '..', 'data', f));

  it('default-rules.json is byte-identical to sdk/rasp/rules', () => {
    expect(embedded('default-rules.json').equals(readFileSync(join(RASP_DIR, 'rules', 'default-rules.json')))).toBe(true);
  });

  it('the template engine table matches sdk/rasp/rules/template-engines.json', () => {
    expect(TEMPLATE_ENGINES).toEqual(loadJson('rules/template-engines.json').engines);
  });

  it('dnslog-domains.json is byte-identical to sdk/rasp/testdata', () => {
    expect(embedded('dnslog-domains.json').equals(readFileSync(join(RASP_DIR, 'testdata', 'dnslog-domains.json')))).toBe(true);
  });
});

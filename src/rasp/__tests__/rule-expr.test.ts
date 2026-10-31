/**
 * Custom rule expressions (README "Custom rules"): the shared conformance
 * corpus (testdata/custom-rules.json), the limits, the safe regex subset and
 * its linear-time matcher, CIDR matching, and fail-open evaluation.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { compileRegex, compileRuleExpr, evaluateRuleExpr, parseCidr, parseIpBytes, RULE_EXPR_LIMITS, type RuleSubject } from '../rule-expr';
import { loadJson, RASP_DIR } from './corpus';

const corpus = loadJson('testdata/custom-rules.json');
const subjectOf = (s: string | RuleSubject): RuleSubject => (typeof s === 'string' ? corpus.subjects[s] : s);

const compiled = (src: string) => {
  const r = compileRuleExpr(src);
  if (!r.ok) throw new Error(`${src}: ${r.error.code}`);
  return r.expr;
};
const run = (src: string, subject: RuleSubject) => evaluateRuleExpr(compiled(src), subject).matched;

describe('custom rule corpus', () => {
  it('is version 1 and states the same limits as the language', () => {
    expect(corpus.version).toBe(1);
    expect(corpus.limits).toEqual({ ...RULE_EXPR_LIMITS });
  });

  it.each((corpus.valid as any[]).map((c) => [c.name, c]))('valid: %s', (_name, c: any) => {
    const r = compileRuleExpr(c.expression);
    expect(r.ok ? 'ok' : r.error.code).toBe('ok');
    if (!r.ok) return;
    if (c.phase) expect(r.expr.phase).toBe(c.phase);
    if (c.usesInput !== undefined) expect(r.expr.usesInput).toBe(c.usesInput);
    if (c.usesBody !== undefined) expect(r.expr.usesBody).toBe(c.usesBody);
    for (const k of c.cases) expect([k.subject, evaluateRuleExpr(r.expr, subjectOf(k.subject)).matched]).toEqual([k.subject, k.expect]);
  });

  it.each((corpus.invalid as any[]).map((c) => [c.name, c]))('invalid: %s', (_name, c: any) => {
    const r = compileRuleExpr(c.expression);
    expect(r.ok ? 'ok' : r.error.code).toBe(c.error);
  });

  it('is the generator output', () => {
    // The generator is the source; a hand edit of the JSON would drift from it.
    const gen = readFileSync(join(RASP_DIR, 'scripts', 'gen-custom-rules.mjs'), 'utf8');
    expect(gen).toContain('testdata", "custom-rules.json"');
    expect(corpus.valid.length).toBeGreaterThan(60);
    expect(corpus.invalid.length).toBeGreaterThan(60);
  });
});

describe('compileRuleExpr', () => {
  it('refuses anything but a string', () => {
    for (const v of [undefined, null, 1, {}, []]) expect(compileRuleExpr(v)).toMatchObject({ ok: false, error: { code: 'empty' } });
  });

  it('reports where a syntax error is', () => {
    const r = compileRuleExpr('request.method == "GET" &&& true');
    expect(r).toMatchObject({ ok: false, error: { code: 'syntax' } });
    expect(!r.ok && r.error.pos).toBeGreaterThan(20);
  });

  it('classifies the phase from the fields read', () => {
    expect(compiled('request.path == "/"').phase).toBe('request');
    expect(compiled('attack.type == "ssrf"').phase).toBe('finding');
    expect(compiled('sink.name == "fs.readFile" && input.key == "query.f"')).toMatchObject({ phase: 'finding', usesInput: true, usesBody: false });
    expect(compiled('request.body["a"] == "b"').usesBody).toBe(true);
    expect(compiled('request.headers["X-A"] == "1" && app.name == "a"').fields).toEqual(['app.name', 'request.headers']);
  });

  it('guards parser recursion before the AST is built', () => {
    // Far deeper than any stack would allow, within the byte limit.
    expect(compileRuleExpr(`${'('.repeat(1000)}true${')'.repeat(1000)}`)).toMatchObject({ ok: false, error: { code: 'depth' } });
    expect(compileRuleExpr(`${'!'.repeat(2000)}true`)).toMatchObject({ ok: false, error: { code: 'depth' } });
  });
});

describe('evaluation', () => {
  const get = corpus.subjects.get as RuleSubject;

  it('short-circuits left to right', () => {
    expect(run('request.method == "GET" || request.path.matches("x")', get)).toBe(true);
    expect(run('request.method == "PUT" && request.path.matches("x")', get)).toBe(false);
  });

  it('returns the input that matched', () => {
    const r = evaluateRuleExpr(compiled('input.key == "query.sort"'), get);
    expect(r).toEqual({ matched: true, input: { value: 'name desc', key: 'query.sort', source: 'request' } });
  });

  it('fails open on a malformed subject', () => {
    const e = compiled('request.headers["a"] == "b" && input.value == "x"');
    for (const s of [{}, { request: 'nope' }, { request: { headers: 'x' } }, { inputs: 'x' }, { inputs: [null, 1] }] as unknown as RuleSubject[]) {
      expect(evaluateRuleExpr(e, s).matched).toBe(false);
    }
    expect(evaluateRuleExpr(compiled('request.headers["a"] == null'), { request: { headers: Object.create({ a: 'inherited' }) } }).matched).toBe(true);
  });

  it('stops at the budget and reports no match', () => {
    const e = compiled('input.value.matches("a{100}x")');
    const big = { app: 'a', inputs: Array.from({ length: 256 }, (_, i) => ({ value: 'a'.repeat(4096), key: `query.k${i}`, source: 'request' })) };
    const budget = { steps: 10_000 };
    expect(evaluateRuleExpr(e, big, budget)).toEqual({ matched: false, exhausted: true });
    expect(budget.steps).toBeLessThan(0);
  });

  it('matches in time linear in the subject (no catastrophic backtracking)', () => {
    // The classic exponential case for backtracking engines, rewritten in the subset.
    const e = compiled('app.name.matches("^(?:a|a)*b$")');
    const t0 = Date.now();
    expect(evaluateRuleExpr(e, { app: 'a'.repeat(4000) }).matched).toBe(false);
    const e2 = compiled('app.name.matches(".*.*.*.*.*.*x")');
    expect(evaluateRuleExpr(e2, { app: 'a'.repeat(4096) }).matched).toBe(false);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe('regex subset', () => {
  it.each(['a', '^a$', '[a-z0-9_]+', '(?:x|y){1,3}', '\\d{3}-\\d{4}', '.*', 'a|', '(?:)', '[\\s\\S]'])('accepts %s', (p) => {
    expect(compileRegex(p)).not.toBeNull();
  });
  it.each(['(a+)+', '(a*)*', '(a|b+)*', 'a{0,1000}', '\\1', '(?=x)', '(?!x)', '(?<=x)', '(?P<n>x)', '\\Z', '\\A', '\\cA', 'a{1,2}{3}', '[a-\\d]', 'x{', '\\'])('refuses %s', (p) => {
    expect(compileRegex(p)).toBeNull();
  });
});

describe('CIDR', () => {
  it('parses addresses strictly', () => {
    expect(parseIpBytes('1.2.3.4')).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4]);
    expect(parseIpBytes('::1')).toEqual([...new Array(15).fill(0), 1]);
    expect(parseIpBytes('1:2:3:4:5:6:1.2.3.4')).toEqual([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4]);
    for (const bad of ['1.2.3', '1.2.3.256', '01.2.3.4', ':1', '1:::2', '1:2:3:4:5:6:7:8:9', '12345::', 'g::', '1.2.3.4::', '']) expect(parseIpBytes(bad)).toBeNull();
  });

  it('keeps IPv4 prefixes in IPv4-mapped space', () => {
    expect(parseCidr('10.0.0.0/8')).toMatchObject({ prefix: 104 });
    expect(parseCidr('::/0')).toMatchObject({ prefix: 0 });
    expect(parseCidr('1.2.3.4')).toMatchObject({ prefix: 128 });
  });
});

// README "Collector contexts": the same language with the collector's fields.
describe('collector contexts', () => {
  it('compiles each context against its own fields', () => {
    expect(compileRuleExpr('tool.name == "Bash" && tool.command.contains("rm -rf")', 'agent_tool').ok).toBe(true);
    expect(compileRuleExpr('ai.provider == "openai" && ai.tokens.matches("^[0-9]{6,}$")', 'ai_proxy').ok).toBe(true);
    expect(compileRuleExpr('ai.model == "x"', 'agent_tool')).toMatchObject({ ok: false, error: { code: 'unknown_field' } });
    expect(compileRuleExpr('tool.name == "x"', 'ai_proxy')).toMatchObject({ ok: false, error: { code: 'unknown_field' } });
    expect(compileRuleExpr('tool.name == "x"')).toMatchObject({ ok: false, error: { code: 'unknown_field' } });
    expect(compileRuleExpr('user.id == "x"', 'nope' as never)).toMatchObject({ ok: false, error: { code: 'context' } });
  });

  it('evaluates collector subjects, with absent fields as null', () => {
    const r = compileRuleExpr('agent.name == "cursor" && tool.path.startsWith("/etc/")', 'agent_tool');
    if (!r.ok) throw new Error(r.error.code);
    expect(r.expr.context).toBe('agent_tool');
    expect(evaluateRuleExpr(r.expr, { collector: { agent: { name: 'cursor' }, tool: { path: '/etc/hosts' } } }).matched).toBe(true);
    expect(evaluateRuleExpr(r.expr, { collector: { agent: { name: 'cursor' } } }).matched).toBe(false);
    expect(evaluateRuleExpr(r.expr, {}).matched).toBe(false);
  });
});

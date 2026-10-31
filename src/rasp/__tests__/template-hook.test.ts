import * as detector from '../template';
import { detectTemplate, type TemplateEngine } from '../template';
import { type HookedTemplateEngine, patchTemplate, patchHandlebarsCompiler, unpatchTemplate, uninstallTemplateHooks, installTemplateHooks, RaspTemplateInstrumentation } from '../hooks/template';
import { installCodeHooks, uninstallCodeHooks } from '../hooks/code';
import { configureEngine, setEventSink } from '../engine';
import { runWithInputs } from '../context';
import { RaspBlockedError } from '../types';
const input = (value: string) => [{ value, key: 'query.q', source: 'request' as const }];
const taint = <T>(value: string, fn: () => T): T => runWithInputs(input(value), fn, { inRequest: true });
const mode = (value: 'block' | 'monitor' | 'off' = 'block') => configureEngine({ enabled: true, applicationName: 'a', mode: 'block', attacks: { code_injection: value }, env: {} });
const engines: [HookedTemplateEngine, string, string][] = [
  ['handlebars', 'compile', '{{name}}'], ['ejs', 'render', '<%= 1 + 2 %>'], ['pug', 'compile', '#{1 + 2}'],
  ['nunjucks', 'renderString', '{{ 1 + 2 }}'], ['lodash', 'template', '<%= 1 + 2 %>'],
];
beforeEach(() => { mode(); setEventSink({ add: () => undefined }); });
afterEach(() => { uninstallCodeHooks(); uninstallTemplateHooks(); jest.restoreAllMocks(); setEventSink(undefined); configureEngine({ enabled: false, applicationName: 'a', env: {} }); });
test.each(engines)('%s blocks source before original; monitor and off preserve arguments and receiver', (engine, method, source) => {
  const original = jest.fn(function (this: unknown, ...args: unknown[]) { return { receiver: this, args }; });
  const module = { [method]: original };
  patchTemplate(engine, module);
  const wrapper = module[method];
  patchTemplate(engine, module);
  expect(module[method]).toBe(wrapper);
  expect(() => taint(source, () => module[method](source))).toThrow(RaspBlockedError);
  expect(original).not.toHaveBeenCalled();
  const events = jest.fn();
  setEventSink({ add: events });
  mode('monitor');
  const data = { name: source };
  expect(taint(source, () => module[method](source, data))).toEqual({ receiver: module, args: [source, data] });
  expect(events).toHaveBeenCalledTimes(1);
  expect(events.mock.calls[0][0].attrs).toMatchObject({ 'shield360.rasp.rule': 'code.template_injection', 'shield360.rasp.attack': 'code_injection' });
  mode('off');
  events.mockClear();
  const spy = jest.spyOn(detector, 'detectTemplate');
  taint(source, () => module[method](source));
  expect(spy).not.toHaveBeenCalled();
  expect(events).not.toHaveBeenCalled();
  mode();
  spy.mockImplementation(() => { throw new Error('detector unavailable'); });
  expect(() => taint(source, () => module[method](source))).not.toThrow();
});
test.each(engines)('%s allows fixed templates with expression-like input only as data', (engine, method, source) => {
  const original = jest.fn((...args: unknown[]) => args);
  const module = { [method]: original };
  patchTemplate(engine, module);
  expect(taint('{{ 7 * 7 }}', () => module[method](source, { name: '{{ 7 * 7 }}' }))).toEqual([source, { name: '{{ 7 * 7 }}' }]);
  expect(taint('ordinary prose', () => module[method]('Hello ordinary prose'))).toEqual(['Hello ordinary prose']);
});
test('structure, overlap, minimum length and single expression tokens', () => {
  expect(detectTemplate('Hello {{ 7 * 7 }}', input('{{ 7 * 7 }}'), 'handlebars')?.rule).toBe('code.template_injection');
  expect(detectTemplate('<%= 7 * 7 %>', input('7 * 7'), 'ejs')?.rule).toBe('code.template_injection');
  expect(detectTemplate('p\n  - 7 + 7', input('- 7 + 7'), 'pug')?.rule).toBe('code.template_injection');
  for (const [source, value] of [['Hello {{name}}', 'name'], ['<%= "ordinary prose" %>', 'ordinary prose'], ['Hello 7 + 7', '7 + 7'], ['{{name}}', 'absent'], ['{{x}}', 'x']]) {
    expect(detectTemplate(source, input(value), source.startsWith('Hello {{') ? 'handlebars' : 'ejs')).toBeNull();
  }
});
test('one check for render delegating to compile and Function', () => {
  installCodeHooks();
  mode('monitor');
  const module = { compile: (s: string) => new Function(`return ${s.length}`)(), render: (s: string) => module.compile(s) };
  patchTemplate('ejs', module);
  const events = jest.fn(); setEventSink({ add: events });
  const spy = jest.spyOn(detector, 'detectTemplate');
  expect(taint('<%= 1 + 2 %>', () => module.render('<%= 1 + 2 %>'))).toBe(12);
  expect(spy).toHaveBeenCalledTimes(1);
  expect(events).toHaveBeenCalledTimes(1);
});
test('generations disable retained wrappers across reinstall; unpatch preserves later wrappers', () => {
  installTemplateHooks();
  const original = jest.fn((s: string) => s);
  const module: { compile: (s: string) => string } = { compile: original };
  patchTemplate('handlebars', module);
  const old = module.compile;
  module.compile = s => old(s);
  const later = module.compile;
  uninstallTemplateHooks();
  installTemplateHooks();
  patchTemplate('handlebars', module);
  const spy = jest.spyOn(detector, 'detectTemplate');
  mode('monitor');
  taint('{{name}}', () => module.compile('{{name}}'));
  expect(spy).toHaveBeenCalledTimes(1);
  unpatchTemplate(module);
  expect(module.compile).toBe(later);
  expect(taint('{{name}}', () => old('{{name}}'))).toBe('{{name}}');
});
test('nunjucks Environment and instrumentation register optional engines without loading them', () => {
  class Environment { renderString(s: string) { return s; } }
  const module = { Environment };
  patchTemplate('nunjucks', module);
  expect(() => taint('{{name}}', () => new Environment().renderString('{{name}}'))).toThrow(RaspBlockedError);
  unpatchTemplate(module);
  expect(taint('{{name}}', () => new Environment().renderString('{{name}}'))).toBe('{{name}}');
  const instrumentation = new RaspTemplateInstrumentation();
  expect(instrumentation).toBeDefined();
  expect(() => patchTemplate('ejs', Object.freeze({ render: () => 'ok' }))).not.toThrow();
});
test('disabled engine, absent input and non-string sources bypass detection; original errors survive', () => {
  const failure = new Error('engine failure');
  const module = { render: jest.fn((..._args: unknown[]) => { throw failure; }) };
  patchTemplate('ejs', module);
  const spy = jest.spyOn(detector, 'detectTemplate');
  expect(() => module.render('<%= 1 + 2 %>')).toThrow(failure);
  expect(() => taint('input', () => module.render({ template: 'input' }))).toThrow(failure);
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
  expect(() => taint('<%= 1 + 2 %>', () => module.render('<%= 1 + 2 %>'))).toThrow(failure);
  expect(spy).not.toHaveBeenCalled();
});
// Review findings: each case below is harmless and never executes fixture source as an attack.
const realHandlebars = (() => { try { return require('handlebars'); } catch { return undefined; } })();
const withHandlebars = realHandlebars ? test : test.skip;
// Jest's module registry is not require.cache, so the real engine is patched the way the import hook patches it.
const patchRealHandlebars = () => {
  patchTemplate('handlebars', realHandlebars);
  patchHandlebarsCompiler(require('handlebars/dist/cjs/handlebars/compiler/compiler'));
};
test('an independent template or Function call inside a render helper is still checked', () => {
  installCodeHooks();
  const inner = { compile: jest.fn((s: string) => s) };
  patchTemplate('handlebars', inner);
  const outer = { render: (s: string, data: { helper: () => unknown }) => `${s}${String(data.helper())}` };
  patchTemplate('ejs', outer);
  const value = '{{name}}';
  expect(() => taint(value, () => outer.render('Hello <%= name %>', { helper: () => inner.compile(`Hi ${value}`) }))).toThrow(RaspBlockedError);
  expect(inner.compile).not.toHaveBeenCalled();
  const code = 'name + 1';
  expect(() => taint(code, () => outer.render('Hello <%= name %>', { helper: () => new Function(`return ${code}`) }))).toThrow(RaspBlockedError);
});
test('handlebars instances from create() share the patched compiler module', () => {
  const compiler = { compile: jest.fn((s: string) => s), precompile: jest.fn((s: string) => s) };
  const create = () => ({ compile: (s: string) => compiler.compile(s), precompile: (s: string) => compiler.precompile(s) });
  patchHandlebarsCompiler(compiler);
  const instance = create();
  expect(() => taint('{{name}}', () => instance.compile('Hi {{name}}'))).toThrow(RaspBlockedError);
  expect(() => taint('{{name}}', () => instance.precompile('Hi {{name}}'))).toThrow(RaspBlockedError);
  expect(compiler.compile).not.toHaveBeenCalled();
  unpatchTemplate(compiler);
  expect(taint('{{name}}', () => instance.compile('Hi {{name}}'))).toBe('Hi {{name}}');
});
withHandlebars('real handlebars: create() instances are covered after install', () => {
  patchRealHandlebars();
  const instance = realHandlebars.create();
  expect(() => taint('{{name}}', () => instance.compile('Hi {{name}}'))).toThrow(RaspBlockedError);
  uninstallTemplateHooks();
  expect(taint('{{name}}', () => instance.compile('Hi {{name}}')({ name: 'x' }))).toBe('Hi x');
});
test('pug attribute values are expression regions', () => {
  expect(detectTemplate('a(href=url + "x") Link', input('url + "x"'), 'pug')?.rule).toBe('code.template_injection');
  expect(detectTemplate('a(class="c" href=url)= label + 1', input('label + 1'), 'pug')?.rule).toBe('code.template_injection');
  expect(detectTemplate('a(href=url) Link', input('url'), 'pug')).toBeNull();
  expect(detectTemplate('a(title="O\'Brien here") Link', input("O'Brien here"), 'pug')).toBeNull();
  expect(detectTemplate('p Hello (see the notes) today', input('see the notes'), 'pug')).toBeNull();
});
test('a dotted path in a fixed template is one reference', () => {
  expect(detectTemplate('Hello {{user.name}}', input('user.name'), 'handlebars')).toBeNull();
  expect(detectTemplate('Hello <%= user.name %>', input('user.name'), 'ejs')).toBeNull();
  expect(detectTemplate('Hello {{ user.name }}', input('user.name }}'), 'nunjucks')?.rule).toBe('code.template_injection');
});
test('quoted closing delimiters stay inside their token where the engine lexes strings', () => {
  expect(detectTemplate('{{shout "a }} b"}} done', input('a }} b'), 'handlebars')).toBeNull();
  expect(detectTemplate('{{ "a }} b" | upper }} done', input('a }} b'), 'nunjucks')).toBeNull();
  expect(detectTemplate('p #{"a } b"} done', input('a } b'), 'pug')).toBeNull();
});
test('escaped handlebars mustaches and nunjucks comments are literal text', () => {
  expect(detectTemplate('Show \\{{name}} literally', input('{{name}}'), 'handlebars')).toBeNull();
  expect(detectTemplate('Show \\\\{{name}} live', input('{{name}}'), 'handlebars')?.rule).toBe('code.template_injection');
  expect(detectTemplate('Hi {# note {{ a + b }} #}', input('{{ a + b }}'), 'nunjucks')).toBeNull();
});
withHandlebars('real handlebars: fixed templates with matching data values render', () => {
  patchRealHandlebars();
  const hb = realHandlebars;
  hb.registerHelper('shout', (s: string) => s.toUpperCase());
  try {
    expect(taint('user.name', () => hb.compile('Hello {{user.name}}')({ user: { name: 'user.name' } }))).toBe('Hello user.name');
    expect(taint('a }} b', () => hb.compile('{{shout "a }} b"}}')({}))).toBe('A }} B');
    expect(taint('{{name}}', () => hb.compile('Show \\{{name}}')({ name: '{{name}}' }))).toBe('Show {{name}}');
  } finally { hb.unregisterHelper('shout'); }
});
test('shared engine table: tags, directives, line code, attributes and pairs are regions', () => {
  const hit = (source: string, value: string, engine: TemplateEngine) => detectTemplate(source, input(value), engine)?.rule;
  expect(hit('<#if x>${a}</#if>', 'x>${a}', 'freemarker')).toBe('code.template_injection');
  expect(hit('<#assign x = 7 * 7>', '7 * 7', 'freemarker')).toBe('code.template_injection');
  expect(hit('#set($x = 7 * 7)', '7 * 7', 'velocity')).toBe('code.template_injection');
  expect(hit('Hi\n% if a + b:\nx', 'a + b', 'mako')).toBe('code.template_injection');
  expect(hit('<%def name="x()">y</%def>', 'name="x()"', 'mako')).toBe('code.template_injection');
  expect(hit('<p th:text="a + b">x</p>', 'a + b', 'thymeleaf')).toBe('code.template_injection');
  expect(hit('@if($a + $b) y @endif', '$a + $b', 'blade')).toBe('code.template_injection');
  expect(hit('{{ printf "%d" 7 }}', 'printf "%d"', 'gotemplate')).toBe('code.template_injection');
  expect(hit('Hi {$a + $b}', '$a + $b', 'smarty')).toBe('code.template_injection');
  expect(hit('{% raw %}x{% endraw %}{{ a }}', '{% endraw %}{{ a }}', 'jinja2')).toBe('code.template_injection');
  expect(detectTemplate('{{ a }}', input('{{ a }}'), 'unknown' as TemplateEngine)).toBeNull();
});
test('review fixes: raw-block close variants, floor division, attribute spacing', () => {
  const hit = (source: string, value: string, engine: TemplateEngine) => detectTemplate(source, input(value), engine)?.rule;
  // A compact or trimming raw close ends the block; what follows is live.
  expect(hit('{% raw %}x{%endraw%}{{ 7 * 7 }}', '{{ 7 * 7 }}', 'jinja2')).toBe('code.template_injection');
  expect(hit('{% raw %}x{%- endraw -%}{{ 7 * 7 }}', '{{ 7 * 7 }}', 'nunjucks')).toBe('code.template_injection');
  // Trimming raw openers make literal text.
  expect(detectTemplate('{%- raw -%}{{ a + b }}{% endraw %}', input('{{ a + b }}'), 'jinja2')).toBeNull();
  // `//` is floor division, not a comment, inside template expressions.
  expect(hit('{{ 10 // a + b }}', 'a + b', 'jinja2')).toBe('code.template_injection');
  // Whitespace around `=` in an attribute.
  expect(hit('<p th:text = "a + b">x</p>', 'a + b', 'thymeleaf')).toBe('code.template_injection');
  // A Thymeleaf expression in plain HTML text is literal.
  expect(detectTemplate('<p>${a + b}</p>', input('${a + b}'), 'thymeleaf')).toBeNull();
});

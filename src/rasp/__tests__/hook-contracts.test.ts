/**
 * Every sink hook through the shared hook contract (hook-kit.ts). Triggers
 * are the harmless ones the hooks' own tests use.
 */
import cp = require('child_process');
import fs = require('fs');
import http = require('http');
import vm = require('vm');
import { tmpdir } from 'os';
import { join } from 'path';
import * as detect from '../detect';
import { installCodeHooks, uninstallCodeHooks } from '../hooks/code';
import { patchPg, unpatchPg } from '../hooks/db';
import { installFsHooks, uninstallFsHooks } from '../hooks/fs';
import { installHttpHooks, uninstallHttpHooks } from '../hooks/http';
import { installProcessHooks, PROCESS_APIS, uninstallProcessHooks } from '../hooks/process';
import { patchHandlebarsCompiler, patchTemplate, unpatchTemplate } from '../hooks/template';
import * as template from '../template';
import type { HookedTemplateEngine as TemplateEngine } from '../hooks/template';
import type { RaspInput } from '../types';
import { describeHookContract } from './hook-kit';

const req = (value: string): RaspInput => ({ value, key: 'query.q', source: 'request' });

describeHookContract({
  name: 'child_process',
  install: installProcessHooks,
  uninstall: uninstallProcessHooks,
  replaced: PROCESS_APIS.map((key) => ({ owner: cp, key })),
  outer: { owner: cp, key: 'execSync' },
  trigger: () => cp.execSync('echo ok; echo rasp-test'),
  inputs: [req('ok; echo rasp-test')],
  detector: { module: detect, name: 'detectCommand' },
  attack: 'command_injection',
});

let dir = '';
describeHookContract({
  name: 'fs',
  install: installFsHooks,
  uninstall: uninstallFsHooks,
  replaced: ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'openSync', 'rename'].map((key) => ({ owner: fs, key })),
  outer: { owner: fs, key: 'readFileSync' },
  trigger: () => fs.readFileSync(`${dir}/child/../escape.txt`, 'utf8'),
  inputs: [req('../escape.txt')],
  detector: { module: detect, name: 'detectPath' },
  attack: 'path_traversal',
  beforeEach: () => {
    dir = fs.mkdtempSync(join(tmpdir(), 'rasp-kit-'));
    fs.mkdirSync(join(dir, 'child'));
    fs.writeFileSync(join(dir, 'escape.txt'), 'fixture');
  },
  afterEach: () => fs.rmSync(dir, { recursive: true, force: true }),
});

// Nothing listens on the discard port, and the request is destroyed at once.
const local = 'http://127.0.0.1:9/fixture';
describeHookContract({
  name: 'outbound http',
  install: () => installHttpHooks({ alwaysAllowedHosts: [] }),
  uninstall: uninstallHttpHooks,
  replaced: [
    { owner: http, key: 'request' },
    { owner: http, key: 'get' },
  ],
  trigger: () => {
    const r = http.request(local);
    r.on('error', () => undefined);
    r.destroy();
  },
  inputs: [req(local)],
  detector: { module: detect, name: 'detectSsrf' },
  attack: 'ssrf',
});

const input = "' OR '1'='1";
class FakeClient {
  query(...values: unknown[]): unknown {
    return values.length;
  }
}
const pg = { Client: FakeClient };
describeHookContract({
  name: 'database (pg)',
  install: () => {
    patchPg(pg);
    return true;
  },
  uninstall: () => unpatchPg(pg),
  replaced: [{ owner: FakeClient.prototype, key: 'query' }],
  trigger: () => new FakeClient().query(`SELECT * FROM products WHERE name = '${input}'`),
  inputs: [req(input)],
  detector: { module: detect, name: 'detectSql' },
  attack: 'sql_injection',
});

describeHookContract({
  name: 'code',
  install: installCodeHooks,
  uninstall: uninstallCodeHooks,
  replaced: [
    ...['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'Script'].map((key) => ({ owner: vm, key })),
    { owner: globalThis, key: 'Function' },
  ],
  added: ['write', 'end'].map((key) => ({ owner: http.ServerResponse.prototype, key })),
  outer: { owner: vm, key: 'runInNewContext' },
  trigger: () => vm.runInNewContext('1 + 2'),
  inputs: [req('1 + 2')],
  detector: { module: detect, name: 'detectCode' },
  attack: 'code_injection',
});

// Template engines: stand-ins shaped like each engine's exports (the engines are optional dependencies).
const templateEngines: [TemplateEngine, string[], string][] = [
  ['handlebars', ['compile', 'precompile'], '{{name}}'],
  ['ejs', ['render', 'compile'], '<%= 1 + 2 %>'],
  ['pug', ['compile', 'render', 'compileClient'], '#{1 + 2}'],
  ['nunjucks', ['renderString'], '{{ 1 + 2 }}'],
  ['lodash', ['template'], '<%= 1 + 2 %>'],
];
for (const [engine, keys, source] of templateEngines) {
  const exports: Record<string, (...a: unknown[]) => unknown> = {};
  for (const key of keys) {
    // Named, with an arity, so the kit can see both survive.
    exports[key] = { [key]: function (text: unknown, data?: unknown) { return [text, data]; } }[key];
  }
  describeHookContract({
    name: `template (${engine})`,
    install: () => {
      patchTemplate(engine, exports);
      return true;
    },
    uninstall: () => unpatchTemplate(exports),
    replaced: keys.map((key) => ({ owner: exports, key })),
    trigger: () => exports[keys[0]](`Hello ${source}`, { name: 'data' }),
    inputs: [req(source)],
    detector: { module: template, name: 'detectTemplate' },
    attack: 'code_injection',
  });
}

// The real Handlebars, when present: the singleton and the compiler module its create() instances call.
let handlebars: { compile: (s: string) => unknown } | undefined;
let compiler: object | undefined;
try {
  handlebars = require('handlebars');
  compiler = require('handlebars/dist/cjs/handlebars/compiler/compiler');
} catch {
  handlebars = undefined;
}
if (handlebars && compiler) {
  const hb = handlebars;
  const internal = compiler;
  describeHookContract({
    name: 'template (real handlebars)',
    install: () => {
      patchTemplate('handlebars', hb);
      patchHandlebarsCompiler(internal);
      return true;
    },
    uninstall: () => {
      unpatchTemplate(hb);
      unpatchTemplate(internal);
    },
    replaced: [
      ...['compile', 'precompile'].map((key) => ({ owner: hb, key })),
      ...['compile', 'precompile'].map((key) => ({ owner: internal, key })),
    ],
    trigger: () => hb.compile('Hello {{name}}'),
    inputs: [req('{{name}}')],
    detector: { module: template, name: 'detectTemplate' },
    attack: 'code_injection',
  });
}

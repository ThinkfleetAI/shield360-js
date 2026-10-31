/**
 * code.include: the detector on its own, and the require hook through the
 * shared hook contract. The trigger loads a temporary fixture module through
 * Node's own loader (Jest's require is its own), so running it is harmless.
 */
import { spawnSync } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import * as detect from '../detect';
import { detectInclude } from '../detect';
import { installIncludeHooks, uninstallIncludeHooks } from '../hooks/include';
import type { RaspInput } from '../types';
import { describeHookContract } from './hook-kit';

const req = (value: string): RaspInput => ({ value, key: 'query.q', source: 'request' });

describe('detectInclude', () => {
  it.each([
    ['a module name taken whole from input', 'plugins-report', [req('plugins-report')]],
    ['a path from input inside the specifier', './plugins/../../srv/data/x.js', [req('../../srv/data/x.js')]],
    ['an absolute path from input', '/srv/app/uploads/handler.js', [req('/srv/app/uploads/handler.js')]],
    ['a NUL byte from input', 'plugins/report\u0000.js', [req('report\u0000.js')]],
    ['a model-output path', './tools/../secret.js', [{ value: '../secret.js', key: 'model.output', source: 'model_output' } as RaspInput]],
  ])('flags %s', (_label, specifier, inputs) => {
    expect(detectInclude(specifier, inputs)?.rule).toBe('code.include');
  });

  it.each([
    ['a fixed module name', 'express', [req('report')]],
    ['the app\'s own relative module with no input in it', './routes/orders', [req('orders-2026')]],
    ['a plain word from input inside a fixed name', './locales/en', [req('en')]],
    ['a word of three or more characters that is not a path', './views/orders', [req('orders')]],
    ['no inputs', '/srv/app/x.js', []],
  ])('passes %s', (_label, specifier, inputs) => {
    expect(detectInclude(specifier, inputs)).toBeNull();
  });
});

// Under Jest, `Module.prototype` is Jest's own and has no require of Node's to wrap,
// so the contract runs against a stand-in; the real loader is tested in a child Node process below.
class StandIn {
  require(id: string): unknown {
    return id.length;
  }
}
const standIn = StandIn.prototype as unknown as { require: (id: string) => unknown };
const fixture = '/srv/app/plugins/../uploads/handler.js';

describeHookContract({
  name: 'module require',
  install: () => installIncludeHooks(standIn),
  uninstall: uninstallIncludeHooks,
  replaced: [{ owner: standIn, key: 'require' }],
  trigger: () => standIn.require(fixture),
  inputs: [req('../uploads/handler.js')],
  detector: { module: detect, name: 'detectInclude' },
  attack: 'code_injection',
});

describe('on Node\'s own loader (child process)', () => {
  it('blocks a require of a path from input, loads it in monitor, and uninstall restores Node\'s require', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rasp-include-'));
    const fixturePath = join(dir, 'fixture.js');
    writeFileSync(fixturePath, 'module.exports = 41 + 1;\n');
    const src = join(__dirname, '..');
    const script = [
      "const Module = require('module');",
      "const original = Module.prototype.require;",
      `const { configureEngine } = require(${JSON.stringify(join(src, 'engine'))});`,
      `const { runWithInputs } = require(${JSON.stringify(join(src, 'context'))});`,
      `const { installIncludeHooks, uninstallIncludeHooks } = require(${JSON.stringify(join(src, 'hooks', 'include'))});`,
      `const file = ${JSON.stringify(fixturePath)};`,
      "const inputs = [{ value: file, key: 'query.q', source: 'request' }];",
      "const out = { installed: installIncludeHooks() };",
      "configureEngine({ enabled: true, applicationName: 'a', mode: 'block', env: {} });",
      "try { runWithInputs(inputs, () => Module.createRequire(file)(file), { inRequest: true }); out.blocked = false; } catch (e) { out.blocked = e && e.name === 'RaspBlockedError'; }",
      "configureEngine({ enabled: true, applicationName: 'a', mode: 'monitor', env: {} });",
      "out.loaded = runWithInputs(inputs, () => Module.createRequire(file)(file), { inRequest: true });",
      "uninstallIncludeHooks();",
      "out.restored = Module.prototype.require === original;",
      "process.stdout.write(JSON.stringify(out));",
    ].join('\n');
    try {
      const run = spawnSync(process.execPath, ['-r', 'ts-node/register/transpile-only', '-e', script], { cwd: join(__dirname, '..', '..', '..'), encoding: 'utf8' });
      expect(run.stderr).toBe('');
      expect(JSON.parse(run.stdout)).toEqual({ installed: true, blocked: true, loaded: 42, restored: true });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60000);
});

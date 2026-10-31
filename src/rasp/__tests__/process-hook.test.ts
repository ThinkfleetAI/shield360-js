/**
 * child_process hook: every process API is checked before the process
 * starts, a block never reaches the original function, failures let the call
 * through, and uninstall restores the module exactly. Drafted with ChatGPT,
 * adapted to the engine. Only harmless commands run here (node -e exit, echo).
 */
import cp = require('child_process');
import nodeModule = require('module');
import { promisify } from 'util';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { detectProcess, installProcessHooks, PROCESS_APIS, processTarget, uninstallProcessHooks, type ProcessApi } from '../hooks/process';
import { RaspBlockedError, type AttackType, type RaspInput, type RaspMode } from '../types';

const node = process.execPath;
const argv = ['-e', 'process.exit(0)'];
const nodeLine = `"${node}" -e "process.exit(0)"`;
const req = (value: string): RaspInput => ({ value, key: 'query.q', source: 'request' });
const inRequest = <T>(inputs: RaspInput[], fn: () => T): T => runWithInputs(inputs, fn, { inRequest: true });

const events: any[] = [];
function setMode(mode: RaspMode, attacks: Partial<Record<AttackType, RaspMode>> = {}, commands: string[] = []) {
  configureEngine({ enabled: true, applicationName: 'orders-api', mode, attacks, allow: { commands }, env: {} });
  setEventSink({ add: (e) => events.push(e) });
}
const originals = new Map(PROCESS_APIS.map((api) => [api, Object.getOwnPropertyDescriptor(cp, api)!]));
const call = (api: ProcessApi, values: unknown[]): unknown => Reflect.apply(cp[api] as (...a: unknown[]) => unknown, cp, values);

beforeEach(() => {
  events.length = 0;
  setMode('block');
});
afterEach(() => {
  uninstallProcessHooks();
  jest.restoreAllMocks();
});
afterAll(() => {
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

describe('processTarget', () => {
  it.each([
    ['exec', [nodeLine], { command: nodeLine }],
    ['execSync', [nodeLine, {}], { command: nodeLine }],
    ['spawn', [node], { argv: [node] }],
    ['spawn', [node, argv, {}], { argv: [node, ...argv] }],
    ['spawnSync', [node, {}], { argv: [node] }],
    ['execFile', [node, argv, () => undefined], { argv: [node, ...argv] }],
    ['execFileSync', [node, argv], { argv: [node, ...argv] }],
    ['spawn', [node, argv, { shell: true }], { command: `${node} -e process.exit(0)` }],
    ['execFile', [node, argv, { shell: '/bin/sh' }], { command: `${node} -e process.exit(0)` }],
    ['spawn', [node, argv, { shell: false }], { argv: [node, ...argv] }],
    ['fork', ['./worker.js', ['a']], { argv: [node, './worker.js', 'a'] }],
    ['fork', ['./worker.js', { shell: true }], { argv: [node, './worker.js'] }],
    ['fork', ['./worker.js', [], { execPath: '/bin/sh' }], { argv: ['/bin/sh', './worker.js'] }],
  ] as [ProcessApi, unknown[], unknown][])('%s %j', (api, values, expected) => {
    expect(processTarget(api, values)).toEqual(expected);
  });

  it('leaves arguments Node would refuse to Node', () => {
    expect(processTarget('spawnSync', [null])).toBeNull();
    expect(processTarget('exec', [42])).toBeNull();
    expect(processTarget('spawn', [node, [1, 2]])).toBeNull();
  });

  it('copies the caller argv', () => {
    const args = [...argv];
    const t = processTarget('spawn', [node, args]) as { argv: string[] };
    t.argv.push('extra');
    expect(args).toEqual(argv);
  });
});

describe('detectProcess', () => {
  it('checks a shell command line for injection', () => {
    expect(detectProcess({ command: 'echo ok; echo rasp-test' }, [req('ok; echo rasp-test')], true, [])?.rule).toBe('cmdi.userinput');
  });

  it('checks the script of sh -c', () => {
    expect(detectProcess({ argv: ['sh', '-c', 'echo ok; echo rasp-test'] }, [req('ok; echo rasp-test')], false, [])?.rule).toBe('cmdi.userinput');
  });

  it('flags an executable taken from the request', () => {
    expect(detectProcess({ argv: ['uptime'] }, [req('uptime')], true, [])?.rule).toBe('cmdi.executable');
  });

  it('flags a shell started during a request unless allowed', () => {
    expect(detectProcess({ argv: ['/bin/bash', '--version'] }, [], true, [])?.rule).toBe('shell_spawn.shell');
    expect(detectProcess({ argv: ['/bin/bash', '--version'] }, [], true, ['bash'])).toBeNull();
    expect(detectProcess({ argv: ['/bin/bash', '--version'] }, [], false, [])).toBeNull();
  });

  it('flags a download piped to a shell at any time', () => {
    expect(detectProcess({ command: 'curl -s https://example.invalid/i | sh' }, [], false, [])?.rule).toBe('shell_spawn.download_exec');
  });

  it('passes a fixed command with unrelated input', () => {
    expect(detectProcess({ command: nodeLine }, [req('report.pdf')], true, [])).toBeNull();
    expect(detectProcess({ argv: [node, ...argv] }, [req('report.pdf')], true, [])).toBeNull();
  });
});

describe('installed hook', () => {
  const injected = { exec: ['echo ok; echo rasp-test'], execSync: ['echo ok; echo rasp-test'] } as const;

  it.each(['exec', 'execSync'] as const)('%s: block never invokes the original', (api) => {
    const original = jest.spyOn(cp, api);
    installProcessHooks();
    const err = inRequest([req('ok; echo rasp-test')], () => {
      try {
        call(api, [...injected[api]]);
      } catch (e) {
        return e;
      }
    });
    expect(err).toBeInstanceOf(RaspBlockedError);
    expect((err as RaspBlockedError).rule).toBe('cmdi.userinput');
    expect(original).not.toHaveBeenCalled();
    expect(events[0].attrs['shield360.rasp.sink']).toBe(`child_process.${api}`);
    expect(events[0].attrs['shield360.rasp.decision']).toBe('blocked');
  });

  it.each(['spawn', 'spawnSync', 'execFile', 'execFileSync'] as const)('%s: a shell spawned in a request is blocked', (api) => {
    const original = jest.spyOn(cp, api);
    installProcessHooks();
    expect(() => inRequest([], () => call(api, ['/bin/sh', ['-c', 'exit 0']]))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });

  it('fork: a shell as execPath is blocked in a request', () => {
    const original = jest.spyOn(cp, 'fork');
    installProcessHooks();
    expect(() => inRequest([], () => cp.fork('./worker.js', [], { execPath: '/bin/sh' }))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });

  it('monitor reports and lets the process run', () => {
    setMode('monitor');
    installProcessHooks();
    const out = inRequest([req('ok; echo rasp-test')], () => cp.execSync('echo ok; echo rasp-test').toString());
    expect(out).toBe('ok\nrasp-test\n');
    expect(events).toHaveLength(1);
    expect(events[0].attrs['shield360.rasp.decision']).toBe('monitored');
  });

  it('runs harmless processes in and out of requests', () => {
    installProcessHooks();
    expect(cp.spawnSync(node, argv).status).toBe(0);
    expect(inRequest([req('report.pdf')], () => cp.spawnSync(node, argv).status)).toBe(0);
    expect(events).toHaveLength(0);
  });

  it('honours allow.commands', () => {
    setMode('block', {}, ['sh']);
    installProcessHooks();
    expect(inRequest([], () => cp.spawnSync('/bin/sh', ['-c', 'exit 0']).status)).toBe(0);
  });

  it('does nothing while RASP is off', () => {
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    installProcessHooks();
    expect(inRequest([req('ok; echo rasp-test')], () => cp.execSync('echo ok; echo rasp-test').toString())).toBe('ok\nrasp-test\n');
    expect(events).toHaveLength(0);
  });

  it('an attack type set to off is not checked', () => {
    setMode('block', { shell_spawn: 'off' });
    installProcessHooks();
    expect(inRequest([], () => cp.spawnSync('/bin/sh', ['-c', 'exit 0']).status)).toBe(0);
  });

  it('leaves invalid arguments to Node', () => {
    installProcessHooks();
    // Node's own error (from Node's realm, so matched by message, not class).
    expect(() => call('spawnSync', [null])).toThrow(/"file" argument must be of type string/);
    expect(events).toHaveLength(0);
  });

  it('promisify(exec) keeps output and child, and cannot skip the check', async () => {
    installProcessHooks();
    const pending = promisify(cp.exec)(nodeLine);
    expect(pending.child).toBeDefined();
    await expect(pending).resolves.toEqual({ stdout: '', stderr: '' });

    uninstallProcessHooks();
    const original = jest.spyOn(cp, 'exec');
    installProcessHooks();
    await expect(inRequest([req('ok; echo rasp-test')], () => promisify(cp.exec)('echo ok; echo rasp-test'))).rejects.toBeInstanceOf(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });
});

describe('several findings for one call', () => {
  // Both fire: the input spans tokens (command_injection) and the command starts a shell (shell_spawn).
  const line = 'bash -c true ok; echo rasp-test';

  it.each(['off', 'monitor'] as const)('a command injection set to %s does not hide a shell_spawn block', (cmdi) => {
    setMode('block', { command_injection: cmdi, shell_spawn: 'block' });
    const original = jest.spyOn(cp, 'execSync');
    installProcessHooks();
    const err = inRequest([req('ok; echo rasp-test')], () => {
      try {
        cp.execSync(line);
      } catch (e) {
        return e;
      }
    });
    expect(err).toBeInstanceOf(RaspBlockedError);
    expect((err as RaspBlockedError).rule).toBe('shell_spawn.shell');
    expect(original).not.toHaveBeenCalled();
    expect(events.map((e) => [e.attrs['shield360.rasp.attack'], e.attrs['shield360.rasp.decision']])).toEqual([['shell_spawn', 'blocked']]);
  });

  it('ties keep the contract order', () => {
    setMode('block');
    installProcessHooks();
    expect(() => inRequest([req('ok; echo rasp-test')], () => cp.execSync(line))).toThrow(expect.objectContaining({ rule: 'cmdi.userinput' }));
  });
});

describe('install and uninstall', () => {
  it('is idempotent and restores the module exactly', () => {
    installProcessHooks();
    const wrapper = cp.spawn;
    installProcessHooks();
    expect(cp.spawn).toBe(wrapper);
    for (const api of PROCESS_APIS) {
      const original = originals.get(api)!.value;
      expect(cp[api]).not.toBe(original);
      expect(cp[api].name).toBe(original.name);
      expect(cp[api].length).toBe(original.length);
    }
    uninstallProcessHooks();
    uninstallProcessHooks();
    for (const api of PROCESS_APIS) expect(Object.getOwnPropertyDescriptor(cp, api)).toEqual(originals.get(api));
  });

  it('carries the change to ESM named bindings on install and uninstall', () => {
    // Jest cannot load native ESM here; the effect on an ESM import is checked in the next test's child process.
    const sync = jest.spyOn(nodeModule, 'syncBuiltinESMExports');
    installProcessHooks();
    expect(sync).toHaveBeenCalledTimes(1);
    uninstallProcessHooks();
    expect(sync).toHaveBeenCalledTimes(2);
  });

  it('an ESM import sees the wrapper', () => {
    // A separate Node process (started before install, so unchecked) runs the
    // same install steps on a native ESM namespace.
    const script = [
      "import * as ns from 'node:child_process';",
      "import { createRequire, syncBuiltinESMExports } from 'node:module';",
      "const cp = createRequire(import.meta.url)('child_process');",
      'const before = ns.spawn;',
      "Object.defineProperty(cp, 'spawn', { ...Object.getOwnPropertyDescriptor(cp, 'spawn'), value: function spawn() {} });",
      'syncBuiltinESMExports();',
      'process.exit(ns.spawn === cp.spawn && ns.spawn !== before ? 0 : 1);',
    ].join('\n');
    expect(cp.spawnSync(node, ['--input-type=module', '-e', script]).status).toBe(0);
  });
});

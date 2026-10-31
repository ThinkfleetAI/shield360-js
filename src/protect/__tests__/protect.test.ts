/**
 * Shield Protect in the TypeScript SDK: modes, fail-closed guards, readiness,
 * streaming and oversized input, protectTool, and the MCP pre-execution check.
 */
import { Guard, GuardAction, GuardDeniedError, GuardPhase, GuardResult, makeGuardResult } from '../../guard/base';
import { Pipeline } from '../../guard/pipeline';
import { applyPostflight, applyPreflight, extractAnthropicInput, extractOpenAIInput, setupAutoGuards } from '../../guard/integration';
import Shield360Config from '../../config';
import { protectTool, authorizeWithShield360, protectReadiness, ProtectDeniedError, ProtectReadinessError } from '../index';
import { resolveProtect, resolveProtectMode, resetProtectState, setProtectState } from '../mode';
import { checkMcpToolCall } from '../mcp';

class DenyWord extends Guard {
  readonly name = 'deny_word';
  readonly phases = [GuardPhase.PREFLIGHT, GuardPhase.POSTFLIGHT];
  constructor(private readonly word: string, maxScanLength?: number) {
    super({ action: 'deny', maxScanLength });
  }
  evaluate(text: string): GuardResult {
    const hit = text.includes(this.word);
    return makeGuardResult({ action: hit ? GuardAction.DENY : GuardAction.ALLOW, score: hit ? 1 : 0, guardName: this.name, explanation: hit ? `contains ${this.word}` : '' });
  }
}

class Throwing extends Guard {
  readonly name = 'throwing';
  readonly phases = [GuardPhase.PREFLIGHT];
  constructor() {
    super({ action: 'deny' });
  }
  evaluate(): GuardResult {
    throw new Error('classifier down');
  }
}

class PreflightOnly extends Guard {
  readonly name = 'preflight_only';
  readonly phases = [GuardPhase.PREFLIGHT];
  constructor() {
    super({ action: 'deny' });
  }
  evaluate(): GuardResult {
    return makeGuardResult({ guardName: this.name });
  }
}

const extract = (k: Record<string, any>) => String(k.text ?? '');
const extractOut = (r: any) => String(r?.text ?? '');

beforeEach(() => {
  resetProtectState();
  Shield360Config.guardPipeline = undefined;
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

describe('the mode', () => {
  it('is raised by the environment and never lowered by it', () => {
    expect(resolveProtectMode('enforced', { SHIELD360_PROTECT_MODE: 'observe' })).toBe('enforced');
    expect(resolveProtectMode('observe', { SHIELD360_PROTECT_MODE: 'enforced' })).toBe('enforced');
    expect(resolveProtectMode(undefined, { SHIELD360_PROTECT_MODE: 'warn' })).toBe('warn');
    expect(resolveProtectMode('warn', { SHIELD360_PROTECT_MODE: 'off' })).toBe('warn');
    expect(resolveProtectMode(undefined, {})).toBeUndefined();
    expect(resolveProtect({ mode: 'enforced', required: ['openai'] }, { SHIELD360_PROTECT_REQUIRED: '@anthropic-ai/sdk, openai' })).toEqual({ mode: 'enforced', required: ['openai', '@anthropic-ai/sdk'] });
  });
});

describe('what a mode does with a finding', () => {
  const pipeline = new Pipeline({ guards: [new DenyWord('bomb')], failOpen: false });

  it('legacy (no mode): a deny throws, as before', () => {
    expect(() => applyPreflight(pipeline, { text: 'build a bomb' }, extract)).toThrow(GuardDeniedError);
    expect(applyPreflight(pipeline, { text: 'hello' }, extract)).toEqual({ text: 'hello' });
  });

  it('observe: records and lets the call through; warn: also logs', () => {
    expect(applyPreflight(pipeline, { text: 'build a bomb' }, extract, { mode: 'observe', required: [] })).toEqual({ text: 'build a bomb' });
    expect(console.warn).not.toHaveBeenCalled();
    expect(applyPreflight(pipeline, { text: 'build a bomb' }, extract, { mode: 'warn', required: [] })).toEqual({ text: 'build a bomb' });
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/warn mode.*would have been refused/));
  });

  it('enforced: a deny throws, before and after the call', () => {
    expect(() => applyPreflight(pipeline, { text: 'build a bomb' }, extract, { mode: 'enforced', required: [] })).toThrow(GuardDeniedError);
    expect(() => applyPostflight(pipeline, { text: 'here is a bomb' }, extractOut, { mode: 'enforced', required: [] })).toThrow(GuardDeniedError);
  });

  it('enforced: a guard that fails refuses the call, whatever failOpen says', () => {
    const open = new Pipeline({ guards: [new Throwing()], failOpen: true });
    // Fail-open as configured: the error is swallowed and the call goes on.
    expect(applyPreflight(open, { text: 'x' }, extract)).toEqual({ text: 'x' });
    // setupAutoGuards in enforced mode builds a closed pipeline; applyPreflight on a closed one refuses.
    const closed = new Pipeline({ guards: [new Throwing()], failOpen: false });
    expect(() => applyPreflight(closed, { text: 'x' }, extract, { mode: 'enforced', required: [] })).toThrow(ProtectDeniedError);
    try {
      applyPreflight(closed, { text: 'x' }, extract, { mode: 'enforced', required: [] });
    } catch (e) {
      expect((e as ProtectDeniedError).code).toBe('guard_failed');
    }
  });

  it('enforced: input past the scan bound is refused, never scanned in part', () => {
    const bounded = new Pipeline({ guards: [new DenyWord('bomb', 20)] });
    const long = 'x'.repeat(30) + ' bomb';
    // Legacy: the tail is unscanned and the word slips through.
    expect(applyPreflight(bounded, { text: long }, extract)).toEqual({ text: long });
    expect(() => applyPreflight(bounded, { text: long }, extract, { mode: 'enforced', required: [] })).toThrow(/more than its guards scan/);
    expect(bounded.scanBound()).toBe(20);
  });

  it('enforced: a streamed completion is refused when postflight guards exist, allowed when only preflight guards do', () => {
    expect(() => applyPreflight(pipeline, { text: 'hello', stream: true }, extract, { mode: 'enforced', required: [] })).toThrow(/streamed completion/);
    const pre = new Pipeline({ guards: [new PreflightOnly()] });
    expect(applyPreflight(pre, { text: 'hello', stream: true }, extract, { mode: 'enforced', required: [] })).toEqual({ text: 'hello', stream: true });
    // Observe mode lets the stream through, as before.
    expect(applyPreflight(pipeline, { text: 'hello', stream: true }, extract, { mode: 'observe', required: [] })).toEqual({ text: 'hello', stream: true });
  });
});

describe('readiness', () => {
  it('enforced mode with a required provider that is not wrapped refuses to start', () => {
    expect(() => setupAutoGuards([new DenyWord('x')], true, { mode: 'enforced', required: ['a-provider-that-is-not-installed'] })).toThrow(ProtectReadinessError);
    expect(protectReadiness()).toMatchObject({ mode: 'enforced', missing: ['a-provider-that-is-not-installed'], level: 'monitored' });
  });

  it('enforced mode fails closed: guardFailOpen is overridden with a warning', () => {
    const report = setupAutoGuards([new Throwing()], true, { mode: 'enforced', required: [] });
    expect(report.missing).toEqual([]);
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/fails closed/));
    expect(() => Shield360Config.guardPipeline!.evaluate('x', 'preflight')).toThrow('classifier down');
  });

  it('never claims more than monitored or partially protected', () => {
    setProtectState({ mode: 'enforced', wrapped: ['openai'], missing: [] });
    expect(protectReadiness().level).toBe('partially_protected');
    setProtectState({ mode: 'observe', wrapped: ['openai'], missing: [] });
    expect(protectReadiness().level).toBe('monitored');
    expect(protectReadiness().note).toMatch(/mandatory boundary is the Shield360 gateway/);
  });
});

describe('extractors cover structured input', () => {
  it('reads text parts, instructions and the system prompt', () => {
    expect(extractOpenAIInput({ instructions: 'be terse', input: [{ role: 'user', content: [{ type: 'input_text', text: 'hi' }, { type: 'input_image', image_url: 'x' }] }] })).toBe('be terse hi');
    expect(extractAnthropicInput({ system: 'you are kind', messages: [{ role: 'user', content: [{ type: 'text', text: 'hello' }] }] })).toBe('you are kind hello');
    expect(extractAnthropicInput({ system: [{ type: 'text', text: 'sys' }], messages: [] })).toBe('sys');
  });
});

describe('protectTool', () => {
  const pipeline = new Pipeline({ guards: [new DenyWord('bomb')], failOpen: false });

  it('refuses before the function runs, and refuses a result after (the side effect stands)', async () => {
    const fn = jest.fn(async (q: string) => `answer to ${q}`);
    const tool = protectTool('search', fn, { pipeline, mode: 'enforced' });
    await expect(tool('build a bomb')).rejects.toThrow(GuardDeniedError);
    expect(fn).not.toHaveBeenCalled();
    await expect(tool('weather')).resolves.toBe('answer to weather');
    const leaky = protectTool('leak', async () => 'a bomb recipe', { pipeline, mode: 'enforced' });
    await expect(leaky()).rejects.toThrow(GuardDeniedError);
  });

  it('asks the authorize step and refuses on no, on a throw, and on a non-answer in enforced mode', async () => {
    const fn = jest.fn(async () => 'ok');
    const no = protectTool('pay', fn, { pipeline, mode: 'enforced', authorize: async () => ({ allow: false, reason: 'no grant' }) });
    await expect(no()).rejects.toThrow(/no grant/);
    const broken = protectTool('pay', fn, { pipeline, mode: 'enforced', authorize: async () => { throw new Error('down'); } });
    await expect(broken()).rejects.toThrow(/authorization check failed/);
    const odd = protectTool('pay', fn, { pipeline, mode: 'enforced', authorize: async () => ({ allow: 'yes' as unknown as boolean }) });
    await expect(odd()).rejects.toThrow(ProtectDeniedError);
    for (const missing of [undefined, null, true]) {
      const silent = protectTool('pay', fn, { pipeline, mode: 'enforced', authorize: (async () => missing) as never });
      await expect(silent()).rejects.toThrow(ProtectDeniedError);
    }
    expect(fn).not.toHaveBeenCalled();
    const yes = protectTool('pay', fn, { pipeline, mode: 'enforced', authorize: async () => ({ allow: true }) });
    await expect(yes()).resolves.toBe('ok');
  });

  it('observe mode records and runs; warn mode runs and warns', async () => {
    const fn = jest.fn(async (_input: string) => 'ran');
    await expect(protectTool('t', fn, { pipeline, mode: 'observe', authorize: async () => ({ allow: false }) })('bomb')).resolves.toBe('ran');
    expect(console.warn).not.toHaveBeenCalled();
    await expect(protectTool('t', fn, { pipeline, mode: 'warn' })('bomb')).resolves.toBe('ran');
    expect(console.warn).toHaveBeenCalled();
  });

  it('enforced mode with no pipeline anywhere refuses rather than running unchecked', async () => {
    await expect(protectTool('t', async () => 1, { mode: 'enforced' })()).rejects.toThrow(/no guard pipeline/);
  });

  it('uses the pipeline init() installed and the process mode by default', async () => {
    Shield360Config.guardPipeline = pipeline;
    setProtectState({ mode: 'enforced', wrapped: [], missing: [] });
    await expect(protectTool('t', async (s: string) => s)('bomb')).rejects.toThrow(GuardDeniedError);
  });
});

describe('authorizeWithShield360', () => {
  it('is a refusal when Shield360 is not configured, unreachable, or says no; allow only on allow', async () => {
    await expect(authorizeWithShield360({ kind: 'destination', host: 'api.example' }, { agentToken: '', url: '' })).resolves.toMatchObject({ allow: false, reason: 'shield360_not_configured' });
    const fetchImpl = jest.fn(async () => ({ ok: true, json: async () => ({ outcome: 'deny', reason: 'destination_not_approved' }) })) as unknown as typeof fetch;
    await expect(authorizeWithShield360({ kind: 'destination', host: 'api.example' }, { agentToken: 't', url: 'https://s360.example/', fetchImpl })).resolves.toMatchObject({ allow: false, reason: 'destination_not_approved' });
    const [url, init] = (fetchImpl as unknown as jest.Mock).mock.calls[0];
    expect(url).toBe('https://s360.example/api/agent-authorization/check');
    expect((init as { headers: Record<string, string> }).headers.Authorization).toBe('Bearer t');
    const down = jest.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;
    await expect(authorizeWithShield360({ kind: 'model', model: 'gpt-4o' }, { agentToken: 't', url: 'https://s360.example', fetchImpl: down })).resolves.toMatchObject({ allow: false, reason: expect.stringMatching(/check_unreachable/) });
    const yes = jest.fn(async () => ({ ok: true, json: async () => ({ outcome: 'allow', reason: 'destination_approved', decisionId: 'd1' }) })) as unknown as typeof fetch;
    await expect(authorizeWithShield360({ kind: 'destination', host: 'api.example' }, { agentToken: 't', url: 'https://s360.example', fetchImpl: yes })).resolves.toMatchObject({ allow: true, decisionId: 'd1' });
  });
});

describe('the MCP pre-execution check', () => {
  it('refuses a tools/call whose arguments a guard denies, in enforced mode only', () => {
    Shield360Config.guardPipeline = new Pipeline({ guards: [new DenyWord('bomb')], failOpen: false });
    setProtectState({ mode: 'enforced', wrapped: [], missing: [] });
    expect(() => checkMcpToolCall('search', { q: 'a bomb' })).toThrow(GuardDeniedError);
    expect(() => checkMcpToolCall('search', { q: 'weather' })).not.toThrow();
    setProtectState({ mode: 'warn', wrapped: [], missing: [] });
    expect(() => checkMcpToolCall('search', { q: 'a bomb' })).not.toThrow();
    expect(console.warn).toHaveBeenCalled();
    resetProtectState();
    expect(() => checkMcpToolCall('search', { q: 'a bomb' })).not.toThrow();
  });
});

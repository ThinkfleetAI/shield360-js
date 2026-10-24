import { isWrapped } from '@opentelemetry/instrumentation';
import AnthropicInstrumentation from '../anthropic';
import AnthropicWrapper from '../anthropic/wrapper';

/**
 * Which of the Anthropic SDK's Messages resources get patched.
 *
 * The SDK has two: `client.messages` and `client.beta.messages`. They are
 * separate classes, not a subclass and its parent, and the beta one is what
 * the SDK's own tool runner calls. For a long time only the stable class was
 * wrapped, so an agent built on `client.beta.messages.toolRunner` — the
 * documented way to run tools — emitted no spans and reported zero cost while
 * looking fully instrumented. That is the failure this file guards against.
 *
 * The SDK is not a dependency here, so the module is a stand-in with the same
 * shape: a client class carrying `Messages` and `Beta.Messages` as statics,
 * each with `create` on its prototype.
 */

function fakeAnthropicModule(options: { withBeta?: boolean } = {}) {
  const { withBeta = true } = options;

  class Messages {
    async create(_params: any) {
      return { id: 'msg', usage: { input_tokens: 1, output_tokens: 1 } };
    }
  }
  class BetaMessages {
    async create(_params: any) {
      return { id: 'beta-msg', usage: { input_tokens: 1, output_tokens: 1 } };
    }
  }
  class Beta {
    static Messages = BetaMessages;
  }
  class Anthropic {
    static Messages = Messages;
    static Beta = withBeta ? Beta : undefined;
  }
  return { Anthropic } as any;
}

describe('Shield360AnthropicInstrumentation', () => {
  it('wraps create on both the stable and the beta Messages resources', () => {
    const mod = fakeAnthropicModule();
    new AnthropicInstrumentation().manualPatch(mod);

    expect(isWrapped(mod.Anthropic.Messages.prototype.create)).toBe(true);
    expect(isWrapped(mod.Anthropic.Beta.Messages.prototype.create)).toBe(true);
  });

  it('names the beta resource as its own endpoint, so the two are told apart', () => {
    const spy = jest.spyOn(AnthropicWrapper, '_patchMessageCreate');
    new AnthropicInstrumentation().manualPatch(fakeAnthropicModule());

    const endpoints = spy.mock.calls.map((call) => call[1]);
    expect(endpoints).toContain('anthropic.resources.messages');
    expect(endpoints).toContain('anthropic.resources.beta.messages');
    spy.mockRestore();
  });

  it('still patches an SDK too old to have a Beta namespace', () => {
    const mod = fakeAnthropicModule({ withBeta: false });
    expect(() => new AnthropicInstrumentation().manualPatch(mod)).not.toThrow();
    expect(isWrapped(mod.Anthropic.Messages.prototype.create)).toBe(true);
  });

  it('patches once, however many times it is asked', () => {
    const mod = fakeAnthropicModule();
    const instrumentation = new AnthropicInstrumentation();
    instrumentation.manualPatch(mod);
    instrumentation.manualPatch(mod);

    // A double wrap would produce a span per layer for one request.
    const wrapped = mod.Anthropic.Beta.Messages.prototype.create;
    expect(isWrapped(wrapped)).toBe(true);
    expect(isWrapped((wrapped as any).__original)).toBe(false);
  });

  it('unpatches both resources, leaving the originals callable', async () => {
    const mod = fakeAnthropicModule();
    const instrumentation = new AnthropicInstrumentation();
    instrumentation.manualPatch(mod);
    (instrumentation as any)._unpatch(mod);

    expect(isWrapped(mod.Anthropic.Messages.prototype.create)).toBe(false);
    expect(isWrapped(mod.Anthropic.Beta.Messages.prototype.create)).toBe(false);
    await expect(new mod.Anthropic.Beta.Messages().create({})).resolves.toMatchObject({
      id: 'beta-msg',
    });
  });
});

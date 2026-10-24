import { trace } from '@opentelemetry/api';
import AnthropicWrapper from '../anthropic/wrapper';
import Shield360Helper from '../../helpers';
import Shield360Config from '../../config';

// SHIELD: `create` must hand back the Anthropic SDK's APIPromise, not a plain
// Promise. The SDK's own helpers — `messages.stream()` and
// `beta.messages.toolRunner({ stream: true })` — call `.withResponse()` on it;
// an async wrapper broke them with "withResponse is not a function".

/** The parts of the Anthropic SDK's APIPromise the wrapper relies on. */
class FakeAPIPromise<T> extends Promise<T> {
  static parses = 0;
  private parsed?: Promise<T>;

  static make<T>(response: Promise<{ ok: boolean }>, parse: () => Promise<T>): FakeAPIPromise<T> {
    const p = new FakeAPIPromise<T>(() => {});
    p.response = response;
    p.parser = parse;
    return p;
  }

  response!: Promise<{ ok: boolean }>;
  parser!: () => Promise<T>;

  static get [Symbol.species]() {
    return Promise;
  }

  private parse(): Promise<T> {
    if (!this.parsed) {
      FakeAPIPromise.parses += 1;
      this.parsed = this.response.then(() => this.parser());
    }
    return this.parsed;
  }

  _thenUnwrap(transform: (data: T) => unknown): FakeAPIPromise<unknown> {
    return FakeAPIPromise.make<unknown>(this.response, async () => transform(await this.parser()));
  }

  asResponse() {
    return this.response;
  }

  async withResponse() {
    const [data, response] = await Promise.all([this.parse(), this.asResponse()]);
    return { data, response };
  }

  override then<A = T, B = never>(ok?: ((v: T) => A | PromiseLike<A>) | null, no?: ((e: any) => B | PromiseLike<B>) | null) {
    return this.parse().then(ok, no);
  }
}

const message = {
  id: 'msg_1',
  model: 'claude-opus-5',
  stop_reason: 'end_turn',
  content: [{ type: 'text', text: 'ok' }],
  usage: { input_tokens: 10, output_tokens: 5 },
};

function wrap(create: (...args: any[]) => any) {
  const tracer = trace.getTracer('test');
  return AnthropicWrapper._patchMessageCreate(tracer, 'anthropic.resources.beta.messages')(create);
}

describe('Anthropic create keeps the SDK APIPromise', () => {
  beforeAll(() => {
    Shield360Config.applicationName = 'test-app';
    Shield360Config.environment = 'test';
    Shield360Config.captureMessageContent = false;
  });

  beforeEach(() => {
    FakeAPIPromise.parses = 0;
    jest.restoreAllMocks();
  });

  it('returns something with withResponse, and the parsed message through it', async () => {
    const create = jest.fn(() => FakeAPIPromise.make(Promise.resolve({ ok: true }), async () => message));
    const result = wrap(create).call({}, { model: 'claude-opus-5', messages: [] });

    expect(typeof result.withResponse).toBe('function');
    const { data, response } = await result.withResponse();
    expect(data).toMatchObject({ id: 'msg_1', usage: { input_tokens: 10 } });
    expect(response.ok).toBe(true);
  });

  it('is still awaitable directly, as ordinary calls use it', async () => {
    const create = jest.fn(() => FakeAPIPromise.make(Promise.resolve({ ok: true }), async () => message));
    await expect(wrap(create).call({}, { model: 'claude-opus-5', messages: [] })).resolves.toMatchObject({ id: 'msg_1' });
  });

  it('never parses the original response, so the body is read once', async () => {
    const create = jest.fn(() => FakeAPIPromise.make(Promise.resolve({ ok: true }), async () => message));
    await wrap(create).call({}, { model: 'claude-opus-5', messages: [] });
    expect(FakeAPIPromise.parses).toBe(1);
  });

  it('passes a failed request to the caller and records it on the span', async () => {
    const handle = jest.spyOn(Shield360Helper, 'handleException');
    const error = Object.assign(new Error('400 bad model'), { status: 400 });
    const failed = Promise.reject(error);
    failed.catch(() => undefined);
    const create = jest.fn(() => FakeAPIPromise.make(failed, async () => message));

    await expect(wrap(create).call({}, { model: 'bad-model', messages: [] })).rejects.toThrow('400 bad model');
    expect(handle).toHaveBeenCalledWith(expect.anything(), error);
  });

  it('still works with a client that returns a plain promise', async () => {
    const create = jest.fn(async () => message);
    await expect(wrap(create).call({}, { model: 'claude-opus-5', messages: [] })).resolves.toMatchObject({ id: 'msg_1' });
  });
});

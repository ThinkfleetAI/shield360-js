import { trace, TraceFlags } from '@opentelemetry/api';
import Shield360Config from '../../config';
import { configureFeedback, feedback, getCurrentSpanId, getCurrentTraceId } from '..';

const TRACE = '0af7651916cd43dd8448eb211c80319c';
const SPAN = 'b7ad6b7169203331';

describe('feedback', () => {
  const fetchMock = jest.fn();
  const realFetch = global.fetch;

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({ ok: true });
    (global as any).fetch = fetchMock;
    Shield360Config.shield360Url = 'https://shield360.example/';
    Shield360Config.shield360ApiKey = 'key-1';
    Shield360Config.applicationName = 'checkout';
    configureFeedback({ app: 'checkout', release: '2.0.0' });
  });

  afterAll(() => {
    (global as any).fetch = realFetch;
  });

  it('posts the rating with the key, naming the app and release', async () => {
    await expect(
      feedback({ traceId: TRACE.toUpperCase(), spanId: SPAN, score: -1, comment: 'wrong', userId: 'u-1', metadata: { plan: 'pro' } })
    ).resolves.toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://shield360.example/api/feedback');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer key-1');
    expect(JSON.parse(init.body)).toEqual({
      traceId: TRACE,
      spanId: SPAN,
      score: -1,
      comment: 'wrong',
      userId: 'u-1',
      metadata: { plan: 'pro' },
      app: 'checkout',
      release: '2.0.0',
    });
  });

  it('defaults to the active trace', async () => {
    const active = jest
      .spyOn(trace, 'getActiveSpan')
      .mockReturnValue(trace.wrapSpanContext({ traceId: TRACE, spanId: SPAN, traceFlags: TraceFlags.SAMPLED }));
    expect(getCurrentTraceId()).toBe(TRACE);
    expect(getCurrentSpanId()).toBe(SPAN);
    await expect(feedback({ score: 5 })).resolves.toBe(true);
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).traceId).toBe(TRACE);
    active.mockReturnValue(undefined);
    expect(getCurrentTraceId()).toBeUndefined();
    active.mockRestore();
  });

  it('never throws: bad input, no trace, no key, a refusal or a network error are false', async () => {
    await expect(feedback({ score: 1 })).resolves.toBe(false);
    await expect(feedback({ traceId: 'nope', score: 1 })).resolves.toBe(false);
    await expect(feedback({ traceId: TRACE, score: 0 })).resolves.toBe(false);
    await expect(feedback({ traceId: TRACE, score: 3, scale: 'thumbs' })).resolves.toBe(false);
    await expect(feedback({ traceId: TRACE, spanId: 'x', score: 1 })).resolves.toBe(false);
    await expect(feedback(undefined as any)).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();

    Shield360Config.shield360ApiKey = undefined;
    const saved = process.env.SHIELD360_API_KEY;
    delete process.env.SHIELD360_API_KEY;
    await expect(feedback({ traceId: TRACE, score: 1 })).resolves.toBe(false);
    if (saved !== undefined) process.env.SHIELD360_API_KEY = saved;
    Shield360Config.shield360ApiKey = 'key-1';

    fetchMock.mockResolvedValueOnce({ ok: false, status: 400 });
    await expect(feedback({ traceId: TRACE, score: 1 })).resolves.toBe(false);
    fetchMock.mockRejectedValueOnce(new Error('offline'));
    await expect(feedback({ traceId: TRACE, score: 1 })).resolves.toBe(false);
  });

  it('sends the star scale when asked, so one star is not a thumbs up', async () => {
    await feedback({ traceId: TRACE, score: 1, scale: 'stars' });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({ score: 1, scale: 'stars' });
  });
});

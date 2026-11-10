/**
 * SHIELD: security event trace ids — RASP and AI security events carry the
 * request's W3C trace and span, so the console's replay opens that trace; a
 * folded or merged repeat (several requests) carries none.
 */
import { trace } from '@opentelemetry/api';
import { traceAttrs, withoutTrace } from '../trace-context';
import { RaspReporter, RASP_EVENT, FOLD_MS } from '../rasp/reporter';

const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const SPAN = '00f067aa0ba902b7';

const inSpan = () =>
  jest.spyOn(trace, 'getActiveSpan').mockReturnValue(trace.wrapSpanContext({ traceId: TRACE, spanId: SPAN, traceFlags: 1 }));

afterEach(() => jest.restoreAllMocks());

describe('traceAttrs', () => {
  it('names the active span under the prefix', () => {
    inSpan();
    expect(traceAttrs('shield360.rasp.')).toEqual({ 'shield360.rasp.trace_id': TRACE, 'shield360.rasp.span_id': SPAN });
  });

  it('is empty outside a span or with an invalid one', () => {
    jest.spyOn(trace, 'getActiveSpan').mockReturnValue(undefined);
    expect(traceAttrs('shield360.rasp.')).toEqual({});
    jest.spyOn(trace, 'getActiveSpan').mockReturnValue(trace.wrapSpanContext({ traceId: '0'.repeat(32), spanId: '0'.repeat(16), traceFlags: 0 }));
    expect(traceAttrs('shield360.rasp.')).toEqual({});
  });

  it('withoutTrace drops only the ids', () => {
    expect(withoutTrace({ a: '1', 'p.trace_id': TRACE, 'p.span_id': SPAN }, 'p.')).toEqual({ a: '1' });
  });
});

describe('RaspReporter', () => {
  const event = () => ({ name: RASP_EVENT, time: new Date(0).toISOString(), attrs: { 'shield360.rasp.event_id': 'a'.repeat(32) } as Record<string, string> });

  it('attaches the trace of the request the event happened in', () => {
    inSpan();
    const r = new RaspReporter({ url: 'https://example.test', apiKey: 'k', applicationName: 'shop', now: () => 1_000 } as never);
    r.add(event(), 'k1');
    expect(r.pending()[0].attrs).toMatchObject({ 'shield360.rasp.trace_id': TRACE, 'shield360.rasp.span_id': SPAN });
  });

  it('sends a folded repeat without a trace', () => {
    inSpan();
    let now = 1_000;
    const r = new RaspReporter({ url: 'https://example.test', apiKey: 'k', applicationName: 'shop', now: () => now } as never);
    r.add(event(), 'k1');
    r.add(event(), 'k1');
    now += FOLD_MS + 1;
    r.add({ ...event(), attrs: { 'shield360.rasp.event_id': 'b'.repeat(32) } }, 'k2');
    const fold = r.pending().find((e) => e.attrs['shield360.rasp.count']);
    expect(fold).toBeDefined();
    expect(fold!.attrs['shield360.rasp.trace_id']).toBeUndefined();
  });
});

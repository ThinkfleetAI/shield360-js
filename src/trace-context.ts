import { isSpanContextValid, trace } from '@opentelemetry/api';

/**
 * SHIELD: security event trace ids — the W3C trace and span of the request
 * this code runs in, as attributes under `prefix` (`shield360.rasp.` or
 * `shield360.ai_security.`), so the console's replay opens the event's own
 * trace. Empty outside a span, or when tracing is not set up. Ids only.
 */
export function traceAttrs(prefix: string): Record<string, string> {
  try {
    const context = trace.getActiveSpan()?.spanContext();
    if (!context || !isSpanContextValid(context)) return {};
    return { [`${prefix}trace_id`]: context.traceId, [`${prefix}span_id`]: context.spanId };
  } catch {
    return {};
  }
}

/** The same attributes without the trace: a folded repeat stands for several requests, not one. */
export function withoutTrace<T extends Record<string, unknown>>(attrs: T, prefix: string): T {
  const out = { ...attrs };
  delete out[`${prefix}trace_id`];
  delete out[`${prefix}span_id`];
  return out;
}

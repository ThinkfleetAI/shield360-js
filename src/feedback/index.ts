import { trace } from '@opentelemetry/api';
import Shield360Config from '../config';

/**
 * User feedback: what one of your application's users thought of an AI
 * response, sent to Shield360 (`POST /api/feedback`) against the trace that
 * produced it.
 *
 * Call it from your server, with the environment's API key — never from a
 * browser. It never throws: anything wrong (no trace, no URL or key, a bad
 * score, the network) resolves to `false`.
 *
 * Shield360 keeps the score, ids, application and release. The comment is
 * kept only when your organisation's Data retention setting stores end users'
 * free text (with secrets and personal data masked); `userId` and `tenantId`
 * are kept only as a keyed hash.
 */

export type FeedbackScale = 'thumbs' | 'stars';

export interface FeedbackOptions {
  /** The trace rated. Defaults to the active span's trace. */
  traceId?: string;
  /** The span rated, when it was one call in the trace. */
  spanId?: string;
  /** 1 or -1 (thumbs), or 1 to 5 (stars; pass `scale: 'stars'` for a one-star rating). */
  score: number;
  scale?: FeedbackScale;
  comment?: string;
  /** Your end user's id. Stored only as a keyed hash. */
  userId?: string;
  /** Your end user's tenant or account. Stored only as a keyed hash. */
  tenantId?: string;
  metadata?: Record<string, string | number | boolean>;
  /** Your own id for this rating: sending it again replaces the earlier rating. */
  feedbackId?: string;
  /** Defaults to the URL and key `init` was given, then SHIELD360_URL / SHIELD360_API_KEY. */
  url?: string;
  apiKey?: string;
  /** Default 5000. */
  timeoutMs?: number;
}

const TRACE_ID = /^[0-9a-f]{32}$/i;
const SPAN_ID = /^[0-9a-f]{16}$/i;
const INVALID_TRACE = '0'.repeat(32);

let defaults: { app?: string; release?: string } = {};

/** Set by `init`: the application and release every rating names. */
export function configureFeedback(values: { app?: string; release?: string }): void {
  defaults = { ...values };
}

/** The active span's trace id, or undefined outside a trace. */
export function getCurrentTraceId(): string | undefined {
  try {
    const id = trace.getActiveSpan()?.spanContext().traceId;
    return id && TRACE_ID.test(id) && id !== INVALID_TRACE ? id : undefined;
  } catch {
    return undefined;
  }
}

/** The active span's id, or undefined outside a trace. */
export function getCurrentSpanId(): string | undefined {
  try {
    const id = trace.getActiveSpan()?.spanContext().spanId;
    return id && SPAN_ID.test(id) && id !== '0'.repeat(16) ? id : undefined;
  } catch {
    return undefined;
  }
}

function validScore(score: unknown, scale?: FeedbackScale): boolean {
  if (typeof score !== 'number' || !Number.isInteger(score)) return false;
  if (scale === 'thumbs') return score === 1 || score === -1;
  if (scale === 'stars') return score >= 1 && score <= 5;
  return score === -1 || (score >= 1 && score <= 5);
}

/** Sends one rating. Resolves to whether Shield360 accepted it; never rejects. */
export async function feedback(options: FeedbackOptions): Promise<boolean> {
  try {
    if (!options || typeof options !== 'object') return false;
    const traceId = (options.traceId || getCurrentTraceId() || '').toLowerCase();
    if (!TRACE_ID.test(traceId) || traceId === INVALID_TRACE) return false;
    if (options.spanId && !SPAN_ID.test(options.spanId)) return false;
    if (!validScore(options.score, options.scale)) return false;

    const url = (options.url || Shield360Config.shield360Url || process.env.SHIELD360_URL || '').trim().replace(/\/+$/, '');
    const apiKey = (options.apiKey || Shield360Config.shield360ApiKey || process.env.SHIELD360_API_KEY || '').trim();
    if (!url || !apiKey) return false;

    const body: Record<string, unknown> = {
      traceId,
      score: options.score,
      ...(options.spanId ? { spanId: options.spanId.toLowerCase() } : {}),
      ...(options.scale ? { scale: options.scale } : {}),
      ...(options.comment ? { comment: options.comment } : {}),
      ...(options.userId ? { userId: options.userId } : {}),
      ...(options.tenantId ? { tenantId: options.tenantId } : {}),
      ...(options.metadata ? { metadata: options.metadata } : {}),
      ...(options.feedbackId ? { feedbackId: options.feedbackId } : {}),
      ...(defaults.app || Shield360Config.applicationName ? { app: defaults.app || Shield360Config.applicationName } : {}),
      ...(defaults.release ? { release: defaults.release } : {}),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
    try {
      const response = await fetch(`${url}/api/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      return response.ok;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return false;
  }
}

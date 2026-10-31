/**
 * Sends check results to the receiver project's inbound decision log
 * (POST /api/inbound-agents/decisions, at most 100 per call). Queued and sent
 * off the request path; a batch that cannot be delivered is retried a few
 * times and then dropped with a warning. Never the passport, headers or bodies.
 */

import { baseUrlOf } from './policy';
import { AgentCheck, Shield360Connection } from './types';

export const REPORT_BATCH = 100;
const FLUSH_MS = 3000;
const MAX_QUEUED = 5000;
const ATTEMPTS = 3;
const TIMEOUT_MS = 10_000;

export type ReportedDecision = AgentCheck & { at: string; route?: string; method?: string; receiver?: string };

export class DecisionReporter {
  private readonly queue: ReportedDecision[] = [];
  private readonly endpoint: string;
  private timer: ReturnType<typeof setInterval> | undefined;
  private sending: Promise<void> = Promise.resolve();
  private warnedFull = false;

  constructor(
    private readonly conn: Shield360Connection,
    private readonly fetchImpl: () => typeof fetch,
    private readonly retryDelayMs = 500,
  ) {
    this.endpoint = `${baseUrlOf(conn)}/api/inbound-agents/decisions`;
  }

  add(decision: ReportedDecision): void {
    if (this.queue.length >= MAX_QUEUED) {
      if (!this.warnedFull) console.warn('Shield360 agents: the decision report queue is full; reports are being dropped');
      this.warnedFull = true;
      return;
    }
    this.warnedFull = false;
    this.queue.push(decision);
    if (!this.timer) {
      this.timer = setInterval(() => void this.flush(), FLUSH_MS);
      // Never keep a process alive just to report.
      (this.timer as { unref?: () => void }).unref?.();
    }
    if (this.queue.length >= REPORT_BATCH) void this.flush();
  }

  /** Sends everything queued; resolves when it has been tried. Never rejects. */
  flush(): Promise<void> {
    this.sending = this.sending
      .then(async () => {
        while (this.queue.length) await this.post(this.queue.splice(0, REPORT_BATCH));
      })
      .catch(() => undefined);
    return this.sending;
  }

  close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    return this.flush();
  }

  private async post(batch: ReportedDecision[]): Promise<void> {
    const body = JSON.stringify({ decisions: batch });
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
      const t = controller ? setTimeout(() => controller.abort(), TIMEOUT_MS) : undefined;
      (t as { unref?: () => void } | undefined)?.unref?.();
      try {
        const res = await this.fetchImpl()(this.endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.conn.apiKey}` },
          body,
          signal: controller?.signal,
        });
        if (res.ok) return;
        if ([400, 401, 403, 404, 413].includes(res.status)) {
          console.warn(`Shield360 agents: the inbound decision log refused ${batch.length} report(s): HTTP ${res.status}`);
          return;
        }
      } catch {
        // retried below
      } finally {
        if (t) clearTimeout(t);
      }
      if (attempt < ATTEMPTS - 1) await new Promise((r) => setTimeout(r, this.retryDelayMs * (attempt + 1)));
    }
    console.warn(`Shield360 agents: could not deliver ${batch.length} decision report(s); dropped`);
  }
}

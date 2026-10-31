/**
 * AI security events: what a check found and what it did, sent to Shield360
 * (POST /api/ai-security/events) in batches off the call path.
 *
 * An event carries the check, the kind of finding, the mode and the action
 * taken, the app, the end customer (tenant and user ids as given: the
 * platform keeps user ids only as a keyed hash) and per finding a kind, a
 * masked token and a keyed fingerprint. Never the text that was checked.
 *
 * A batch that cannot be delivered is retried a few times and dropped; the
 * decision was already taken. Repeated identical events (same check, kind,
 * tool and customer) inside a few seconds are counted into one.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_events.py
 */

import { randomUUID } from 'crypto';
import { hostname } from 'os';
import { getCustomer } from '../customer';

export const AI_SECURITY_EVENT = 'shield360.ai_security.event';

export type AiSecurityCheck =
  | 'indirect_injection'
  | 'jailbreak'
  | 'output'
  | 'tool_permission'
  | 'limits'
  | 'mcp'
  | 'rag'
  /** The SDK's own state, e.g. no pinned config key. */
  | 'config';

export type AiSecurityAction = 'reported' | 'stripped' | 'redacted' | 'dropped' | 'blocked' | 'denied' | 'allowed';

/** Output findings: kind, token, fingerprint. Injection findings: rule, category, masked snippet, fingerprint. */
export type EventFinding = { kind?: string; masked?: string; fingerprint?: string; rule?: string; category?: string; snippet?: string };

export type AiSecurityEvent = {
  check: AiSecurityCheck;
  /** What was found: injection, jailbreak, pii, secret, custom_kind, cross_tenant, exfil_link, system_prompt_leak, canary_leak, tool_denied, rate_limited, mcp_unknown_server, mcp_unknown_tool, mcp_tool_changed, mcp_tool_poisoned, rag_cross_tenant, rag_hub. */
  kind: string;
  mode: 'monitor' | 'enforce';
  action: AiSecurityAction;
  /** Where the text came from: prompt, tool_result, document, context, file, output, tool_description. */
  source?: string;
  score?: number;
  rules?: string[];
  categories?: string[];
  rulesVersion?: string;
  tool?: string;
  server?: string;
  /** A short, already-masked description (rule snippets, hashes); never content. */
  detail?: string;
  findings?: EventFinding[];
  count?: number;
};

const BATCH = 100;
const FLUSH_MS = 2000;
const MAX_QUEUED = 5000;
const ATTEMPTS = 3;
const DEDUPE_MS = 5000;
const MAX_DETAIL = 1000;

type Wire = { name: string; time: string; attrs: Record<string, string | number | boolean> };

export interface EventSink {
  add(event: AiSecurityEvent): void;
  flush(): Promise<void>;
  close(): Promise<void>;
}

type Pending = { wire: Wire; key: string; at: number };

export class EventReporter implements EventSink {
  private queue: Pending[] = [];
  private readonly recent = new Map<string, Pending>();
  private readonly timer: ReturnType<typeof setInterval>;
  private sending: Promise<void> = Promise.resolve();

  constructor(
    private readonly endpoint: string,
    private readonly apiKey: string,
    private readonly app: string,
    private readonly environment: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    this.timer = setInterval(() => void this.flush(), FLUSH_MS);
    this.timer.unref?.();
  }

  add(event: AiSecurityEvent): void {
    try {
      const customer = getCustomer();
      const key = [event.check, event.kind, event.action, event.tool || '', event.server || '', customer?.tenantId || '', customer?.userId || ''].join('|');
      const at = this.now();
      const seen = this.recent.get(key);
      if (seen && at - seen.at < DEDUPE_MS && this.queue.includes(seen)) {
        seen.wire.attrs['shield360.ai_security.count'] = Number(seen.wire.attrs['shield360.ai_security.count'] || 1) + (event.count || 1);
        return;
      }
      if (this.queue.length >= MAX_QUEUED) return;
      const attrs: Record<string, string | number | boolean> = {
        'shield360.ai_security.event_id': randomUUID().replace(/-/g, ''),
        'shield360.ai_security.app': this.app,
        'shield360.ai_security.check': event.check,
        'shield360.ai_security.kind': event.kind,
        'shield360.ai_security.mode': event.mode,
        'shield360.ai_security.action': event.action,
        'shield360.ai_security.count': event.count || 1,
      };
      const put = (k: string, v: unknown) => {
        if (v === undefined || v === null || v === '') return;
        attrs[`shield360.ai_security.${k}`] = typeof v === 'number' || typeof v === 'boolean' ? v : String(v).slice(0, MAX_DETAIL);
      };
      put('source', event.source);
      if (typeof event.score === 'number') put('score', Math.round(event.score * 1000) / 1000);
      put('rules', event.rules?.join(','));
      put('categories', event.categories?.join(','));
      put('rules_version', event.rulesVersion);
      put('tool', event.tool);
      put('server', event.server);
      put('detail', event.detail);
      if (event.findings?.length) {
        const kept = event.findings.slice(0, 10);
        put('findings', JSON.stringify(kept));
        put('fingerprints', kept.map((f) => f.fingerprint).filter(Boolean).join(','));
      }
      if (customer) {
        attrs['shield360.customer.tenant_id'] = customer.tenantId;
        if (customer.userId) attrs['shield360.customer.user_id'] = customer.userId;
      }
      const pending: Pending = { wire: { name: AI_SECURITY_EVENT, time: new Date(at).toISOString(), attrs }, key, at };
      this.queue.push(pending);
      this.recent.set(key, pending);
      if (this.recent.size > 2000) this.recent.clear();
    } catch {
      // Reporting never breaks a call.
    }
  }

  flush(): Promise<void> {
    this.sending = this.sending.then(async () => {
      while (this.queue.length) {
        const batch = this.queue.splice(0, BATCH);
        await this.post(batch.map((p) => p.wire));
      }
    });
    return this.sending;
  }

  private async post(batch: Wire[]): Promise<void> {
    const body = JSON.stringify({
      resource: { 'host.name': hostname(), 'deployment.environment': this.environment, 'service.name': this.app },
      events: batch,
    });
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      try {
        const res = await this.fetchImpl(this.endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
          body,
        });
        if (res.ok) return;
        if ([400, 401, 403, 413].includes(res.status)) return;
      } catch {
        // retried below
      }
      await new Promise((r) => setTimeout(r, 300 * (attempt + 1)).unref?.());
    }
  }

  close(): Promise<void> {
    clearInterval(this.timer);
    return this.flush();
  }
}

/** Collects events in memory: for tests, and when no Shield360 URL is configured. */
export class MemorySink implements EventSink {
  readonly events: AiSecurityEvent[] = [];
  add(event: AiSecurityEvent): void {
    if (this.events.length < 10_000) this.events.push(event);
  }
  flush(): Promise<void> {
    return Promise.resolve();
  }
  close(): Promise<void> {
    return Promise.resolve();
  }
}

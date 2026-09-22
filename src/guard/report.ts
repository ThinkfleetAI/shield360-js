/**
 * Reports guard decisions to Shield360 as compliance evidence.
 *
 * When `init` is given a Shield360 URL and API key (or SHIELD360_URL /
 * SHIELD360_API_KEY), every guard decision other than allow is sent to
 * `/api/guard/events`: which guard, what it did, the kind of data found, in
 * which app, on which host. Never the text that was checked.
 *
 * With each report go the values found, masked, and fingerprinted with the
 * organisation's key (fetched from `/api/guard/config`), so a reviewer can see
 * the same value recurring. The full value is never sent.
 *
 * Reports are queued and sent in batches off the call path, so a guard adds no
 * network time to the call it protects. A batch that cannot be delivered is
 * retried a few times and then dropped; the decision was already enforced.
 *
 * Must stay in sync with: sdk/python/src/shield360/guard/_report.py
 */

import { randomUUID } from 'crypto';
import { hostname, userInfo } from 'os';
import { completeFinding, Finding, setFingerprintKey } from './findings';

export const EVENT_NAME = 'shield360.guard.decision';
const BATCH = 100;
const FLUSH_MS = 2000;
const MAX_QUEUED = 5000;
const ATTEMPTS = 3;

type ReportedEvent = { name: string; time: string; attrs: Record<string, string>; findings?: Finding[] };

class Reporter {
  private readonly queue: ReportedEvent[] = [];
  private readonly timer: ReturnType<typeof setInterval>;
  private sending: Promise<void> = Promise.resolve();
  /** Settles once the fingerprint key has been fetched (or could not be). */
  keyReady: Promise<void> = Promise.resolve();

  constructor(
    private readonly endpoint: string,
    private readonly apiKey: string,
    private readonly resource: Record<string, string>,
    readonly applicationName: string,
  ) {
    this.timer = setInterval(() => void this.flush(), FLUSH_MS);
    // Never keep a process alive just to report.
    this.timer.unref?.();
  }

  add(event: ReportedEvent): void {
    if (this.queue.length >= MAX_QUEUED) {
      console.warn('Shield360 guard report queue is full; a report was dropped');
      return;
    }
    this.queue.push(event);
  }

  /** Sends everything queued; resolves when it has been tried. */
  flush(): Promise<void> {
    this.sending = this.sending.then(async () => {
      await this.keyReady;
      while (this.queue.length) await this.post(this.queue.splice(0, BATCH).map(serialise));
    });
    return this.sending;
  }

  private async post(batch: ReportedEvent[]): Promise<void> {
    const body = JSON.stringify({ resource: this.resource, events: batch });
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      try {
        const res = await fetch(this.endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
          body,
        });
        if (res.ok) return;
        if ([400, 401, 403, 413].includes(res.status)) {
          console.warn(`Shield360 rejected guard reports: HTTP ${res.status}`);
          return;
        }
      } catch {
        // retried below
      }
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
    console.warn(`Could not deliver ${batch.length} guard report(s) to Shield360`);
  }

  close(): Promise<void> {
    clearInterval(this.timer);
    return this.flush();
  }
}

/** Findings go out fingerprinted if the key has arrived since they were made. */
function serialise(event: ReportedEvent): ReportedEvent {
  const { findings, ...rest } = event;
  if (!findings?.length) return rest;
  const done = findings.map(completeFinding);
  return {
    ...rest,
    attrs: {
      ...rest.attrs,
      'shield360.guard.findings': JSON.stringify(done),
      'shield360.guard.fingerprints': done.map((f) => f.fingerprint).filter(Boolean).join(','),
    },
  };
}

let reporter: Reporter | null = null;

/** Starts reporting when both a URL and a key are given. Returns whether it did. */
export function configureGuardReports(opts: {
  url?: string;
  apiKey?: string;
  applicationName: string;
  environment: string;
  sdkVersion?: string;
}): boolean {
  if (!opts.url || !opts.apiKey) return false;
  let user = '';
  try {
    user = userInfo().username;
  } catch {
    // no user in some containers
  }
  const resource: Record<string, string> = {};
  for (const [k, v] of Object.entries({
    'host.name': hostname(),
    'user.name': user,
    'deployment.environment': opts.environment,
    'service.version': opts.sdkVersion || '',
  })) {
    if (v) resource[k] = v;
  }
  void reporter?.close();
  const base = opts.url.replace(/\/+$/, '');
  reporter = new Reporter(`${base}/api/guard/events`, opts.apiKey, resource, opts.applicationName);
  reporter.keyReady = fetchFingerprintKey(base, opts.apiKey);
  return true;
}

/** The organisation's fingerprint key; without it findings are masked only. */
async function fetchFingerprintKey(base: string, apiKey: string): Promise<void> {
  try {
    const res = await fetch(`${base}/api/guard/config`, { headers: { Authorization: `Bearer ${apiKey}` } });
    if (!res.ok) return;
    const body = (await res.json()) as { fingerprintKey?: unknown };
    if (typeof body.fingerprintKey === 'string' && body.fingerprintKey) setFingerprintKey(body.fingerprintKey);
  } catch {
    // masked only
  }
}

/** Queues one decision. Allow decisions are not evidence of anything. */
export function reportGuardDecision(
  guardName: string,
  action: string,
  classification: string,
  phase: string,
  findings: Finding[] = [],
): void {
  if (!reporter || action === 'allow') return;
  const kept = findings.slice(0, 10);
  const kinds = (classification || '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean)
    .join(',');
  reporter.add({
    name: EVENT_NAME,
    time: new Date().toISOString(),
    attrs: {
      'shield360.guard.event_id': randomUUID().replace(/-/g, ''),
      'shield360.guard.client': reporter.applicationName,
      'shield360.guard.action': action,
      'shield360.guard.target': phase,
      'shield360.guard.kinds': kinds,
      'shield360.guard.name': guardName,
    },
    findings: kept,
  });
}

/** Sends everything queued now (tests, and short-lived scripts). */
export function flushGuardReports(): Promise<void> {
  return reporter ? reporter.flush() : Promise.resolve();
}

/** Stops reporting; for tests. */
export async function resetGuardReports(): Promise<void> {
  await reporter?.close();
  reporter = null;
}

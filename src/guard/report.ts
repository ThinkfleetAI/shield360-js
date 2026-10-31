/**
 * Reports guard decisions to Shield360 as compliance evidence.
 *
 * When `init` is given a Shield360 URL and API key (or SHIELD360_URL /
 * SHIELD360_API_KEY), every guard decision other than allow is sent to
 * `/api/guard/events`: which guard, what it did, the kind of data found, in
 * which app (its service name, as its telemetry reports it), on which host.
 * Never the text that was checked.
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
import type { Guard } from './base';
import { completeFinding, Finding, setFingerprintKey } from './findings';
import { HEARTBEAT_EVENT_NAME, heartbeatAttrs, heartbeatEnabled, nextDelay } from './heartbeat';

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
    await postGuardEvents(this.endpoint, this.apiKey, { resource: this.resource, events: batch }, { label: 'guard report' });
  }

  private beat: ReturnType<typeof setTimeout> | null = null;

  /** Sends a heartbeat now and then about every five minutes (heartbeat.ts). Never throws. */
  startHeartbeat(guards: readonly Guard[], sdkVersion: string): void {
    const send = () => {
      try {
        this.add({ name: HEARTBEAT_EVENT_NAME, time: new Date().toISOString(), attrs: heartbeatAttrs(guards, this.applicationName, sdkVersion) });
        void this.flush().catch(() => undefined);
      } catch {
        // a heartbeat is never worth an error in the app
      }
      this.beat = setTimeout(send, nextDelay());
      this.beat.unref?.();
    };
    send();
  }

  close(): Promise<void> {
    clearInterval(this.timer);
    if (this.beat) clearTimeout(this.beat);
    this.beat = null;
    return this.flush();
  }
}

export type GuardEventsTransportOptions = {
  /** What the batch is, for the warning when it cannot be delivered. */
  label?: string;
  attempts?: number;
  /** Delay before retry n is retryDelayMs * n. */
  retryDelayMs?: number;
  fetchImpl?: typeof fetch;
};

/**
 * Posts one batch to `/api/guard/events`: the transport guard reports, the
 * heartbeat and runtime-protection (RASP) events share. Retries a few times,
 * gives up on a refusal, and never throws. Resolves to whether it was accepted.
 */
export async function postGuardEvents(
  endpoint: string,
  apiKey: string,
  payload: { resource: Record<string, string>; events: unknown[] },
  options: GuardEventsTransportOptions = {},
): Promise<boolean> {
  const label = options.label ?? 'guard report';
  const attempts = options.attempts ?? ATTEMPTS;
  const delay = options.retryDelayMs ?? 500;
  const send = options.fetchImpl ?? globalThis.fetch;
  if (typeof send !== 'function') return false;
  let body: string;
  try {
    body = JSON.stringify(payload);
  } catch {
    return false;
  }
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const res = await send(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body,
      });
      if (res.ok) return true;
      if ([400, 401, 403, 413].includes(res.status)) {
        console.warn(`Shield360 rejected ${label}s: HTTP ${res.status}`);
        return false;
      }
    } catch {
      // retried below
    }
    if (attempt + 1 < attempts) await new Promise((r) => setTimeout(r, delay * (attempt + 1)));
  }
  console.warn(`Could not deliver ${payload.events.length} ${label}(s) to Shield360`);
  return false;
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
  /** The guards init was given: with them, a heartbeat says which run and in which mode. */
  guards?: readonly Guard[];
  /** False turns the heartbeat off (as does SHIELD360_GUARD_HEARTBEAT=false). */
  heartbeat?: boolean;
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
    // The app, by the service name its telemetry uses (security per app).
    'service.name': opts.applicationName,
  })) {
    if (v) resource[k] = v;
  }
  void reporter?.close();
  const base = opts.url.replace(/\/+$/, '');
  reporter = new Reporter(`${base}/api/guard/events`, opts.apiKey, resource, opts.applicationName);
  reporter.keyReady = fetchFingerprintKey(base, opts.apiKey);
  if (opts.guards?.length && heartbeatEnabled(opts.heartbeat)) reporter.startHeartbeat(opts.guards, opts.sdkVersion || '');
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
      'shield360.guard.app': reporter.applicationName,
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

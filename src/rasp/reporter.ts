/**
 * RASP event reporter (README "Events"). Batches `shield360.rasp.event` and
 * `shield360.rasp.component` records to `POST /api/guard/events` through the
 * guard reporter's transport (guard/report.ts `postGuardEvents`), off the
 * call path. At most 100 events a minute per process; repeats of the same
 * (attack, rule, sink, route, decision) within 10 s fold into one more
 * event carrying `shield360.rasp.count`. Events name locations, never values.
 */
import * as fs from 'fs';
import { hostname } from 'os';
import { join, sep } from 'path';
import { postGuardEvents } from '../guard/report';

export const RASP_EVENT = 'shield360.rasp.event';
export const RASP_COMPONENT = 'shield360.rasp.component';
export const PER_MINUTE = 100;
export const FOLD_MS = 10_000;
const FLUSH_MS = 2000;
const MAX_QUEUED = 1000;
export const MAX_COMPONENTS = 500;
const BATCH = 100;

// Captured at load, before any later file-system hook.
const readFile = fs.readFileSync.bind(fs);

export type RaspEvent = { name: string; time: string; attrs: Record<string, string> };
type Fold = { event: RaspEvent; extra: number; until: number };

export type ReporterOptions = {
  url: string;
  apiKey: string;
  applicationName: string;
  environment?: string;
  sdkVersion?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  retryDelayMs?: number;
};

export class RaspReporter {
  private queue: RaspEvent[] = [];
  private folds = new Map<string, Fold>();
  private windowStart = -Infinity;
  private sentInWindow = 0;
  private timer?: ReturnType<typeof setInterval>;
  private readonly endpoint: string;
  readonly resource: Record<string, string>;
  private readonly now: () => number;
  private sending: Promise<void> = Promise.resolve();

  constructor(private readonly o: ReporterOptions) {
    this.endpoint = `${o.url.replace(/\/+$/, '')}/api/guard/events`;
    this.now = o.now ?? Date.now;
    this.resource = { 'service.name': o.applicationName };
    const host = safeHost();
    if (host) this.resource['host.name'] = host;
    if (o.environment) this.resource['deployment.environment'] = o.environment;
    if (o.sdkVersion) this.resource['service.version'] = o.sdkVersion;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), FLUSH_MS);
    this.timer.unref?.();
  }

  /**
   * Queues an event, folding repeats of the same key. Returns whether it was queued now.
   * An empty `foldKey` never folds: the event is queued or refused and nothing is kept,
   * for callers that count repeats themselves (passive IAST).
   */
  add(event: RaspEvent, foldKey: string): boolean {
    const now = this.now();
    this.closeFolds(now);
    if (!foldKey) return this.enqueue(event, now);
    const f = this.folds.get(foldKey);
    if (f && now < f.until) {
      f.extra++;
      return false;
    }
    this.folds.set(foldKey, { event, extra: 0, until: now + FOLD_MS });
    return this.enqueue(event, now);
  }

  private enqueue(event: RaspEvent, now: number): boolean {
    if (now - this.windowStart >= 60_000) {
      this.windowStart = now;
      this.sentInWindow = 0;
    }
    if (this.sentInWindow >= PER_MINUTE || this.queue.length >= MAX_QUEUED) return false;
    this.sentInWindow++;
    this.queue.push(event);
    return true;
  }

  private closeFolds(now: number): void {
    for (const [k, f] of this.folds) {
      if (now < f.until) continue;
      this.folds.delete(k);
      if (f.extra > 0) {
        const time = new Date(Number.isFinite(now) ? now : this.now()).toISOString();
        this.enqueue({ ...f.event, time, attrs: { ...f.event.attrs, 'shield360.rasp.count': String(f.extra) } }, Number.isFinite(now) ? now : this.now());
      }
    }
  }

  /** Queued events (tests). */
  pending(): RaspEvent[] {
    return [...this.queue];
  }

  /** Sends what is queued; `force` also closes every open fold. Never rejects. */
  flush(force = false): Promise<void> {
    this.sending = this.sending
      .then(async () => {
        this.closeFolds(force ? Infinity : this.now());
        while (this.queue.length) {
          await postGuardEvents(
            this.endpoint,
            this.o.apiKey,
            { resource: this.resource, events: this.queue.splice(0, BATCH) },
            { label: 'runtime protection event', fetchImpl: this.o.fetchImpl, retryDelayMs: this.o.retryDelayMs },
          );
        }
      })
      .catch(() => undefined);
    return this.sending;
  }

  /** Queues the components report: names and versions only, at most 500. */
  reportComponents(components: Component[]): void {
    const time = new Date(this.now()).toISOString();
    for (const c of components.slice(0, MAX_COMPONENTS)) {
      if (this.queue.length >= MAX_QUEUED) break;
      this.queue.push({
        name: RASP_COMPONENT,
        time,
        attrs: {
          'shield360.rasp.app': this.o.applicationName,
          'shield360.rasp.component.ecosystem': c.ecosystem,
          'shield360.rasp.component.name': c.name,
          'shield360.rasp.component.version': c.version,
        },
      });
    }
  }

  stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    return this.flush(true);
  }
}

function safeHost(): string {
  try {
    return hostname();
  } catch {
    return '';
  }
}

export type Component = { ecosystem: string; name: string; version: string };

const PACKAGE = /^[A-Za-z0-9@_][A-Za-z0-9@/._+~-]{0,213}$/;
const VERSION = /^v?[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$/;

function readPackage(dir: string): { name?: string; version?: string } | null {
  try {
    return JSON.parse(readFile(join(dir, 'package.json'), 'utf8')) as { name?: string; version?: string };
  } catch {
    return null;
  }
}

/**
 * The runtime, the app's declared dependencies (resolved from
 * `<cwd>/node_modules`), and every npm package loaded through `require` so
 * far. Names and versions only; at most 500.
 */
export function collectComponents(
  cache: Record<string, unknown> = require.cache as Record<string, unknown>,
  cwd: string = process.cwd(),
): Component[] {
  const out: Component[] = [{ ecosystem: 'runtime', name: 'node', version: process.versions.node }];
  const seen = new Set<string>();
  const push = (name: unknown, version: unknown) => {
    if (typeof name !== 'string' || typeof version !== 'string' || !PACKAGE.test(name) || !VERSION.test(version)) return;
    const id = `${name}@${version}`;
    if (seen.has(id) || out.length >= MAX_COMPONENTS) return;
    seen.add(id);
    out.push({ ecosystem: 'npm', name, version });
  };
  const app = readPackage(cwd) as { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> } | null;
  for (const name of Object.keys({ ...(app?.dependencies || {}), ...(app?.optionalDependencies || {}) })) {
    const pkg = readPackage(join(cwd, 'node_modules', ...name.split('/')));
    if (pkg) push(pkg.name, pkg.version);
  }
  const roots = new Set<string>();
  const marker = `${sep}node_modules${sep}`;
  for (const file of Object.keys(cache)) {
    if (out.length >= MAX_COMPONENTS) break;
    const at = file.lastIndexOf(marker);
    if (at < 0) continue;
    const rest = file.slice(at + marker.length).split(sep);
    if (!rest[0]) continue;
    const name = rest[0].startsWith('@') && rest[1] ? `${rest[0]}/${rest[1]}` : rest[0];
    const root = join(file.slice(0, at + marker.length), ...name.split('/'));
    if (roots.has(root)) continue;
    roots.add(root);
    const pkg = readPackage(root);
    if (pkg) push(pkg.name, pkg.version);
  }
  return out;
}

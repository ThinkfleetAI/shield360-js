/**
 * Server and process metrics, when asked for.
 *
 * The TypeScript twin of Python's `collect_system_metrics`: a few observable
 * gauges sampled each time the SDK's metric reader exports (every 60 s unless
 * OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL says otherwise), so nothing runs
 * between exports except Node's own event-loop delay histogram. They go to the
 * same destination as the spans, under the application's service.name, and
 * Shield360's Infrastructure view reads them by those names:
 *
 *   system.cpu.utilization       host CPU busy, 0..1 (all cores)
 *   system.memory.utilization    host memory in use, 0..1
 *   system.memory.usage          host memory in use, bytes (state=used)
 *   process.cpu.utilization      this process's CPU, 0..1 of one host
 *   process.memory.usage         this process's resident set size, bytes
 *   nodejs.eventloop.delay.p99   event-loop delay, seconds
 *
 * Every gauge carries host.name. Nothing is collected unless it is turned on:
 * `collectSystemMetrics: true` in init(), or SHIELD360_COLLECT_SYSTEM_METRICS=true.
 */
import os from 'os';
import { monitorEventLoopDelay, type IntervalHistogram } from 'perf_hooks';
import type { Meter, ObservableResult } from '@opentelemetry/api';
import { parseBoolEnv } from './utils';

export const SYSTEM_METRIC_NAMES = {
  systemCpu: 'system.cpu.utilization',
  systemMemoryUtilization: 'system.memory.utilization',
  systemMemoryUsage: 'system.memory.usage',
  processCpu: 'process.cpu.utilization',
  processMemory: 'process.memory.usage',
  eventLoopDelay: 'nodejs.eventloop.delay.p99',
} as const;

/** The option, else SHIELD360_COLLECT_SYSTEM_METRICS, else off. */
export function resolveCollectSystemMetrics(option?: boolean): boolean {
  return option ?? parseBoolEnv('SHIELD360_COLLECT_SYSTEM_METRICS') ?? false;
}

type CpuTimes = { idle: number; total: number };

function cpuTimes(): CpuTimes {
  let idle = 0;
  let total = 0;
  for (const cpu of os.cpus()) {
    const t = cpu.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.irq + t.idle;
  }
  return { idle, total };
}

/** Busy share between two samples of all cores' times; null when no time passed. */
export function cpuBusy(before: CpuTimes, after: CpuTimes): number | null {
  const total = after.total - before.total;
  if (total <= 0) return null;
  return Math.min(1, Math.max(0, 1 - (after.idle - before.idle) / total));
}

export type SystemSampler = {
  host(): number | null;
  process(): number | null;
  memory(): { used: number; total: number };
  rss(): number;
  loopDelaySeconds(): number | null;
};

/** Samples from Node itself; each CPU reading is the share since the previous one. */
export function nodeSampler(): SystemSampler & { stop(): void } {
  let lastHost = cpuTimes();
  let lastProcess = { usage: process.cpuUsage(), at: process.hrtime.bigint() };
  let histogram: IntervalHistogram | null = null;
  try {
    histogram = monitorEventLoopDelay({ resolution: 20 });
    histogram.enable();
  } catch {
    histogram = null;
  }
  return {
    host() {
      const now = cpuTimes();
      const busy = cpuBusy(lastHost, now);
      lastHost = now;
      return busy;
    },
    process() {
      const usage = process.cpuUsage();
      const at = process.hrtime.bigint();
      const elapsedMicros = Number(at - lastProcess.at) / 1000;
      const used = usage.user - lastProcess.usage.user + (usage.system - lastProcess.usage.system);
      lastProcess = { usage, at };
      if (elapsedMicros <= 0) return null;
      const cores = Math.max(1, os.cpus().length);
      return Math.min(1, Math.max(0, used / elapsedMicros / cores));
    },
    memory() {
      const total = os.totalmem();
      return { used: total - os.freemem(), total };
    },
    rss() {
      return process.memoryUsage().rss;
    },
    loopDelaySeconds() {
      if (!histogram) return null;
      const p99 = histogram.percentile(99);
      histogram.reset();
      return Number.isFinite(p99) && p99 > 0 ? p99 / 1e9 : null;
    },
    stop() {
      histogram?.disable();
    },
  };
}

let active: { stop(): void } | null = null;

/**
 * Registers the gauges on `meter`. Returns a function that stops sampling.
 * Calling it again replaces the previous registration's sampler.
 */
export function setupSystemMetrics(meter: Meter, sampler: SystemSampler & { stop?(): void } = nodeSampler()): () => void {
  active?.stop();
  const attributes = { 'host.name': os.hostname() };
  const observe = (fn: (result: ObservableResult) => void) => (result: ObservableResult) => {
    try {
      fn(result);
    } catch {
      // A metric never throws into the application.
    }
  };
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.systemCpu, { description: 'Host CPU busy share across all cores', unit: '1' })
    .addCallback(observe((r) => {
      const v = sampler.host();
      if (v !== null) r.observe(v, attributes);
    }));
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.systemMemoryUtilization, { description: 'Host memory in use', unit: '1' })
    .addCallback(observe((r) => {
      const { used, total } = sampler.memory();
      if (total > 0) r.observe(used / total, attributes);
    }));
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.systemMemoryUsage, { description: 'Host memory in use', unit: 'By' })
    .addCallback(observe((r) => r.observe(sampler.memory().used, { ...attributes, state: 'used' })));
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.processCpu, { description: 'This process\'s CPU share of the host', unit: '1' })
    .addCallback(observe((r) => {
      const v = sampler.process();
      if (v !== null) r.observe(v, attributes);
    }));
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.processMemory, { description: 'Resident set size of this process', unit: 'By' })
    .addCallback(observe((r) => r.observe(sampler.rss(), attributes)));
  meter
    .createObservableGauge(SYSTEM_METRIC_NAMES.eventLoopDelay, { description: 'Event-loop delay, 99th percentile since the last export', unit: 's' })
    .addCallback(observe((r) => {
      const v = sampler.loopDelaySeconds();
      if (v !== null) r.observe(v, attributes);
    }));
  const stop = () => sampler.stop?.();
  active = { stop };
  return stop;
}

import { MeterProvider, MetricReader, AggregationTemporality, InstrumentType } from '@opentelemetry/sdk-metrics';
import { cpuBusy, nodeSampler, resolveCollectSystemMetrics, setupSystemMetrics, SYSTEM_METRIC_NAMES } from '../system-metrics';

/**
 * Host and process metrics are opt-in, named the way Shield360's
 * Infrastructure view reads them, and never throw into the application.
 */
class TestReader extends MetricReader {
  constructor() {
    super({ aggregationTemporalitySelector: (_t: InstrumentType) => AggregationTemporality.CUMULATIVE });
  }
  protected async onForceFlush(): Promise<void> {}
  protected async onShutdown(): Promise<void> {}
}

describe('system metrics', () => {
  const originalEnv = process.env;
  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SHIELD360_COLLECT_SYSTEM_METRICS;
  });
  afterAll(() => {
    process.env = originalEnv;
  });

  it('is off unless asked for', () => {
    expect(resolveCollectSystemMetrics()).toBe(false);
    process.env.SHIELD360_COLLECT_SYSTEM_METRICS = 'true';
    expect(resolveCollectSystemMetrics()).toBe(true);
    expect(resolveCollectSystemMetrics(false)).toBe(false);
  });

  it('computes CPU busy from two samples', () => {
    expect(cpuBusy({ idle: 100, total: 200 }, { idle: 150, total: 400 })).toBeCloseTo(0.75);
    expect(cpuBusy({ idle: 1, total: 1 }, { idle: 1, total: 1 })).toBeNull();
  });

  it('exports the gauges with host.name, skipping readings that are not available', async () => {
    const reader = new TestReader();
    const provider = new MeterProvider({ readers: [reader] });
    const sampler = {
      host: () => 0.42,
      process: () => null,
      memory: () => ({ used: 3, total: 4 }),
      rss: () => 123,
      loopDelaySeconds: () => 0.015,
      stop: jest.fn(),
    };
    setupSystemMetrics(provider.getMeter('test'), sampler);
    const { resourceMetrics } = await reader.collect();
    const metrics = resourceMetrics.scopeMetrics.flatMap((s) => s.metrics);
    const value = (name: string) => metrics.find((m) => m.descriptor.name === name)?.dataPoints[0];
    expect(value(SYSTEM_METRIC_NAMES.systemCpu)?.value).toBeCloseTo(0.42);
    expect(value(SYSTEM_METRIC_NAMES.systemMemoryUtilization)?.value).toBeCloseTo(0.75);
    expect(value(SYSTEM_METRIC_NAMES.systemMemoryUsage)?.attributes).toMatchObject({ state: 'used' });
    expect(value(SYSTEM_METRIC_NAMES.processMemory)?.value).toBe(123);
    expect(value(SYSTEM_METRIC_NAMES.eventLoopDelay)?.value).toBeCloseTo(0.015);
    expect(value(SYSTEM_METRIC_NAMES.processCpu)).toBeUndefined();
    expect(value(SYSTEM_METRIC_NAMES.systemCpu)?.attributes['host.name']).toBeTruthy();
    await provider.shutdown();
  });

  it('keeps a failing sampler from throwing', async () => {
    const reader = new TestReader();
    const provider = new MeterProvider({ readers: [reader] });
    const boom = () => {
      throw new Error('no');
    };
    setupSystemMetrics(provider.getMeter('test'), { host: boom, process: boom, memory: boom, rss: boom, loopDelaySeconds: boom } as never);
    await expect(reader.collect()).resolves.toBeDefined();
    await provider.shutdown();
  });

  it('samples Node itself', () => {
    const sampler = nodeSampler();
    expect(sampler.memory().total).toBeGreaterThan(0);
    expect(sampler.rss()).toBeGreaterThan(0);
    sampler.host();
    const busy = sampler.host();
    expect(busy === null || (busy >= 0 && busy <= 1)).toBe(true);
    sampler.stop();
  });
});

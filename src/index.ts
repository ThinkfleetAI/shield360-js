import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_TELEMETRY_SDK_NAME } from '@opentelemetry/semantic-conventions';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';
import { Shield360Options, ResolvedOptions } from './types';
import Tracing from './otel/tracing';
import Events from './otel/events';
import { DEFAULT_APPLICATION_NAME, DEFAULT_ENVIRONMENT, SDK_NAME } from './constant';
import BaseShield360 from './features/base';
import Shield360Config from './config';
import Shield360Helper from './helpers';
import {
  usingAttributes,
  injectAdditionalAttributes,
  setAgentVersion,
  resetAgentVersion,
  runWithAgentVersion,
  getCurrentAgentVersion,
} from './helpers';
import { runEval, runEvalBatch, fetchEvalTypes } from './evals';
import { logScore } from './score';
import { TracedSpan, startTrace, trace as traceManual } from './manual-trace';
import Metrics from './otel/metrics';
import GpuMetricsCollector from './instrumentation/gpu';
import SemanticConvention from './semantic-convention';
import { parseBoolEnv } from './otel/utils';
import { setupAutoGuards } from './guard/integration';
import { configureGuardReports } from './guard/report';
import { PII } from './guard/pii';
import { PromptInjection } from './guard/prompt-injection';
import { Moderation } from './guard/moderation';
import { SensitiveTopic } from './guard/sensitive-topic';
import { TopicRestriction } from './guard/topic-restriction';
import { Schema } from './guard/schema';
import { Custom } from './guard/custom';
import { Pipeline } from './guard/pipeline';
import {
  Guard,
  GuardAction,
  GuardPhase,
  GuardError,
  GuardDeniedError,
  GuardTimeoutError,
  GuardConfigError,
  PipelineResult,
} from './guard/base';

/**
 * Resolve Shield360Options into a single ResolvedOptions object.
 * Precedence: arg > env var > default.
 */
function resolveOptions(options?: Shield360Options): ResolvedOptions {
  const o = options || {};

  const environment = o.environment ?? DEFAULT_ENVIRONMENT;
  const applicationName = o.applicationName ?? DEFAULT_APPLICATION_NAME;

  const rawEndpoint =
    o.otlpEndpoint ??
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT ??
    undefined;

  const otlpEndpoint = rawEndpoint
    ? rawEndpoint.replace(/\/v1\/traces$/, '')
    : undefined;

  let otlpHeaders = o.otlpHeaders ?? undefined;
  if (!otlpHeaders && process.env.OTEL_EXPORTER_OTLP_HEADERS) {
    otlpHeaders = process.env.OTEL_EXPORTER_OTLP_HEADERS.split(',').reduce(
      (acc: Record<string, string>, item: string) => {
        const keyVal = item.split('=');
        acc[keyVal[0]] = keyVal[1];
        return acc;
      },
      {} as Record<string, string>
    );
  }
  if (!otlpHeaders) otlpHeaders = {};

  let disableBatch = o.disableBatch ?? undefined;
  const envDisableBatch = parseBoolEnv('SHIELD360_DISABLE_BATCH');
  if (disableBatch === undefined) {
    disableBatch = envDisableBatch ?? false;
  }

  let captureMessageContent = o.captureMessageContent ?? undefined;
  const envCapture = parseBoolEnv('OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT');
  if (captureMessageContent === undefined) {
    captureMessageContent = envCapture ?? true;
  }

  let disableMetrics = o.disableMetrics ?? undefined;
  const envDisableMetrics = parseBoolEnv('SHIELD360_DISABLE_METRICS');
  if (disableMetrics === undefined) {
    disableMetrics = envDisableMetrics ?? false;
  }

  let disableEvents = o.disableEvents ?? undefined;
  const envDisableEvents = parseBoolEnv('SHIELD360_DISABLE_EVENTS');
  if (disableEvents === undefined) {
    disableEvents = envDisableEvents ?? false;
  }

  let collectGpuStats = o.collectGpuStats ?? undefined;
  const envCollectGpuStats = parseBoolEnv('SHIELD360_COLLECT_GPU_STATS');
  if (collectGpuStats === undefined) {
    collectGpuStats = envCollectGpuStats ?? false;
  }

  const shield360ApiKey = o.shield360ApiKey ?? process.env.SHIELD360_API_KEY ?? undefined;
  const shield360Url = o.shield360Url ?? process.env.SHIELD360_URL ?? undefined;

  return {
    environment,
    applicationName,
    tracer: o.tracer,
    otlpEndpoint,
    otlpHeaders,
    disableBatch,
    captureMessageContent,
    disabledInstrumentors: o.disabledInstrumentors,
    instrumentations: o.instrumentations,
    disableMetrics,
    disableEvents,
    pricingJson: o.pricingJson,
    maxContentLength: o.maxContentLength ?? null,
    customSpanAttributes: o.customSpanAttributes ?? null,
    shield360ApiKey,
    shield360Url,
    guards: o.guards,
    guardFailOpen: o.guardFailOpen ?? true,
    collectGpuStats,
  };
}

class Shield360 extends BaseShield360 {
  static resource: ReturnType<typeof resourceFromAttributes>;
  static options: ResolvedOptions;

  // Top-level guard class exports
  static PII = PII;
  static PromptInjection = PromptInjection;
  static Moderation = Moderation;
  static SensitiveTopic = SensitiveTopic;
  static TopicRestriction = TopicRestriction;
  static Schema = Schema;
  static Custom = Custom;
  static Pipeline = Pipeline;
  static GuardAction = GuardAction;
  static GuardPhase = GuardPhase;
  static GuardError = GuardError;
  static GuardDeniedError = GuardDeniedError;
  static GuardTimeoutError = GuardTimeoutError;
  static GuardConfigError = GuardConfigError;

  static eval = runEval;
  static evalBatch = runEvalBatch;
  static getEvalTypes = fetchEvalTypes;
  static logScore = logScore;

  /**
   * Public API: stamp every subsequent chat span / inference event in the
   * current async scope with a user-supplied agent version label
   * (`gen_ai.agent.version`). Useful when you want versions to follow a
   * release tag, git SHA, or business-meaningful name instead of the SDK's
   * auto-computed fingerprint.
   *
   * For a one-shot block, prefer `Shield360.withAgentVersion(label, fn)`.
   */
  static setAgentVersion = setAgentVersion;
  /**
   * Clear the agent version label set by `setAgentVersion`. Always call this
   * in a `finally` block when you use `setAgentVersion` directly, otherwise
   * the label will persist on subsequent requests handled by the same
   * worker. Prefer `withAgentVersion(label, fn)` for scoped usage.
   */
  static resetAgentVersion = resetAgentVersion;
  static withAgentVersion = runWithAgentVersion;
  static getAgentVersion = getCurrentAgentVersion;

  static startTrace = startTrace;
  static trace = traceManual;

  static init(options?: Shield360Options) {
    try {
      diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.WARN);

      const resolved = resolveOptions(options);
      this.options = resolved;

      this.resource = resourceFromAttributes({
        [ATTR_SERVICE_NAME]: resolved.applicationName,
        [SemanticConvention.ATTR_DEPLOYMENT_ENVIRONMENT]: resolved.environment,
        [ATTR_TELEMETRY_SDK_NAME]: SDK_NAME,
      });

      const setupBase = {
        ...resolved,
        resource: this.resource,
      };

      Tracing.setup(setupBase);

      if (!resolved.disableEvents) {
        Events.setup(setupBase);
      }

      if (!resolved.disableMetrics) {
        const exportIntervalMillis =
          Number(process.env.OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL ?? 60000) || 60000;

        const meter = Metrics.setup({
          ...setupBase,
          exportIntervalMillis,
        });

        // GPU metrics: only register gauges when a supported GPU is detected
        // (mirrors Python shield360.init collect_gpu_stats path).
        if (resolved.collectGpuStats && meter) {
          new GpuMetricsCollector()
            .setup({
              meter,
              environment: resolved.environment,
              applicationName: resolved.applicationName,
            })
            .catch((e) => {
              diag.error(`Shield360 GPU metrics setup failed: ${e}`);
            });
        }
      }

      Shield360Config.shield360ApiKey = resolved.shield360ApiKey;
      Shield360Config.shield360Url = resolved.shield360Url;

      Shield360Helper.fetchPricingInfo(resolved.pricingJson).then(
        (info) => { Shield360Config.pricingInfo = info; },
        () => { Shield360Config.pricingInfo = {}; }
      );

      if (resolved.guards && resolved.guards.length > 0) {
        setupAutoGuards(resolved.guards, resolved.guardFailOpen);
        // With a Shield360 URL and API key, what the guards stop is also
        // recorded in Shield360's Data protection report.
        configureGuardReports({
          url: resolved.shield360Url,
          apiKey: resolved.shield360ApiKey,
          applicationName: resolved.applicationName,
          environment: resolved.environment,
        });
      }
    } catch (e) {
      console.error('Shield360 initialization failed:', e);
    }
  }
}

const shield360 = Shield360 as typeof Shield360 & {
  usingAttributes: typeof usingAttributes;
  injectAdditionalAttributes: typeof injectAdditionalAttributes;
};

(shield360 as any).usingAttributes = usingAttributes;
(shield360 as any).injectAdditionalAttributes = injectAdditionalAttributes;

export default shield360;
export { Shield360, usingAttributes, injectAdditionalAttributes, logScore };
export { TracedSpan, startTrace, traceManual as trace };
export type { Shield360Options } from './types';
export type { LogScoreOptions } from './score';

// Guard re-exports for named imports: import { PII, Pipeline } from 'shield360'
export {
  PII,
  PromptInjection,
  Moderation,
  SensitiveTopic,
  TopicRestriction,
  Schema,
  Custom,
  Pipeline,
  Guard,
  GuardAction,
  GuardPhase,
  GuardError,
  GuardDeniedError,
  GuardTimeoutError,
  GuardConfigError,
  PipelineResult,
};
export type { GuardResult } from './guard/base';

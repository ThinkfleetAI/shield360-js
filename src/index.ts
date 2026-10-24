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
// Shield Protect: enforcement, kept apart from tracing.
import { ProtectReadinessError, resolveProtect, setProtectState } from './protect/mode';
import { configureGuardReports } from './guard/report';
import { PII } from './guard/pii';
import { PromptInjection } from './guard/prompt-injection';
import { Moderation } from './guard/moderation';
import { SensitiveTopic } from './guard/sensitive-topic';
import { TopicRestriction } from './guard/topic-restriction';
import { Schema } from './guard/schema';
import { Custom } from './guard/custom';
import { Pipeline } from './guard/pipeline';
import { parseOtlpHeaders, resolveDestination } from './destination';
import { resolveCaptureCodeLocation } from './otel/code-location';
import { resolveBuildAttributes } from './otel/build-info';
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

  const shield360ApiKey = o.shield360ApiKey ?? process.env.SHIELD360_API_KEY ?? undefined;
  const shield360Url = o.shield360Url ?? process.env.SHIELD360_URL ?? undefined;

  const rawEndpoint =
    o.otlpEndpoint ??
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT ??
    undefined;

  let givenHeaders = o.otlpHeaders ?? undefined;
  if (!givenHeaders && process.env.OTEL_EXPORTER_OTLP_HEADERS) {
    givenHeaders = parseOtlpHeaders(process.env.OTEL_EXPORTER_OTLP_HEADERS);
  }

  // With no OTLP endpoint, a Shield360 URL and API key are the destination.
  const { otlpEndpoint, otlpHeaders } = resolveDestination({
    otlpEndpoint: rawEndpoint,
    otlpHeaders: givenHeaders,
    shield360Url,
    shield360ApiKey,
  });

  let disableBatch = o.disableBatch ?? undefined;
  const envDisableBatch = parseBoolEnv('SHIELD360_DISABLE_BATCH');
  if (disableBatch === undefined) {
    disableBatch = envDisableBatch ?? false;
  }

  let captureMessageContent = o.captureMessageContent ?? undefined;
  const envCapture = parseBoolEnv('OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT');
  // Prompt and completion text is captured only when asked for (the option
  // or OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true): a Shield360
  // organisation stores no content unless it opts in, so none is sent by default.
  if (captureMessageContent === undefined) {
    captureMessageContent = envCapture ?? false;
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
    protect: resolveProtect(o.protect),
    collectGpuStats,
    captureCodeLocation: resolveCaptureCodeLocation(o.captureCodeLocation),
    codeRoot: o.codeRoot,
    serviceVersion: o.serviceVersion,
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
        ...resolveBuildAttributes({ serviceVersion: resolved.serviceVersion }),
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
        setupAutoGuards(resolved.guards, resolved.guardFailOpen, resolved.protect);
        // With a Shield360 URL and API key, what the guards stop is also
        // recorded in Shield360's Data protection report.
        configureGuardReports({
          url: resolved.shield360Url,
          apiKey: resolved.shield360ApiKey,
          applicationName: resolved.applicationName,
          environment: resolved.environment,
        });
      } else if (resolved.protect.mode === 'enforced' && resolved.protect.required.length) {
        // Shield Protect: enforced mode that names required providers but has no guards is not protected startup.
        setProtectState({ mode: resolved.protect.mode, wrapped: [], missing: resolved.protect.required });
        throw new ProtectReadinessError(resolved.protect.required, 'Shield360 Protect: enforced mode requires guards; pass guards to init().');
      } else {
        setProtectState({ mode: resolved.protect.mode, wrapped: [], missing: [] });
      }
    } catch (e) {
      // Shield Protect: a readiness failure in enforced mode stops startup; it is never logged and swallowed.
      if (e instanceof ProtectReadinessError) throw e;
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

// Shield Protect re-exports: enforcement APIs, apart from the tracing ones above.
export { protectTool, authorizeWithShield360, protectReadiness, ProtectDeniedError, ProtectReadinessError, ProtectError } from './protect';
export type { ProtectMode, ProtectConfig, ProtectReadiness, ProtectToolOptions, AuthorizeTarget, AuthorizeAnswer } from './protect';

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

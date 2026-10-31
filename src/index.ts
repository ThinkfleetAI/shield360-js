import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_TELEMETRY_SDK_NAME } from '@opentelemetry/semantic-conventions';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';
import { Shield360Options, ResolvedOptions } from './types';
import Tracing from './otel/tracing';
import Events from './otel/events';
import { DEFAULT_APPLICATION_NAME, DEFAULT_ENVIRONMENT, SDK_NAME, SDK_VERSION } from './constant';
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
// SHIELD: host and process metrics (opt-in).
import { resolveCollectSystemMetrics, setupSystemMetrics } from './otel/system-metrics';
// SHIELD: logger bridges (pino, winston, console) to application logs.
import { captureConsole, captureStdio, pinoStream, releaseConsole, releaseStdio, winstonTransport } from './otel/log-bridges';
// SHIELD: winston and pino bridged without code changes when application logs are on.
import { enableLogBridges } from './otel/log-auto';
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
// Budget check: app budgets enforced through the SDK.
import { budgets, configureBudgets, BudgetClient, BudgetExceededError } from './budgets';
import { setupAutoBudgetCheck } from './budgets/auto';
// Feature flags: fetched rules, evaluated locally.
import { flags as flagsClient } from './flags/client';
// Cost per end customer: tag AI calls with the builder's own customer.
import { setCustomer, withCustomer, getCustomer, CustomerSpanProcessor } from './customer';
// AI security pack: checks on the app's own AI traffic, kept apart from tracing.
import { aiSecurity, configureAiSecurity, AiSecurityBlockedError } from './ai-security';
import { setupAiSecurity } from './ai-security/hooks';
import { resolveCaptureCodeLocation } from './otel/code-location';
import { ATTR_SERVICE_VERSION, resolveBuildAttributes } from './otel/build-info';
import { configureFeedback, feedback, getCurrentSpanId, getCurrentTraceId } from './feedback';
// SHIELD: runtime protection (RASP), opt-in.
import { initRasp, disableRasp, enableRasp } from './rasp';
import { noteSkippedInit, zeroCodeStarted } from './zero-code';
// SHIELD: application logs, opt-in.
import {
  createLogger,
  disableAppLogs,
  enableAppLogs,
  resolveCaptureLogs,
  resolveLogLevel,
} from './otel/app-logs';
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
    guardHeartbeat: o.guardHeartbeat,
    protect: resolveProtect(o.protect),
    collectGpuStats,
    captureCodeLocation: resolveCaptureCodeLocation(o.captureCodeLocation),
    codeRoot: o.codeRoot,
    serviceVersion: o.serviceVersion,
    captureLogs: resolveCaptureLogs(o.captureLogs),
    captureStdio: o.captureStdio ?? parseBoolEnv('SHIELD360_CAPTURE_STDIO') ?? false,
    logLevel: resolveLogLevel(o.logLevel),
    collectSystemMetrics: resolveCollectSystemMetrics(o.collectSystemMetrics),
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

  /**
   * Send what one of your users thought of an AI response (thumbs 1/-1 or
   * stars 1-5) against its trace. Server side, with the environment's API
   * key. Resolves to whether it was accepted; never throws.
   */
  static feedback = feedback;
  /** The active span's trace id, to keep with a response so a later rating can name it. */
  static getCurrentTraceId = getCurrentTraceId;
  static getCurrentSpanId = getCurrentSpanId;

  static startTrace = startTrace;
  static trace = traceManual;
  /** SHIELD: a logger for application logs; a no-op unless captureLogs is on. */
  static logger = createLogger;
  /** SHIELD: bridges from pino, winston and console to application logs (no-ops unless captureLogs is on). */
  static pinoStream = pinoStream;
  static winstonTransport = winstonTransport;
  static captureConsole = captureConsole;
  static releaseConsole = releaseConsole;
  static captureStdio = captureStdio;
  static releaseStdio = releaseStdio;

  /** Feature flags: `Shield360.flags.getFlag(key, context, default)` and `isEnabled(key, context)`. */
  static flags = flagsClient;

  /** Budget check: Shield360.budgets.check({ model, estimatedCostUsd }) never throws; see ./budgets. */
  static budgets = budgets;
  static BudgetExceededError = BudgetExceededError;

  /**
   * Cost per end customer. setCustomer({ tenantId, userId? }) sets a process-wide
   * default (null clears it); withCustomer(customer, fn) scopes one to fn and its
   * async work, winning over the default; getCustomer() returns the one in effect.
   * Invalid ids are dropped silently. The SDK never hashes: Shield360 stores user
   * ids only as a keyed hash, and tenant ids as given unless the organisation opts
   * to hash them. See ./customer.
   */
  static setCustomer = setCustomer;

  /** SHIELD: the runtime kill switch for RASP (env SHIELD360_RASP=off and the signed config's killSwitch win over it). */
  static disableRasp = disableRasp;
  static enableRasp = enableRasp;
  static withCustomer = withCustomer;
  static getCustomer = getCustomer;

  /** AI security pack: Shield360.aiSecurity.scanContext(), scanOutput(), defineTool(), ... See ./ai-security. */
  static aiSecurity = aiSecurity;
  static AiSecurityBlockedError = AiSecurityBlockedError;

  static init(options?: Shield360Options) {
    // SHIELD: shield360/register already started Shield360 from the environment: a second init() is a no-op.
    if (zeroCodeStarted()) return noteSkippedInit();
    try {
      diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.WARN);

      const resolved = resolveOptions(options);
      this.options = resolved;

      const buildAttributes = resolveBuildAttributes({ serviceVersion: resolved.serviceVersion });
      // User feedback names the application and release it was given for.
      configureFeedback({ app: resolved.applicationName, release: buildAttributes[ATTR_SERVICE_VERSION] });
      this.resource = resourceFromAttributes({
        ...buildAttributes,
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

      // SHIELD: application logs share the events LoggerProvider, so they go
      // to the same destination as traces. Nothing is sent unless asked for.
      // With them on, console output, winston and pino are bridged too, as
      // the Python SDK attaches its handler to the root logger.
      if (resolved.captureLogs) {
        enableAppLogs(Events.ensureProvider(setupBase), resolved.logLevel, {
          captureCodeLocation: resolved.captureCodeLocation,
          codeRoot: resolved.codeRoot,
        });
        if (resolved.captureStdio) {
          // console, pino and winston write to stdout and stderr too: one record per line, not two.
          releaseConsole();
          captureStdio();
        } else {
          captureConsole();
          enableLogBridges();
        }
      } else {
        disableAppLogs();
        releaseConsole();
        releaseStdio();
      }

      if (!resolved.disableMetrics) {
        const exportIntervalMillis =
          Number(process.env.OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL ?? 60000) || 60000;

        const meter = Metrics.setup({
          ...setupBase,
          exportIntervalMillis,
        });

        // SHIELD: host and process metrics for the Infrastructure view, when asked for.
        if (resolved.collectSystemMetrics && meter) {
          try {
            setupSystemMetrics(meter);
          } catch (e) {
            diag.error(`Shield360 system metrics setup failed: ${e}`);
          }
        }

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

      // Budget check: the automatic pre-call check, when asked for.
      const budgetCheck = options?.budgetCheck ?? (parseBoolEnv('SHIELD360_BUDGET_CHECK') || false);
      if (budgetCheck) {
        const client = configureBudgets({
          app: resolved.applicationName,
          ...(typeof budgetCheck === 'object' && budgetCheck.failClosed !== undefined ? { failClosed: budgetCheck.failClosed } : {}),
        });
        setupAutoBudgetCheck({ client, onWarn: (r) => console.warn(`[shield360] ${r.reason}`) });
      } else {
        configureBudgets({ app: resolved.applicationName });
      }

      // AI security pack: on when asked for; monitors by default.
      const ai = options?.aiSecurity ?? (parseBoolEnv('SHIELD360_AI_SECURITY') || false);
      if (ai) {
        const o = typeof ai === 'object' ? ai : {};
        configureAiSecurity({
          url: resolved.shield360Url,
          apiKey: resolved.shield360ApiKey,
          app: resolved.applicationName,
          environment: resolved.environment,
          policy: o.policy,
          configPublicKey: o.configPublicKey,
          allowUnpinnedConfig: o.allowUnpinnedConfig,
          configCacheFile: o.configCacheFile,
          recordAllowed: o.recordAllowed,
        });
        if (o.autoInstrument !== false) setupAiSecurity();
      }

      Shield360Helper.fetchPricingInfo(resolved.pricingJson).then(
        (info) => { Shield360Config.pricingInfo = info; },
        () => { Shield360Config.pricingInfo = {}; }
      );

      // SHIELD: runtime protection (RASP): off unless options.rasp or SHIELD360_RASP turns it on.
      initRasp(options?.rasp, {
        applicationName: resolved.applicationName,
        environment: resolved.environment,
        url: resolved.shield360Url,
        apiKey: resolved.shield360ApiKey,
        sdkVersion: SDK_VERSION,
        otlpEndpoint: resolved.otlpEndpoint,
      });

      if (resolved.guards && resolved.guards.length > 0) {
        setupAutoGuards(resolved.guards, resolved.guardFailOpen, resolved.protect);
        // With a Shield360 URL and API key, what the guards stop is also
        // recorded in Shield360's Data protection report.
        configureGuardReports({
          url: resolved.shield360Url,
          apiKey: resolved.shield360ApiKey,
          applicationName: resolved.applicationName,
          environment: resolved.environment,
          sdkVersion: SDK_VERSION,
          guards: resolved.guards,
          heartbeat: resolved.guardHeartbeat,
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
export { budgets, BudgetClient, BudgetExceededError };
export type { BudgetCheckOptions, BudgetCheckResult, BudgetAction, BudgetClientOptions } from './budgets';
export { createLogger } from './otel/app-logs';
export type { Shield360Logger, LogLevel } from './otel/app-logs';

// Feature flags.
export { FlagsClient, flags } from './flags';
export type { FlagsOptions, FlagDetail, FlagDefinition, EvaluationContext, Evaluation, FlagValue, PromptRef, PromptFlagOptions, PromptFlagResult, Segment } from './flags';
export { setCustomer, withCustomer, getCustomer, CustomerSpanProcessor };
export type { Customer, CustomerInput } from './customer';
export { aiSecurity, AiSecurityBlockedError };
export type { AiSecurityPolicy, AiSecurityPolicyInput, AiSecurityEvent, EndUserInput } from './ai-security';
export type { AiSecurityInitOptions } from './types';
export type { Shield360Options } from './types';
export type { LogScoreOptions } from './score';
export { feedback, getCurrentTraceId, getCurrentSpanId } from './feedback';
export type { FeedbackOptions, FeedbackScale } from './feedback';

// Shield Protect re-exports: enforcement APIs, apart from the tracing ones above.
export { protectTool, authorizeWithShield360, protectReadiness, ProtectDeniedError, ProtectReadinessError, ProtectError } from './protect';
export type { ProtectMode, ProtectConfig, ProtectReadiness, ProtectToolOptions, AuthorizeTarget, AuthorizeAnswer } from './protect';

// Agent passports: verify the agents that call this service (also at 'shield360/agents').
export { agentVerifier, AGENT_HEADER, MemoryReplayStore } from './agents';
export type { AgentVerifier, AgentVerifierOptions, AgentCheck, AgentCheckOptions, AgentCheckInput, AgentPolicy, ReplayStore } from './agents';

// SHIELD: runtime protection (RASP): middleware, the block error, the model-output hook point.
export {
  raspExpress,
  raspExpressErrorHandler,
  raspFastify,
  raspKoa,
  raspHttp,
  withRasp,
  recordRequestBody,
  recordModelOutput,
  recordToolArguments,
  runInRaspScope,
  disableRasp,
  enableRasp,
  raspActive,
  isRaspBlocked,
  RaspBlockedError,
  Shield360RaspBlocked,
} from './rasp';
export type { RaspOptions, RaspMode, AttackType as RaspAttackType, ConfigPublicKey } from './rasp';

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

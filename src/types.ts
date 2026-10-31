import { Resource } from '@opentelemetry/resources';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { metrics } from '@opentelemetry/api';
import type { Guard } from './guard/base';
import type { ProtectConfig, ResolvedProtect } from './protect/mode';
import type { LogLevel } from './otel/app-logs';
import type { AiSecurityPolicyInput } from './ai-security/policy';
import type { RaspOptions } from './rasp/types';

/** init({ aiSecurity }) options. */
export type AiSecurityInitOptions = {
  policy?: AiSecurityPolicyInput;
  /** The config signing key(s) to pin (JWK, PEM or JWKS); env SHIELD360_CONFIG_PUBLIC_KEY. Required for the platform policy. */
  configPublicKey?: unknown;
  /** Development only: trust the first config key seen when none is pinned. */
  allowUnpinnedConfig?: boolean;
  configCacheFile?: string;
  /** Wire the checks into installed providers and frameworks (default true). */
  autoInstrument?: boolean;
  recordAllowed?: boolean;
};

export type InstrumentationType = 'openai' | 'anthropic' | 'cohere' | 'groq' | 'mistral' | 'google-ai' | 'vertexai' | 'together' | 'ollama' | 'vllm' | 'vercel-ai' | 'langchain' | 'langgraph' | 'pinecone' | 'bedrock' | 'llamaindex' | 'huggingface' | 'replicate' | 'chroma' | 'qdrant' | 'milvus' | 'astra' | 'azure-ai-inference' | 'openai-agents' | 'strands' | 'google-adk' | 'claude-agent-sdk' | 'cursor-sdk' | 'ai21' | 'gradient' | 'browser-use' | 'mcp' | 'mem0' | 'elevenlabs' | 'assemblyai' | 'transformers' | 'pg' | 'firecrawl' | 'letta';

export type Shield360Instrumentations = Partial<Record<InstrumentationType, any>>;

export type PricingObject = Record<string, Record<string, unknown>>;

/**
 * Internal config interface used by Shield360Config.
 */
export interface Shield360ConfigInterface {
  environment?: string;
  applicationName?: string;
  pricingInfo?: PricingObject;
  tracer: NodeTracerProvider;
  otlpEndpoint?: string;
  otlpHeaders?: Record<string, unknown>;
  disableBatch?: boolean;
  captureMessageContent?: boolean;
  pricingJson?: string | PricingObject;
  disableMetrics?: boolean;
  disableEvents?: boolean;
  maxContentLength?: number | null;
  customSpanAttributes?: Record<string, string> | null;
  shield360ApiKey?: string;
  shield360Url?: string;
}

/**
 * Public init() options.
 *
 * Names match the Python SDK's init() parameters in camelCase form:
 *   Python: application_name     → JS: applicationName
 *   Python: otlp_endpoint        → JS: otlpEndpoint
 *   Python: otlp_headers         → JS: otlpHeaders
 *   Python: disable_batch        → JS: disableBatch
 *   Python: capture_message_content → JS: captureMessageContent
 *   Python: disabled_instrumentors  → JS: disabledInstrumentors
 *   Python: disable_metrics      → JS: disableMetrics
 *   Python: disable_events       → JS: disableEvents
 *   Python: pricing_json         → JS: pricingJson
 *   Python: max_content_length   → JS: maxContentLength
 *   Python: custom_span_attributes → JS: customSpanAttributes
 *   Python: collect_gpu_stats     → JS: collectGpuStats
 *   Python: capture_code_location → JS: captureCodeLocation
 *   Python: code_root             → JS: codeRoot
 *   Python: service_version       → JS: serviceVersion
 *   Python: capture_logs          → JS: captureLogs
 *   Python: collect_system_metrics → JS: collectSystemMetrics
 *   Python: log_level             → JS: logLevel
 */
export type Shield360Options = {
  environment?: string;
  applicationName?: string;
  tracer?: NodeTracerProvider;
  otlpEndpoint?: string;
  otlpHeaders?: Record<string, unknown>;
  disableBatch?: boolean;
  captureMessageContent?: boolean;
  disabledInstrumentors?: string[];
  instrumentations?: Shield360Instrumentations;
  disableMetrics?: boolean;
  disableEvents?: boolean;
  pricingJson?: string | PricingObject;
  maxContentLength?: number | null;
  customSpanAttributes?: Record<string, string> | null;
  shield360ApiKey?: string;
  shield360Url?: string;
  guards?: Guard[];
  guardFailOpen?: boolean;
  /**
   * With guards and a Shield360 URL and key, the SDK tells Shield360 every
   * few minutes which guards run and in which mode (no content). False turns
   * it off; so does SHIELD360_GUARD_HEARTBEAT=false.
   */
  guardHeartbeat?: boolean;
  /**
   * Shield Protect: the enforcement mode (observe | warn | enforced; env
   * SHIELD360_PROTECT_MODE can raise it, never lower it) and the provider
   * packages that must be wrapped for protected startup (env
   * SHIELD360_PROTECT_REQUIRED adds to the list). In enforced mode, init()
   * throws ProtectReadinessError instead of starting unguarded.
   */
  protect?: ProtectConfig;
  collectGpuStats?: boolean;
  /** Add code.* call-site attributes to GenAI spans (default true; env SHIELD360_CAPTURE_CODE_LOCATION). */
  captureCodeLocation?: boolean;
  /** Root stripped from code.file.path (env SHIELD360_CODE_ROOT). */
  codeRoot?: string;
  /**
   * service.version resource attribute: the release. Env SHIELD360_SERVICE_VERSION,
   * or its alias SHIELD360_RELEASE, then OTEL_SERVICE_VERSION.
   */
  serviceVersion?: string;
  /**
   * Check this app's Shield360 budgets before each provider call (env
   * SHIELD360_BUDGET_CHECK=1). A call a budget blocks throws
   * BudgetExceededError. Cached per the decision's ttl and headroom; fails
   * open unless failClosed (env SHIELD360_BUDGET_FAIL_CLOSED=1). Off by
   * default; Shield360.budgets.check() works either way.
   */
  budgetCheck?: boolean | { failClosed?: boolean };
  /**
   * SHIELD: send application logs written with Shield360.logger() (default
   * false; env SHIELD360_CAPTURE_LOGS). Off, the loggers are no-ops.
   */
  captureLogs?: boolean;
  /**
   * SHIELD: with captureLogs, take application logs from every line the app writes to stdout and
   * stderr (JSON lines by their level, message and fields) instead of from console, pino and
   * winston, for apps whose logger writes lines itself (default false; env SHIELD360_CAPTURE_STDIO).
   */
  captureStdio?: boolean;
  /** SHIELD: lowest level sent: debug | info | warn | error | fatal (default info; env SHIELD360_LOG_LEVEL). */
  logLevel?: LogLevel;
  /**
   * SHIELD: send host and process CPU, memory and event-loop delay as metrics
   * (default false; env SHIELD360_COLLECT_SYSTEM_METRICS). Shield360's
   * Infrastructure view reads them. Python: collect_system_metrics.
   */
  collectSystemMetrics?: boolean;
  /**
   * AI security pack (OWASP Top 10 for LLM apps): indirect injection, jailbreak,
   * output, tool permission, limit, MCP pinning and RAG checks, monitoring by
   * default. true turns it on with the platform's policy; an object adds a
   * policy from code and options. Env SHIELD360_AI_SECURITY=1. See ./ai-security.
   */
  aiSecurity?: boolean | AiSecurityInitOptions;
  /**
   * SHIELD: runtime protection (RASP), off by default. `true` or options
   * (an object turns it on unless `enabled: false`); env
   * SHIELD360_RASP=monitor|block|off. See sdk/rasp/README.md.
   */
  rasp?: boolean | RaspOptions;
};

/**
 * Resolved options used internally after merging args, env vars, and defaults.
 */
export interface ResolvedOptions {
  environment: string;
  applicationName: string;
  tracer?: NodeTracerProvider;
  otlpEndpoint?: string;
  otlpHeaders?: Record<string, unknown>;
  /** SHIELD: with no destination, print to the console (destination.ts consoleFallbackAllowed); otherwise send nothing. */
  consoleFallback: boolean;
  disableBatch: boolean;
  captureMessageContent: boolean;
  disabledInstrumentors?: string[];
  instrumentations?: Shield360Instrumentations;
  disableMetrics: boolean;
  disableEvents: boolean;
  pricingJson?: string | PricingObject;
  maxContentLength?: number | null;
  customSpanAttributes?: Record<string, string> | null;
  shield360ApiKey?: string;
  shield360Url?: string;
  guards?: Guard[];
  guardFailOpen: boolean;
  guardHeartbeat?: boolean;
  protect: ResolvedProtect;
  collectGpuStats: boolean;
  captureCodeLocation: boolean;
  codeRoot?: string;
  serviceVersion?: string;
  captureLogs: boolean;
  captureStdio: boolean;
  logLevel: LogLevel;
  collectSystemMetrics: boolean;
}

export type SetupTracerOptions = ResolvedOptions & {
  resource: Resource;
};

export type MeterType = ReturnType<typeof metrics.getMeter>;

export type SetupMetricsOptions = SetupTracerOptions & {
  meter?: MeterType;
  exportIntervalMillis?: number;
};

export type SetupEventsOptions = SetupTracerOptions;

export interface BaseShield360Options {
  url?: string;
  apiKey?: string;
}

export interface PromptHubOptions extends BaseShield360Options {
  name?: string;
  version?: string;
  shouldCompile?: boolean;
  variables?: Record<string, any>;
  promptId?: string;
  metaProperties?: Record<string, any>;
}

export interface VaultOptions extends BaseShield360Options {
  key?: string;
  tags?: string[];
  shouldSetEnv?: boolean;
}

export type RuleEntityType = 'context' | 'prompt' | 'evaluation';

export interface RuleEngineOptions extends BaseShield360Options {
  entityType: RuleEntityType;
  fields: Record<string, string | number | boolean>;
  includeEntityData?: boolean;
  entityInputs?: Record<string, any>;
}

export interface RuleEngineResult {
  matchingRuleIds: string[];
  entities: Array<{ rule_id: string; entity_type: string; entity_id: string }>;
  entity_data?: Record<string, any>;
}

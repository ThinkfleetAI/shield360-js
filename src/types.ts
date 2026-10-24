import { Resource } from '@opentelemetry/resources';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { metrics } from '@opentelemetry/api';
import type { Guard } from './guard/base';
import type { ProtectConfig, ResolvedProtect } from './protect/mode';

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
  /** service.version resource attribute (env SHIELD360_SERVICE_VERSION). */
  serviceVersion?: string;
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
  protect: ResolvedProtect;
  collectGpuStats: boolean;
  captureCodeLocation: boolean;
  codeRoot?: string;
  serviceVersion?: string;
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

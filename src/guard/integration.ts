/**
 * Auto-guard integration layer.
 *
 * setupAutoGuards wraps LLM provider methods so that guards run on every
 * call without any changes to existing instrumentation code.
 *
 * Call chain after setup:
 *
 *   User call
 *     -> Guard wrapper  (preflight -> may deny/redact)
 *       -> Instrumentor wrapper  (OTel telemetry)
 *         -> Original SDK method  (actual API call)
 *       <- Instrumentor wrapper
 *     <- Guard wrapper  (postflight -> may redact/warn)
 *   <- Returns to user
 *
 * **Streaming limitation**: postflight guards require a complete response
 * object with `choices[].message.content` (or equivalent). Streaming
 * responses yield incremental chunks that extractors cannot fully
 * reassemble, so postflight guards are silently skipped for streamed
 * completions. Preflight guards always run.
 *
 * Must stay in sync with: sdk/python/src/shield360/guard/_integration.py
 */

import { Guard, GuardAction, GuardDeniedError, GuardPhase } from './base';
import { Pipeline } from './pipeline';
import { ProtectDeniedError, ProtectReadinessError, refuses, setProtectState, type ResolvedProtect } from '../protect/mode';

// ---------------------------------------------------------------------------
// Provider-specific text extractors
// ---------------------------------------------------------------------------

type Extractor = (arg: any) => string;

/** The text in a message's content: a string, or the text parts of a list of blocks. */
function contentText(content: unknown): string[] {
  if (typeof content === 'string') return content ? [content] : [];
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const block of content) {
    if (typeof block === 'string') out.push(block);
    else if (block && typeof block === 'object' && typeof (block as any).text === 'string') out.push((block as any).text);
  }
  return out;
}

export function extractOpenAIInput(kwargs: Record<string, any>): string {
  const messages = kwargs.messages || kwargs.input || [];
  const parts: string[] = [];
  // The Responses API's instructions are a system prompt: scanned like one.
  if (typeof kwargs.instructions === 'string' && kwargs.instructions) parts.push(kwargs.instructions);
  if (typeof messages === 'string') parts.push(messages);
  else if (Array.isArray(messages)) {
    for (const m of messages) {
      if (typeof m === 'object' && m !== null) parts.push(...contentText(m.content));
      else if (typeof m === 'string') parts.push(m);
    }
  }
  return parts.join(' ');
}

export function extractOpenAIOutput(response: any): string {
  try {
    const choices = response?.choices;
    if (choices && Array.isArray(choices)) {
      return choices
        .map((c: any) => c?.message?.content || '')
        .join(' ');
    }
    const output = response?.output;
    if (output && Array.isArray(output)) {
      const parts: string[] = [];
      for (const item of output) {
        const content = item?.content;
        if (Array.isArray(content)) {
          for (const block of content) {
            const text = block?.text;
            if (text) parts.push(text);
          }
        } else if (typeof content === 'string') {
          parts.push(content);
        }
      }
      return parts.join(' ');
    }
  } catch {
    // ignore
  }
  return '';
}

export function extractAnthropicInput(kwargs: Record<string, any>): string {
  const messages = kwargs.messages || [];
  const parts: string[] = [];
  // The system prompt is input too: a string, or text blocks.
  parts.push(...contentText(kwargs.system));
  if (Array.isArray(messages)) {
    for (const m of messages) {
      if (typeof m === 'object' && m !== null) {
        const content = m.content ?? '';
        if (typeof content === 'string') {
          parts.push(content);
        } else if (Array.isArray(content)) {
          for (const block of content) {
            if (typeof block === 'object' && block?.type === 'text') {
              parts.push(block.text || '');
            }
          }
        }
      }
    }
  }
  return parts.join(' ');
}

export function extractAnthropicOutput(response: any): string {
  try {
    const content = response?.content;
    if (Array.isArray(content)) {
      const parts: string[] = [];
      for (const block of content) {
        const text = block?.text;
        if (text) parts.push(text);
      }
      return parts.join(' ');
    }
  } catch {
    // ignore
  }
  return '';
}

export function extractGenericInput(kwargs: Record<string, any>): string {
  for (const key of ['messages', 'message', 'prompt', 'input', 'text']) {
    const val = kwargs[key];
    if (val == null) continue;
    if (typeof val === 'string') return val;
    if (Array.isArray(val)) {
      const parts: string[] = [];
      for (const item of val) {
        if (typeof item === 'string') {
          parts.push(item);
        } else if (typeof item === 'object' && item !== null) {
          parts.push(item.content || '');
        }
      }
      return parts.join(' ');
    }
  }
  return '';
}

export function extractGenericOutput(response: any): string {
  try {
    const choices = response?.choices;
    if (choices && Array.isArray(choices)) {
      return choices
        .map((c: any) => c?.message?.content || '')
        .join(' ');
    }
  } catch {
    // ignore
  }
  try {
    const content = response?.content;
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
      const parts: string[] = [];
      for (const block of content) {
        const text = block?.text;
        if (text) parts.push(text);
      }
      if (parts.length) return parts.join(' ');
    }
  } catch {
    // ignore
  }
  try {
    if (response?.text) return response.text;
  } catch {
    // ignore
  }
  return '';
}

// ---------------------------------------------------------------------------
// Methods to guard: (npmPackage, protoPath, methodName, inputExtractor, outputExtractor)
// ---------------------------------------------------------------------------

export interface GuardedMethod {
  npmPackage: string;
  protoPath: string[];
  methodName: string;
  extractInput: Extractor;
  extractOutput: Extractor;
}

export const GUARDED_METHODS: GuardedMethod[] = [
  // OpenAI
  { npmPackage: 'openai', protoPath: ['OpenAI', 'Chat', 'Completions', 'prototype'], methodName: 'create', extractInput: extractOpenAIInput, extractOutput: extractOpenAIOutput },
  { npmPackage: 'openai', protoPath: ['OpenAI', 'Responses', 'prototype'], methodName: 'create', extractInput: extractOpenAIInput, extractOutput: extractOpenAIOutput },
  // Anthropic
  { npmPackage: '@anthropic-ai/sdk', protoPath: ['Anthropic', 'Messages', 'prototype'], methodName: 'create', extractInput: extractAnthropicInput, extractOutput: extractAnthropicOutput },
  // Groq
  { npmPackage: 'groq-sdk', protoPath: ['Groq', 'Chat', 'Completions', 'prototype'], methodName: 'create', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
  // Mistral
  { npmPackage: '@mistralai/mistralai', protoPath: ['Mistral', 'chat', 'prototype'], methodName: 'complete', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
  // Cohere
  { npmPackage: 'cohere-ai', protoPath: ['CohereClientV2', 'prototype'], methodName: 'chat', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
  // Together
  { npmPackage: 'together-ai', protoPath: ['Together', 'Chat', 'Completions', 'prototype'], methodName: 'create', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
  // Bedrock (AWS)
  { npmPackage: '@aws-sdk/client-bedrock-runtime', protoPath: ['BedrockRuntimeClient', 'prototype'], methodName: 'send', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
  // Google Generative AI
  { npmPackage: '@google/generative-ai', protoPath: ['GenerativeModel', 'prototype'], methodName: 'generateContent', extractInput: extractGenericInput, extractOutput: extractGenericOutput },
];

// ---------------------------------------------------------------------------
// Preflight / Postflight
// ---------------------------------------------------------------------------

/**
 * Redact a prompt or message list one message (and text block) at a time.
 *
 * The decision to redact is made on all the input together, but each message
 * is rewritten on its own: writing the joined text into one message would copy
 * the system prompt and earlier turns into it, and leave the originals --
 * secrets included -- untouched.
 */
function redactMessages(pipeline: Pipeline, value: any, phase: string): any {
  if (typeof value === 'string') return pipeline.redact(value, phase);
  if (!Array.isArray(value)) return value;
  return value.map((m) => {
    if (typeof m === 'string') return pipeline.redact(m, phase);
    if (typeof m !== 'object' || m === null) return m;
    if (typeof m.content === 'string') return { ...m, content: pipeline.redact(m.content, phase) };
    if (Array.isArray(m.content)) {
      return {
        ...m,
        content: m.content.map((b: any) =>
          b && typeof b === 'object' && typeof b.text === 'string'
            ? { ...b, text: pipeline.redact(b.text, phase) }
            : b,
        ),
      };
    }
    return m;
  });
}

/**
 * Shield Protect: what a mode does with a pipeline result, and with a
 * pipeline that failed. No mode (legacy): a DENY throws, as it always did.
 * observe: recorded, the call goes on. warn: as observe, and logged.
 * enforced: a DENY throws; a failed pipeline throws (fail closed), whatever
 * failOpen says.
 */
function evaluateUnder(pipeline: Pipeline, text: string, phase: 'preflight' | 'postflight', protect?: ResolvedProtect) {
  const mode = protect?.mode;
  const bound = pipeline.scanBound();
  if (refuses(mode) && bound > 0 && text.length > bound) {
    throw new ProtectDeniedError('oversized', `Shield360 Protect refused the call: ${text.length} characters is more than its guards scan (${bound}); send less.`);
  }
  let result;
  try {
    result = pipeline.evaluate(text, phase);
  } catch (e) {
    if (refuses(mode)) {
      throw new ProtectDeniedError('guard_failed', 'Shield360 Protect refused the call: a guard failed and enforced mode does not run unchecked calls.');
    }
    throw e;
  }
  if (result.action === GuardAction.DENY) {
    if (mode === undefined || refuses(mode)) throw new GuardDeniedError(result);
    if (mode === 'warn') console.warn(`[shield360] Protect (warn mode): the call would have been refused at ${phase}: ${result.explanation}`);
    // observe / warn: recorded by the pipeline's own span event; the call goes on.
    return { ...result, action: GuardAction.WARN };
  }
  return result;
}

/** @internal exported for tests */
export function applyPreflight(
  pipeline: Pipeline,
  kwargs: Record<string, any>,
  extractInput: Extractor,
  protect?: ResolvedProtect,
): Record<string, any> {
  const inputText = extractInput(kwargs);
  if (!inputText) return kwargs;

  // A streamed completion cannot be inspected after the fact. Enforced mode
  // with postflight guards refuses it rather than let the response through
  // unread; with preflight-only guards the stream is fine.
  if (refuses(protect?.mode) && kwargs.stream === true && pipeline.hasPhase(GuardPhase.POSTFLIGHT)) {
    throw new ProtectDeniedError('streaming', 'Shield360 Protect refused a streamed completion: postflight guards cannot inspect a stream. Call without stream, or configure preflight-only guards.');
  }

  const result = evaluateUnder(pipeline, inputText, 'preflight', protect);

  if (result.action === GuardAction.REDACT && result.transformedText !== null) {
    for (const key of ['messages', 'input', 'prompt', 'text']) {
      if (key in kwargs) {
        return { ...kwargs, [key]: redactMessages(pipeline, kwargs[key], 'preflight') };
      }
    }
  }

  return kwargs;
}

function redactTextField(pipeline: Pipeline, obj: any, field: string): void {
  if (obj && typeof obj[field] === 'string' && obj[field]) {
    obj[field] = pipeline.redact(obj[field], 'postflight');
  }
}

/**
 * Each choice and text block is redacted on its own, so none is left holding
 * the original text or another block's.
 *
 * @internal exported for tests
 */
export function applyPostflight(
  pipeline: Pipeline,
  response: any,
  extractOutput: Extractor,
  protect?: ResolvedProtect,
): any {
  const outputText = extractOutput(response);
  if (!outputText) return response;

  const result = evaluateUnder(pipeline, outputText, 'postflight', protect);

  if (result.action === GuardAction.REDACT && result.transformedText !== null) {
    try {
      if (Array.isArray(response?.choices) && response.choices.length > 0) {
        // OpenAI chat completions.
        for (const choice of response.choices) redactTextField(pipeline, choice?.message, 'content');
      } else if (Array.isArray(response?.output) && response.output.length > 0) {
        // OpenAI Responses API: output items hold text blocks.
        for (const item of response.output) {
          if (Array.isArray(item?.content)) {
            for (const block of item.content) redactTextField(pipeline, block, 'text');
          }
        }
        if (typeof response.output_text === 'string') redactTextField(pipeline, response, 'output_text');
      } else if (Array.isArray(response?.content) && response.content.length > 0) {
        // Anthropic messages.
        for (const block of response.content) redactTextField(pipeline, block, 'text');
      } else {
        redactTextField(pipeline, response, 'text');
      }
    } catch {
      // best-effort redaction
    }
  }

  return response;
}

// ---------------------------------------------------------------------------
// Prototype resolver
// ---------------------------------------------------------------------------

export function resolveProto(moduleExports: any, protoPath: string[]): any {
  let obj = moduleExports;
  for (const key of protoPath) {
    if (obj == null) return null;
    obj = obj[key];
  }
  return obj;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export type AutoGuardReport = {
  /** npm packages whose provider methods were wrapped. */
  wrapped: string[];
  /** Required packages that were not wrapped: not installed, or not resolvable from this module (an ESM-only resolution). */
  missing: string[];
};

/**
 * Wraps every installed provider the SDK knows. With Shield Protect in
 * enforced mode the pipeline fails closed (failOpen is overridden, with a
 * warning when it was set), and a package named in `required` that could
 * not be wrapped throws ProtectReadinessError: protected startup fails
 * rather than running unguarded.
 *
 * Supported module loading: CommonJS `require`, and ESM `import` of a
 * provider whose package resolves to the same CommonJS build (openai and
 * @anthropic-ai/sdk do under Node's default conditions). An ESM-only
 * resolution loads a class this function never sees; name the package in
 * `required` so enforced mode fails rather than silently not wrapping it,
 * or use protectTool() which needs no patching.
 */
export function setupAutoGuards(
  guards: Guard[],
  failOpen = true,
  protect?: ResolvedProtect,
): AutoGuardReport {
  let effectiveFailOpen = failOpen;
  if (refuses(protect?.mode) && failOpen) {
    console.warn('[shield360] Protect: enforced mode fails closed; guardFailOpen is ignored.');
    effectiveFailOpen = false;
  }
  const pipeline = new Pipeline({ guards, failOpen: effectiveFailOpen });

  try {
    const Shield360Config = require('../config').default;
    Shield360Config.guardPipeline = pipeline;
  } catch {
    // config not available
  }

  const wrapped = new Set<string>();
  for (const { npmPackage, protoPath, methodName, extractInput, extractOutput } of GUARDED_METHODS) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require(npmPackage);
      const proto = resolveProto(mod, protoPath);
      if (!proto || typeof proto[methodName] !== 'function') continue;

      const original = proto[methodName];
      proto[methodName] = async function (this: any, ...args: any[]) {
        let params = args[0] || {};

        params = applyPreflight(pipeline, params, extractInput, protect);
        args[0] = params;

        const response = await original.apply(this, args);

        return applyPostflight(pipeline, response, extractOutput, protect);
      };
      wrapped.add(npmPackage);
    } catch {
      // module not installed, skip silently
    }
  }

  const missing = (protect?.required ?? []).filter((pkg) => !wrapped.has(pkg));
  setProtectState({ mode: protect?.mode, wrapped: Array.from(wrapped), missing });
  if (wrapped.size > 0) {
    console.log(`[shield360] Auto-guards: wrapped ${wrapped.size} provider package(s): ${Array.from(wrapped).join(', ')}`);
  }
  if (refuses(protect?.mode) && missing.length) {
    throw new ProtectReadinessError(missing, `Shield360 Protect: enforced mode requires guards on ${missing.join(', ')}, which could not be wrapped (not installed, or not resolvable as CommonJS). Protected startup refused.`);
  }
  return { wrapped: Array.from(wrapped), missing };
}

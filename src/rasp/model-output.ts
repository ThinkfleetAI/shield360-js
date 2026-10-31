/**
 * The hook point the SDK's LLM instrumentation calls with what a model
 * returned (README "Sources of untrusted input", `source: "model_output"`).
 * No patching happens here: the instrumentation already sees the response
 * and hands the text over. A no-op unless RASP is on with `modelOutput`.
 *
 * Inside a request the fragments join the request's inputs. Outside one,
 * the SDK starts a context for the rest of the current async continuation;
 * a worker that acts on a model's answer gets reliable scoping by wrapping
 * the job in `runInRaspScope(fn)`.
 */
import { newContext, storage, type RaspContext } from './context';
import { addModelOutput, addToolArguments } from './normalize';

let enabled = false;

/** Set by the engine: whether model output is recorded at all. */
export function setModelOutputRecording(on: boolean): void {
  enabled = on;
}

export function modelOutputRecording(): boolean {
  return enabled;
}

function scope(): RaspContext {
  let ctx = storage.getStore();
  if (!ctx) {
    ctx = newContext();
    storage.enterWith(ctx);
  }
  return ctx;
}

/** Registers completion text a model returned as untrusted input. Never throws. */
export function recordModelOutput(text: unknown, key = 'model.completion'): void {
  if (!enabled) return;
  try {
    if (typeof text !== 'string' || !text) return;
    addModelOutput(scope().inputs, text, key);
  } catch {
    // fail open
  }
}

/** Registers tool-call arguments (a JSON string or an object) as untrusted input. Never throws. */
export function recordToolArguments(args: unknown, toolName?: string): void {
  if (!enabled) return;
  try {
    if (args == null || args === '') return;
    const name = typeof toolName === 'string' ? toolName.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64) : '';
    addToolArguments(scope().inputs, args, name ? `model.tool.${name}` : 'model.tool');
  } catch {
    // fail open
  }
}

/**
 * Records a provider response the instrumentation already holds: OpenAI chat
 * completions (`choices[].message`), OpenAI Responses (`output[]`), Anthropic
 * messages (`content[]`). Text becomes completion fragments; tool-call
 * arguments become `model.tool.<name>` inputs. Never throws.
 */
export function recordModelResponse(result: unknown): void {
  if (!enabled || !result || typeof result !== 'object') return;
  try {
    const r = result as Record<string, any>;
    if (Array.isArray(r.choices)) {
      for (const c of r.choices.slice(0, 8)) {
        const m = c?.message;
        if (typeof m?.content === 'string') recordModelOutput(m.content);
        for (const t of Array.isArray(m?.tool_calls) ? m.tool_calls.slice(0, 32) : []) recordToolArguments(t?.function?.arguments, t?.function?.name);
      }
    }
    if (Array.isArray(r.output)) {
      for (const item of r.output.slice(0, 64)) {
        if (item?.type === 'function_call') recordToolArguments(item.arguments, item.name);
        for (const part of Array.isArray(item?.content) ? item.content : []) {
          if (typeof part?.text === 'string') recordModelOutput(part.text);
        }
      }
    }
    if (Array.isArray(r.content)) {
      for (const block of r.content.slice(0, 64)) {
        if (block?.type === 'text' && typeof block.text === 'string') recordModelOutput(block.text);
        else if (block?.type === 'tool_use') recordToolArguments(block.input, block.name);
      }
    }
  } catch {
    // fail open
  }
}

/**
 * Wires the AI security checks into the providers and frameworks the SDK
 * knows, without changing their instrumentations (kept apart so the
 * tracing and the security code can change independently):
 *
 *   OpenAI chat completions and responses, Anthropic messages
 *     before the call   limits; jailbreak check of the user turns; indirect
 *                       injection check of tool results in the messages
 *                       (role "tool", function_call_output, tool_result
 *                       blocks), stripped in place in enforce mode
 *     after the call    output check (redacted in place in enforce mode),
 *                       streamed answers through the bounded stream scanner;
 *                       tokens and cost counted for limits
 *   LangChain           retrievers (checkRetrieval, pageContent stripped in
 *                       place) and tools (permission before, injection check
 *                       of the result after)
 *   LlamaIndex          retrievers
 *   MCP client          listTools (pinning, poisoning), callTool (refused
 *                       tools, permissions, injection check of text results)
 *
 * Every hook fails open: if anything inside it throws (other than a block
 * the policy asked for), the call proceeds as if the hook were not there.
 *
 * Supported module loading: CommonJS require, and ESM imports that resolve
 * to the same CommonJS build. Each patch function also takes the module
 * object, for apps that load it another way.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_hooks.py
 */

import Shield360Config from '../config';
import Shield360Helper from '../helpers';
import {
  AiSecurityBlockedError,
  authorizeTool,
  checkLimits,
  checkMcpTools,
  checkPrompt,
  checkRetrieval,
  mcpCallRefused,
  recordUsage,
  scanContext,
  scanOutput,
  streamScanner,
} from './index';
import { TOOL_DENIED_MESSAGE } from './tools';

const PATCHED = Symbol.for('shield360.aiSecurity.patched');

function wrap(proto: any, method: string, make: (original: any) => any): boolean {
  if (!proto || typeof proto[method] !== 'function' || proto[method][PATCHED]) return false;
  const original = proto[method];
  const wrapped = make(original);
  wrapped[PATCHED] = true;
  proto[method] = wrapped;
  return true;
}

const pass = <T>(fn: () => T, fallback: T): T => {
  try {
    return fn();
  } catch (e) {
    if (e instanceof AiSecurityBlockedError) throw e;
    return fallback;
  }
};

function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((b) => (typeof b === 'string' ? b : b && typeof b === 'object' && typeof (b as any).text === 'string' ? (b as any).text : ''))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

// ---------------------------------------------------------------------------
// Requests: OpenAI and Anthropic shapes.

type Prepared = { params: any; systemPrompt: string };

/** Checks and, in enforce mode, rewrites a request's messages. @internal exported for tests */
export function prepareRequest(params: any, provider: 'openai' | 'anthropic'): Prepared {
  if (!params || typeof params !== 'object') return { params, systemPrompt: '' };
  checkLimits();
  const out = { ...params };
  const system: string[] = [];
  const userTurns: string[] = [];
  if (provider === 'anthropic') system.push(textOf(params.system));
  if (typeof params.instructions === 'string') system.push(params.instructions);
  const list = Array.isArray(params.messages) ? params.messages : Array.isArray(params.input) ? params.input : null;
  if (typeof params.input === 'string') userTurns.push(params.input);
  if (list) {
    const key = Array.isArray(params.messages) ? 'messages' : 'input';
    out[key] = list.map((m: any) => {
      if (!m || typeof m !== 'object') return m;
      const role = m.role;
      if (role === 'system' || role === 'developer') {
        system.push(textOf(m.content));
        return m;
      }
      if (role === 'tool') {
        const scan = scanContext(textOf(m.content), { source: 'tool_result', tool: m.name });
        return scan.action === 'stripped' ? { ...m, content: scan.text } : m;
      }
      if (m.type === 'function_call_output' && typeof m.output === 'string') {
        const scan = scanContext(m.output, { source: 'tool_result' });
        return scan.action === 'stripped' ? { ...m, output: scan.text } : m;
      }
      if (role === 'user') {
        if (Array.isArray(m.content)) {
          let changed = false;
          const blocks = m.content.map((b: any) => {
            if (b && b.type === 'tool_result') {
              const scan = scanContext(textOf(b.content), { source: 'tool_result' });
              if (scan.action === 'stripped') {
                changed = true;
                return { ...b, content: scan.text };
              }
              return b;
            }
            return b;
          });
          const text = m.content.filter((b: any) => b && b.type !== 'tool_result').map((b: any) => (typeof b === 'string' ? b : b?.text || '')).join('\n');
          if (text.trim()) userTurns.push(text);
          return changed ? { ...m, content: blocks } : m;
        }
        userTurns.push(textOf(m.content));
      }
      return m;
    });
  }
  if (userTurns.length) checkPrompt(userTurns);
  return { params: out, systemPrompt: system.filter(Boolean).join('\n') };
}

function outputTextAndSetter(response: any): { text: string; set: (t: string) => void } | null {
  if (Array.isArray(response?.choices)) {
    const msg = response.choices[0]?.message;
    if (msg && typeof msg.content === 'string') return { text: msg.content, set: (t) => (msg.content = t) };
    return null;
  }
  if (Array.isArray(response?.output)) {
    const blocks: any[] = [];
    for (const item of response.output) if (Array.isArray(item?.content)) for (const b of item.content) if (typeof b?.text === 'string') blocks.push(b);
    if (!blocks.length) return null;
    return {
      text: blocks.map((b) => b.text).join('\n'),
      set: (t) => {
        blocks[0].text = t;
        for (const b of blocks.slice(1)) b.text = '';
        if (typeof response.output_text === 'string') response.output_text = t;
      },
    };
  }
  if (Array.isArray(response?.content)) {
    const blocks = response.content.filter((b: any) => typeof b?.text === 'string');
    if (!blocks.length) return null;
    return {
      text: blocks.map((b: any) => b.text).join('\n'),
      set: (t) => {
        blocks[0].text = t;
        for (const b of blocks.slice(1)) b.text = '';
      },
    };
  }
  return null;
}

function countUsage(params: any, response: any): void {
  pass(() => {
    const u = response?.usage;
    if (!u) return recordUsage({ requests: 1 });
    const input = Number(u.prompt_tokens ?? u.input_tokens ?? 0) || 0;
    const output = Number(u.completion_tokens ?? u.output_tokens ?? 0) || 0;
    const model = String(response?.model || params?.model || '');
    let cost = 0;
    try {
      cost = Shield360Helper.getChatModelCost(model, Shield360Config.pricingInfo, input, output) || 0;
    } catch {
      cost = 0;
    }
    recordUsage({ requests: 1, tokens: input + output, costUsd: cost });
  }, undefined);
}

/** Checks a whole answer; redacts it in place. @internal exported for tests */
export function finishResponse(response: any, prepared: Prepared): any {
  const target = pass(() => outputTextAndSetter(response), null);
  if (target && target.text) {
    const res = scanOutput(target.text, { systemPrompt: prepared.systemPrompt });
    if (res.action === 'redacted') pass(() => target.set(res.text), undefined);
  }
  countUsage(prepared.params, response);
  return response;
}

/** Wraps a streamed answer (OpenAI chunks or Anthropic events) with the stream scanner. @internal exported for tests */
export function wrapStream(stream: any, prepared: Prepared): any {
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') return stream;
  const scanner = streamScanner({ systemPrompt: prepared.systemPrompt });
  const source = stream;
  let usage: any = null;
  let model = '';
  async function* iterate() {
    let last: any = null;
    for await (const chunk of source) {
      last = chunk;
      if (chunk?.usage) usage = chunk.usage;
      if (chunk?.model) model = chunk.model;
      if (chunk?.type === 'message_delta' && chunk.usage) usage = { ...(usage || {}), ...chunk.usage };
      if (chunk?.type === 'message_start' && chunk.message?.usage) usage = chunk.message.usage;
      // OpenAI chat completion chunk
      const delta = chunk?.choices?.[0]?.delta;
      if (delta && typeof delta.content === 'string') {
        let text = scanner.push(delta.content);
        if (chunk.choices[0].finish_reason) text += scanner.end();
        delta.content = text;
        yield chunk;
        continue;
      }
      if (chunk?.choices?.[0]?.finish_reason) {
        const rest = scanner.end();
        if (rest && chunk.choices[0].delta) chunk.choices[0].delta.content = rest;
        yield chunk;
        continue;
      }
      // Anthropic events
      if (chunk?.type === 'content_block_delta' && typeof chunk.delta?.text === 'string') {
        chunk.delta.text = scanner.push(chunk.delta.text);
        yield chunk;
        continue;
      }
      if (chunk?.type === 'content_block_stop' || chunk?.type === 'message_stop') {
        const rest = scanner.end();
        if (rest) yield { type: 'content_block_delta', index: chunk.index ?? 0, delta: { type: 'text_delta', text: rest } };
        yield chunk;
        continue;
      }
      // OpenAI responses stream
      if (chunk?.type === 'response.output_text.delta' && typeof chunk.delta === 'string') {
        chunk.delta = scanner.push(chunk.delta);
        yield chunk;
        continue;
      }
      if (chunk?.type === 'response.output_text.done' || chunk?.type === 'response.completed') {
        const rest = scanner.end();
        if (rest) yield { type: 'response.output_text.delta', delta: rest };
        yield chunk;
        continue;
      }
      yield chunk;
    }
    const rest = scanner.end();
    if (rest && last?.choices) yield { ...last, choices: [{ index: 0, delta: { content: rest }, finish_reason: null }] };
    countUsage({ ...prepared.params, model: model || prepared.params?.model }, { usage, model });
  }
  const wrapped = Object.create(source);
  wrapped[Symbol.asyncIterator] = () => iterate();
  return wrapped;
}

function providerWrapper(provider: 'openai' | 'anthropic') {
  return (original: any) =>
    async function (this: any, ...args: any[]) {
      let prepared: Prepared = { params: args[0], systemPrompt: '' };
      prepared = pass(() => prepareRequest(args[0], provider), prepared);
      args[0] = prepared.params;
      const response = await original.apply(this, args);
      if (prepared.params?.stream === true) return pass(() => wrapStream(response, prepared), response);
      return pass(() => finishResponse(response, prepared), response);
    };
}

export function patchOpenAI(mod: any): string[] {
  const done: string[] = [];
  const OpenAI = mod?.OpenAI || mod?.default || mod;
  if (wrap(OpenAI?.Chat?.Completions?.prototype, 'create', providerWrapper('openai'))) done.push('openai.chat.completions');
  if (wrap(OpenAI?.Responses?.prototype, 'create', providerWrapper('openai'))) done.push('openai.responses');
  return done;
}

export function patchAnthropic(mod: any): string[] {
  const Anthropic = mod?.Anthropic || mod?.default || mod;
  return wrap(Anthropic?.Messages?.prototype, 'create', providerWrapper('anthropic')) ? ['anthropic.messages'] : [];
}

// ---------------------------------------------------------------------------
// LangChain.

export function patchLangChainRetrievers(mod: any): string[] {
  const BaseRetriever = mod?.BaseRetriever;
  const ok = wrap(BaseRetriever?.prototype, 'invoke', (original) =>
    async function (this: any, input: any, ...rest: any[]) {
      const docs = await original.call(this, input, ...rest);
      if (!Array.isArray(docs)) return docs;
      const query = typeof input === 'string' ? input : typeof input?.query === 'string' ? input.query : '';
      const res = checkRetrieval(docs, {
        query,
        toChunk: (d: any) => ({ text: String(d?.pageContent ?? ''), id: d?.id, metadata: d?.metadata }),
        setText: (d: any, t: string) => {
          d.pageContent = t;
          return d;
        },
      });
      return res.chunks;
    },
  );
  return ok ? ['langchain.retriever'] : [];
}

export function patchLangChainTools(mod: any): string[] {
  const StructuredTool = mod?.StructuredTool;
  const ok = wrap(StructuredTool?.prototype, 'invoke', (original) =>
    async function (this: any, input: any, ...rest: any[]) {
      const name = String(this?.name || 'tool');
      const d = pass(() => authorizeTool(name), { runs: true } as any);
      if (!d.runs) return JSON.stringify({ error: 'permission_denied', tool: name, message: TOOL_DENIED_MESSAGE });
      const result = await original.call(this, input, ...rest);
      if (typeof result === 'string') {
        const scan = scanContext(result, { source: 'tool_result', tool: name });
        return scan.action === 'stripped' ? scan.text : result;
      }
      if (result && typeof result === 'object' && typeof result.content === 'string') {
        const scan = scanContext(result.content, { source: 'tool_result', tool: name });
        if (scan.action === 'stripped') result.content = scan.text;
      }
      return result;
    },
  );
  return ok ? ['langchain.tool'] : [];
}

// ---------------------------------------------------------------------------
// LlamaIndex.

export function patchLlamaIndex(mod: any): string[] {
  const BaseRetriever = mod?.BaseRetriever;
  const ok = wrap(BaseRetriever?.prototype, 'retrieve', (original) =>
    async function (this: any, params: any, ...rest: any[]) {
      const nodes = await original.call(this, params, ...rest);
      if (!Array.isArray(nodes)) return nodes;
      const query = typeof params === 'string' ? params : typeof params?.query === 'string' ? params.query : '';
      const textOfNode = (n: any) => {
        const node = n?.node ?? n;
        if (typeof node?.text === 'string') return node.text;
        try {
          return typeof node?.getContent === 'function' ? String(node.getContent()) : '';
        } catch {
          return '';
        }
      };
      const res = checkRetrieval(nodes, {
        query,
        toChunk: (n: any) => ({ text: textOfNode(n), id: (n?.node ?? n)?.id_ ?? (n?.node ?? n)?.id, metadata: (n?.node ?? n)?.metadata }),
        setText: (n: any, t: string) => {
          const node = n?.node ?? n;
          if (node && typeof node.text === 'string') node.text = t;
          return n;
        },
      });
      return res.chunks;
    },
  );
  return ok ? ['llamaindex.retriever'] : [];
}

// ---------------------------------------------------------------------------
// MCP client.

function serverOf(client: any): { name: string; version?: string } {
  try {
    const info = typeof client?.getServerVersion === 'function' ? client.getServerVersion() : null;
    if (info?.name) return { name: String(info.name), version: info.version ? String(info.version) : undefined };
  } catch {
    // unknown
  }
  return { name: 'unknown' };
}

export function patchMcpClient(mod: any): string[] {
  const Client = mod?.Client;
  const done: string[] = [];
  if (
    wrap(Client?.prototype, 'listTools', (original) =>
      async function (this: any, ...args: any[]) {
        const result = await original.apply(this, args);
        if (!result || !Array.isArray(result.tools)) return result;
        const { tools } = checkMcpTools(serverOf(this), result.tools);
        return tools.length === result.tools.length ? result : { ...result, tools };
      },
    )
  )
    done.push('mcp.listTools');
  if (
    wrap(Client?.prototype, 'callTool', (original) =>
      async function (this: any, params: any, ...rest: any[]) {
        const server = serverOf(this).name;
        const name = String(params?.name || '');
        const refused = (message: string) => ({ isError: true, content: [{ type: 'text', text: message }] });
        if (pass(() => mcpCallRefused(server, name), false)) return refused('This tool is not approved for use.');
        const d = pass(() => authorizeTool(name), { runs: true } as any);
        if (!d.runs) return refused(TOOL_DENIED_MESSAGE);
        const result = await original.call(this, params, ...rest);
        if (result && Array.isArray(result.content)) {
          let changed = false;
          const content = result.content.map((b: any) => {
            if (b?.type !== 'text' || typeof b.text !== 'string') return b;
            const scan = scanContext(b.text, { source: 'tool_result', tool: name });
            if (scan.action !== 'stripped') return b;
            changed = true;
            return { ...b, text: scan.text };
          });
          return changed ? { ...result, content } : result;
        }
        return result;
      },
    )
  )
    done.push('mcp.callTool');
  return done;
}

// ---------------------------------------------------------------------------

const MODULES: Array<[string, (mod: any) => string[]]> = [
  ['openai', patchOpenAI],
  ['@anthropic-ai/sdk', patchAnthropic],
  ['@langchain/core/retrievers', patchLangChainRetrievers],
  ['@langchain/core/tools', patchLangChainTools],
  ['llamaindex', patchLlamaIndex],
  ['@modelcontextprotocol/sdk/client/index.js', patchMcpClient],
];

/** Patches every installed module it knows. Returns what was wired. */
export function setupAiSecurity(): string[] {
  const done: string[] = [];
  for (const [name, patch] of MODULES) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      done.push(...patch(require(name)));
    } catch {
      // not installed
    }
  }
  return done;
}

/**
 * MCP and tool pinning (OWASP LLM03 supply chain): which MCP servers and
 * tools an app may use, and what each tool said about itself when it was
 * approved.
 *
 * A tool is pinned by the SHA-256 of its description and of its input
 * schema (canonical JSON). When a server lists its tools the SDK compares
 * them with the pins from the platform:
 *
 *   mcp_unknown_server  a server not on the allow-list (by name, and by
 *                       publisher and version when the pin names them)
 *   mcp_unknown_tool    a tool with no pin
 *   mcp_tool_changed    a pinned tool whose description or schema changed
 *                       since approval: the "rug pull"
 *   mcp_tool_poisoned   a description that reads like tool poisoning
 *                       (scanned when first seen and on every change)
 *
 * Every tool seen is reported to the platform (name, hashes and the
 * description itself, which is the tool author's text, not user data) so an
 * operator can approve it or its change; approval adds the pin. With mode
 * enforce and blockUnknown, unknown, changed and poisoned tools are removed
 * from the list the model sees and calls to them are refused.
 *
 * The description scan is the shared injection detector (source
 * tool_description) plus tool-rules.json, rules adapted from Cisco AI
 * Defense's mcp-scanner (Apache-2.0), plus a cross-tool shadowing check: a
 * description that names another tool of the session with a directive.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_mcp.py
 */

import { createHash } from 'crypto';
import TOOL_RULES from './tool-rules.json';
import { scanForInjection, INJECTION_RULES_VERSION } from './injection';
import type { AiSecurityPolicy, McpToolPin } from './policy';

export type McpTool = { name: string; description?: string; inputSchema?: unknown };
export type McpServerInfo = { name: string; version?: string; publisher?: string };

export type ToolVerdict = {
  tool: string;
  descriptionHash: string;
  schemaHash: string;
  status: 'pinned' | 'unknown' | 'changed';
  changed?: ('description' | 'schema')[];
  poisoning: { score: number; detected: boolean; rules: string[] };
  /** Whether enforce mode removes it from the list and refuses calls to it. */
  refuse: boolean;
};

export type ServerVerdict = {
  server: string;
  allowed: boolean;
  /** Why not: unknown name, or a publisher or version other than the pin's. */
  reason?: 'unknown' | 'publisher' | 'version';
  tools: ToolVerdict[];
};

type ToolRule = { id: string; weight: number; patterns: string[]; compiled?: RegExp[] };
const RULES: ToolRule[] = (TOOL_RULES as { rules: ToolRule[] }).rules.map((r) => ({ ...r, compiled: r.patterns.map((p) => new RegExp(p, 'iu')) }));
export const TOOL_RULES_VERSION: string = (TOOL_RULES as { version: string }).version;
const TOOL_THRESHOLD: number = (TOOL_RULES as { threshold: number }).threshold;

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** JSON with object keys sorted, so the same schema always hashes the same. */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value as object).sort();
  return `{${keys.filter((k) => (value as Record<string, unknown>)[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

export const descriptionHash = (description: string | undefined) => sha256((description || '').trim());
export const schemaHash = (schema: unknown) => sha256(canonicalJson(schema ?? null));

/**
 * How much a tool description reads like tool poisoning: the injection
 * detector's rules for tool descriptions, the tool rules, and cross-tool
 * shadowing (another tool of the session named with a directive).
 */
export function scanToolDescription(description: string, otherTools: readonly string[] = []): { score: number; detected: boolean; rules: string[] } {
  const text = (description || '').slice(0, 20_000);
  if (!text) return { score: 0, detected: false, rules: [] };
  const inj = scanForInjection(text, { source: 'tool_description' });
  let keep = 1 - inj.score;
  const rules = inj.matches.map((m) => m.rule);
  for (const rule of RULES) {
    if (rule.compiled!.some((re) => re.test(text))) {
      rules.push(rule.id);
      keep *= 1 - rule.weight;
    }
  }
  const lower = text.toLowerCase();
  const shadowed = otherTools.find((name) => {
    const n = name.toLowerCase();
    if (n.length < 3) return false;
    const at = lower.indexOf(n);
    if (at < 0) return false;
    const around = lower.slice(Math.max(0, at - 120), at + n.length + 120);
    return /\b(?:always|must|instead|never|before|whenever|override|replace|redirect)\b/.test(around);
  });
  if (shadowed) {
    rules.push('tool.cross_tool_shadowing');
    keep *= 1 - 0.6;
  }
  const score = Math.round((1 - keep) * 1000) / 1000;
  return { score, detected: score >= Math.min(TOOL_THRESHOLD, inj.threshold), rules: Array.from(new Set(rules)).sort() };
}

export { INJECTION_RULES_VERSION };

/** Compares a server's tools with the pins. Pure: no events, no network. */
export function checkServerTools(policy: AiSecurityPolicy['mcp'], server: McpServerInfo, tools: readonly McpTool[]): ServerVerdict {
  const enforce = policy.mode === 'enforce';
  const pin = policy.servers.find((s) => s.name === server.name);
  let allowed = true;
  let reason: ServerVerdict['reason'];
  if (!pin) {
    allowed = false;
    reason = 'unknown';
  } else if (pin.publisher && pin.publisher !== server.publisher) {
    allowed = false;
    reason = 'publisher';
  } else if (pin.version && pin.version !== server.version) {
    allowed = false;
    reason = 'version';
  }
  // An unpinned server is refused only with blockUnknown; a pinned one that changed publisher or version always is.
  const refuseServer = enforce && !allowed && (reason !== 'unknown' || policy.blockUnknown);
  const pins = new Map<string, McpToolPin>();
  for (const t of policy.tools) if (t.server === server.name) pins.set(t.name, t);
  const names = tools.map((t) => t.name);
  const verdicts = tools.map((tool): ToolVerdict => {
    const dh = descriptionHash(tool.description);
    const sh = schemaHash(tool.inputSchema);
    const p = pins.get(tool.name);
    let status: ToolVerdict['status'] = 'pinned';
    const changed: ('description' | 'schema')[] = [];
    if (!p) status = 'unknown';
    else {
      if (p.descriptionHash !== dh) changed.push('description');
      if (p.schemaHash !== sh) changed.push('schema');
      if (changed.length) status = 'changed';
    }
    // Scanned when first seen and when changed; a pinned, unchanged tool was scanned at approval.
    const poisoning = status === 'pinned' ? { score: 0, detected: false, rules: [] } : scanToolDescription(tool.description || '', names.filter((n) => n !== tool.name));
    const refuse = refuseServer || (enforce && (poisoning.detected || status === 'changed' || (status === 'unknown' && policy.blockUnknown)));
    return { tool: tool.name, descriptionHash: dh, schemaHash: sh, status, ...(changed.length ? { changed } : {}), poisoning, refuse };
  });
  return { server: server.name, allowed, ...(reason ? { reason } : {}), tools: verdicts };
}

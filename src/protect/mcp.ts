/**
 * Shield Protect -- the pre-execution check on an MCP client's tools/call.
 *
 * The MCP instrumentation records every call; this is the one place it can
 * refuse one. The tool's arguments, as canonical JSON, go through the
 * preflight guards init() installed, under the process's Protect mode:
 * observe records, warn records and logs, enforced refuses (and refuses when
 * a guard fails, or when the arguments are past the scan bound). With no
 * pipeline or no mode, nothing changes: the call is recorded as before.
 *
 * Must stay in sync with: sdk/python/src/shield360/protect/_mcp.py
 */

import Shield360Config from '../config';
import { GuardAction, GuardDeniedError, GuardPhase } from '../guard/base';
import { canonicalJson } from './index';
import { ProtectDeniedError, currentProtectMode, refuses } from './mode';

export function checkMcpToolCall(toolName: string, toolArguments: unknown): void {
  const mode = currentProtectMode();
  const pipeline = Shield360Config.guardPipeline;
  if (!pipeline || mode === undefined) return;
  const text = canonicalJson(toolArguments ?? {});
  const bound = pipeline.scanBound();
  if (refuses(mode) && bound > 0 && text.length > bound) {
    throw new ProtectDeniedError('oversized', `Shield360 Protect refused MCP tool ${toolName}: ${text.length} characters of arguments is more than its guards scan (${bound}).`);
  }
  let result;
  try {
    result = pipeline.evaluate(text, GuardPhase.PREFLIGHT);
  } catch (e) {
    if (refuses(mode)) throw new ProtectDeniedError('guard_failed', `Shield360 Protect refused MCP tool ${toolName}: a guard failed and enforced mode does not run unchecked calls.`);
    throw e;
  }
  if (result.action !== GuardAction.DENY) return;
  if (refuses(mode)) throw new GuardDeniedError(result);
  if (mode === 'warn') console.warn(`[shield360] Protect (warn mode): MCP tool ${toolName} would have been refused: ${result.explanation}`);
}

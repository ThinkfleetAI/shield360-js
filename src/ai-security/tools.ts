/**
 * Per end-user tool permissions (OWASP LLM06 excessive agency): a tool call
 * is authorized for the signed-in end user before it executes, the way
 * Shield Protect authorizes an agent's call at the gateway: decide, record,
 * then run (or refuse).
 *
 *   const lookup = aiSecurity.defineTool({
 *     name: 'refund_order',
 *     permissions: { roles: ['support_lead'], attributes: { region: ['eu'] } },
 *     execute: async (args) => ...,
 *   });
 *
 * The end user is the one in effect (aiSecurity.withEndUser({ tenantId,
 * userId, roles, attributes }, fn)). A rule allows when every condition it
 * names holds: one of `roles`, each attribute's value among those listed,
 * the tenant among `tenants`; `deny` refuses everyone. Rules from the
 * platform replace the code's rule for the same tool. A tool with no rule is
 * allowed, unless defaultDeny is set. No end user means no roles: a rule
 * with conditions refuses.
 *
 * In enforce mode a refused call does not run; the wrapper returns a tool
 * error the model can read ({ error: 'permission_denied', message }) instead
 * of throwing, so the agent can tell the user. In monitor mode the call runs
 * and the refusal is reported. Every refusal is recorded; allows are counted
 * only on request (recordAllowed), to keep the stream small.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_tools.py
 */

import type { AiSecurityPolicy, ToolRule } from './policy';
import type { EndUser } from './context';

export type ToolDecision = {
  allowed: boolean;
  /** Whether the call runs: refused calls run in monitor mode. */
  runs: boolean;
  reason: 'no_rule' | 'allowed' | 'denied' | 'role' | 'attribute' | 'tenant' | 'default_deny' | 'off';
  tool: string;
};

export const TOOL_DENIED_MESSAGE = 'This action is not permitted for the current user.';

export function decideTool(
  policy: AiSecurityPolicy['toolPermissions'],
  tool: string,
  codeRule: ToolRule | undefined,
  user: EndUser | null,
  tenant: string | null,
): ToolDecision {
  if (policy.mode === 'off') return { allowed: true, runs: true, reason: 'off', tool };
  const rule = policy.rules[tool] ?? codeRule;
  const enforce = policy.mode === 'enforce';
  const refuse = (reason: ToolDecision['reason']): ToolDecision => ({ allowed: false, runs: !enforce, reason, tool });
  if (!rule) return policy.defaultDeny ? refuse('default_deny') : { allowed: true, runs: true, reason: 'no_rule', tool };
  if (rule.deny) return refuse('denied');
  if (rule.roles?.length && !(user?.roles || []).some((r) => rule.roles!.includes(r))) return refuse('role');
  if (rule.attributes) {
    for (const [name, values] of Object.entries(rule.attributes)) {
      const have = user?.attributes?.[name];
      if (have === undefined || !values.includes(have)) return refuse('attribute');
    }
  }
  if (rule.tenants?.length && (!tenant || !rule.tenants.includes(tenant))) return refuse('tenant');
  return { allowed: true, runs: true, reason: 'allowed', tool };
}

/** What a refused tool call returns to the model. */
export function toolDeniedResult(tool: string, reason: ToolDecision['reason']) {
  return { error: 'permission_denied', tool, reason, message: TOOL_DENIED_MESSAGE };
}

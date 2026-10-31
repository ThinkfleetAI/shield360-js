/**
 * The automatic budget check: before each call to a provider the SDK knows
 * (the same methods the auto-guards wrap), ask Shield360.budgets.check() for
 * the call's model and refuse the call with BudgetExceededError when a
 * budget blocks it or its throttle is spent. On by init({ budgetCheck: true })
 * or SHIELD360_BUDGET_CHECK=1; off by default.
 *
 * The check is cached (see ./index.ts), so it does not reach the platform on
 * every call; it fails open unless asked to fail closed.
 *
 * Must stay in sync with: sdk/python/src/shield360/budgets.py (setup_auto_budget_check)
 */

import { GUARDED_METHODS, resolveProto, type GuardedMethod } from '../guard/integration';
import { BudgetExceededError, defaultBudgetClient, type BudgetClient, type BudgetCheckResult } from './index';

const WRAPPED = Symbol.for('shield360.budgetCheck');

/** The model a provider call names, when it names one. */
export function modelOf(params: unknown): string | undefined {
  if (!params || typeof params !== 'object') return undefined;
  const p = params as Record<string, unknown>;
  if (typeof p.model === 'string') return p.model;
  // Bedrock's send(command) carries the model on the command's input.
  const input = p.input as Record<string, unknown> | undefined;
  if (input && typeof input === 'object' && typeof input.modelId === 'string') return input.modelId;
  return undefined;
}

export type AutoBudgetReport = { wrapped: string[] };

/** Wraps the known providers' methods with the budget check. Idempotent per method. */
export function setupAutoBudgetCheck(
  options: { client?: BudgetClient; methods?: GuardedMethod[]; onWarn?: (result: BudgetCheckResult) => void } = {},
): AutoBudgetReport {
  const client = options.client ?? defaultBudgetClient();
  const wrapped = new Set<string>();
  for (const { npmPackage, protoPath, methodName } of options.methods ?? GUARDED_METHODS) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require(npmPackage);
      const proto = resolveProto(mod, protoPath);
      if (!proto || typeof proto[methodName] !== 'function' || proto[methodName][WRAPPED]) continue;
      const original = proto[methodName];
      const checked = async function (this: unknown, ...args: unknown[]) {
        const result = await client.check({ model: modelOf(args[0]) });
        if (!result.allowed) throw new BudgetExceededError(result);
        if (result.action === 'warn' && result.reason) options.onWarn?.(result);
        return original.apply(this, args);
      };
      (checked as unknown as Record<symbol, boolean>)[WRAPPED] = true;
      proto[methodName] = checked;
      wrapped.add(npmPackage);
    } catch {
      // not installed
    }
  }
  return { wrapped: Array.from(wrapped) };
}

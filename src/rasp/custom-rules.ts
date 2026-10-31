/**
 * Custom rules (README "Custom rules"): the organization's own rules, written
 * in the expression language of rule-expr.ts and delivered inside the signed
 * config (`customRules`). They are data: each expression is parsed and
 * type-checked when the config arrives and evaluated against the request (or
 * a built-in finding) as a value. An invalid rule is skipped with one
 * warning and never breaks the config; evaluation fails open.
 *
 * This file turns rules and the request context into the language's terms;
 * the engine and capture decide what a match does.
 */
import { routeOf, type RaspContext } from './context';
import { compileRuleExpr, DEFAULT_RULE_BUDGET, evaluateRuleExpr, type CompiledRuleExpr, type RuleBudget, type RuleSubject } from './rule-expr';
import type { Finding, RaspInput, RaspMode } from './types';

export const MAX_CUSTOM_RULES = 64;
export const MAX_RULE_APPS = 32;
/** Lower-case, so the event rule `custom.<id>` fits the platform's rule shape. */
export const CUSTOM_RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export const CUSTOM_RULE_PREFIX = 'custom.';
export const CUSTOM_RULE_ACTIONS = ['block', 'monitor', 'alert'] as const;
export type CustomRuleAction = (typeof CUSTOM_RULE_ACTIONS)[number];

export type CustomRule = {
  id: string;
  name: string;
  action: CustomRuleAction;
  apps?: string[];
  expr: CompiledRuleExpr;
};

export type SkippedRule = { index: number; id?: string; reason: string };

const warned = new Set<string>();

function defaultWarn(s: SkippedRule): void {
  console.warn(`Shield360 RASP: custom rule ${s.id ? `"${s.id}"` : `#${s.index + 1}`} was skipped (${s.reason}); the other rules apply.`);
}

/** Tests only: lets the once-per-rule warnings fire again. */
export function resetCustomRuleWarnings(): void {
  warned.clear();
}

/**
 * The rules of a signed config that apply to this app: invalid rules are
 * skipped (one warning per rule and reason, per process), disabled rules and
 * rules scoped to other apps are left out silently. At most 64.
 */
export function parseCustomRules(raw: unknown, app: string, warn: (s: SkippedRule) => void = defaultWarn): CustomRule[] {
  if (!Array.isArray(raw)) return [];
  const out: CustomRule[] = [];
  const ids = new Set<string>();
  const skip = (s: SkippedRule, expression?: unknown) => {
    const key = `${s.id ?? s.index}\u0000${s.reason}\u0000${typeof expression === 'string' ? expression : ''}`;
    if (warned.has(key)) return;
    if (warned.size > 1024) warned.clear();
    warned.add(key);
    try {
      warn(s);
    } catch {
      // never
    }
  };
  for (let index = 0; index < raw.length; index++) {
    try {
      const r = raw[index] as Record<string, unknown> | null;
      if (!r || typeof r !== 'object' || Array.isArray(r)) {
        skip({ index, reason: 'not an object' });
        continue;
      }
      const id = typeof r.id === 'string' && CUSTOM_RULE_ID.test(r.id) ? r.id : undefined;
      if (!id) {
        skip({ index, reason: 'invalid id' });
        continue;
      }
      if (ids.has(id)) {
        skip({ index, id, reason: 'duplicate id' });
        continue;
      }
      ids.add(id);
      if (typeof r.enabled !== 'boolean') {
        skip({ index, id, reason: 'invalid enabled flag' });
        continue;
      }
      if (!(CUSTOM_RULE_ACTIONS as readonly unknown[]).includes(r.action)) {
        skip({ index, id, reason: 'invalid action' });
        continue;
      }
      if (r.name !== undefined && typeof r.name !== 'string') {
        skip({ index, id, reason: 'invalid name' });
        continue;
      }
      if (r.apps !== undefined && r.apps !== null && !(Array.isArray(r.apps) && r.apps.length <= MAX_RULE_APPS && r.apps.every((a) => typeof a === 'string'))) {
        skip({ index, id, reason: 'invalid apps' });
        continue;
      }
      const compiled = compileRuleExpr(r.expression);
      if (!compiled.ok) {
        skip({ index, id, reason: `expression: ${compiled.error.code}` }, r.expression);
        continue;
      }
      if (!r.enabled) continue;
      const apps = Array.isArray(r.apps) && r.apps.length ? (r.apps as string[]) : undefined;
      if (apps && !apps.includes(app)) continue;
      if (out.length >= MAX_CUSTOM_RULES) {
        skip({ index, id, reason: 'more than 64 rules' });
        continue;
      }
      out.push({ id, name: typeof r.name === 'string' ? r.name : id, action: r.action as CustomRuleAction, ...(apps ? { apps } : {}), expr: compiled.expr });
    } catch {
      skip({ index, reason: 'unreadable' });
    }
  }
  return out;
}

/** The most a rule does: `alert` reports like `monitor` (the platform raises the alert). */
export function actionMode(a: CustomRuleAction): RaspMode {
  return a === 'block' ? 'block' : 'monitor';
}

/** The finding a matched rule reports (attack type `custom_rule`, rule `custom.<id>`). */
export function customFinding(rule: CustomRule, input?: RaspInput): Finding {
  return { attack: 'custom_rule', rule: `${CUSTOM_RULE_PREFIX}${rule.id}`, action: actionMode(rule.action), ...(input ? { input } : {}) };
}

const joined = (v: string | string[] | undefined): string | undefined => (v === undefined ? undefined : Array.isArray(v) ? v.join(', ') : String(v));

/** The request as the language sees it (README "Custom rules: fields"). */
export function requestSubject(ctx: RaspContext | undefined, app: string, inputs?: RaspInput[]): RuleSubject {
  if (!ctx) return { app, inputs: [] };
  const list = inputs ?? ctx.inputs;
  const headers: Record<string, string> = {};
  const raw = ctx.vp?.req.headers;
  if (raw) {
    for (const k of Object.keys(raw)) {
      const v = joined(raw[k]);
      if (v !== undefined) headers[k.toLowerCase()] = v;
    }
  }
  const query: Record<string, string> = {};
  const body: Record<string, string> = {};
  for (const i of list) {
    if (i.source !== 'request') continue;
    if (i.key.startsWith('query.')) {
      const k = i.key.slice(6);
      if (!Object.prototype.hasOwnProperty.call(query, k)) query[k] = i.value;
    } else if (i.key.startsWith('body.')) {
      const k = i.key.slice(5);
      if (!Object.prototype.hasOwnProperty.call(body, k)) body[k] = i.value;
    }
  }
  const path = ctx.path ?? null;
  return {
    app,
    request: ctx.inRequest
      ? {
          method: ctx.method ? ctx.method.toUpperCase() : null,
          path,
          route: ctx.route ?? (path ? routeOf(path) : null),
          ip: ctx.ip ?? null,
          headers,
          query,
          body,
        }
      : null,
    inputs: list.map((i) => ({ value: i.value, key: i.key, source: i.source })),
  };
}

/** Per-request evaluation state, kept on the context. */
export type CustomRuleState = { matched: Set<string>; budget: RuleBudget; ranHead: boolean; ranBody: boolean };

export function ruleState(ctx: RaspContext): CustomRuleState {
  if (!ctx.rules) ctx.rules = { matched: new Set(), budget: { steps: DEFAULT_RULE_BUDGET }, ranHead: false, ranBody: false };
  return ctx.rules;
}

export type RuleMatch = { rule: CustomRule; input?: RaspInput };

/**
 * The request rules to judge in a phase, matched in order. `head`: every
 * request rule that does not read the body. `body`: rules that read the body,
 * and rules reading `input.*` that did not match at `head` (the body added
 * inputs). A rule matches at most once per request.
 */
export function matchRequestRules(rules: CustomRule[], ctx: RaspContext, phase: 'head' | 'body', subject: RuleSubject): RuleMatch[] {
  const st = ruleState(ctx);
  const out: RuleMatch[] = [];
  for (const rule of rules) {
    const e = rule.expr;
    if (st.budget.steps < 0) break;
    if (e.phase !== 'request' || st.matched.has(rule.id)) continue;
    if (phase === 'head' ? e.usesBody : !(e.usesBody || e.usesInput)) continue;
    const r = evaluateRuleExpr(e, subject, st.budget);
    if (r.exhausted) break;
    if (!r.matched) continue;
    st.matched.add(rule.id);
    out.push({ rule, input: r.input as RaspInput | undefined });
  }
  return out;
}

/** The finding rules a built-in finding matches, in order. */
export function matchFindingRules(rules: CustomRule[], subject: RuleSubject, budget: RuleBudget): RuleMatch[] {
  const out: RuleMatch[] = [];
  for (const rule of rules) {
    if (budget.steps < 0) break;
    if (rule.expr.phase !== 'finding') continue;
    const r = evaluateRuleExpr(rule.expr, subject, budget);
    if (r.exhausted) break;
    if (r.matched) out.push({ rule, input: r.input as RaspInput | undefined });
  }
  return out;
}

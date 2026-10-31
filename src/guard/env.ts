/**
 * Guards from the environment, for apps started without code changes
 * (`--require shield360/register`), where `init({ guards })` is never called:
 *
 *   SHIELD360_GUARDS=prompt_injection:block,pii:redact,moderation:warn
 *
 * Each entry is a guard kind and, after a colon, its action (allow, warn,
 * redact, block or deny; block is deny). Without an action a guard keeps its
 * own default. Entries that cannot be read are skipped with a warning, so a
 * typo never stops the app; the rest still run.
 */
import { Guard, GuardAction } from './base';
import { Moderation } from './moderation';
import { PII } from './pii';
import { PromptInjection } from './prompt-injection';

const KINDS: Record<string, (action?: GuardAction) => Guard> = {
  prompt_injection: (action) => new PromptInjection(action ? { action } : {}),
  pii: (action) => new PII(action ? { action } : {}),
  moderation: (action) => new Moderation(action ? { action } : {}),
};

const ACTIONS: Record<string, GuardAction> = {
  allow: GuardAction.ALLOW,
  warn: GuardAction.WARN,
  redact: GuardAction.REDACT,
  block: GuardAction.DENY,
  deny: GuardAction.DENY,
};

/** The guards SHIELD360_GUARDS names, or undefined when it names none. */
export function guardsFromEnv(value: string | undefined, warn: (message: string) => void = console.warn): Guard[] | undefined {
  if (!value || !value.trim()) return undefined;
  const guards = new Map<string, Guard>();
  for (const raw of value.split(',')) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;
    const [kind, action, extra] = entry.split(':').map((part) => part.trim());
    const make = KINDS[kind.replace(/-/g, '_')];
    const mode = action ? ACTIONS[action] : undefined;
    if (!make || (action && !mode) || extra !== undefined) {
      warn(`[shield360] SHIELD360_GUARDS: "${raw.trim()}" is not a guard (kinds: ${Object.keys(KINDS).join(', ')}; actions: ${Object.keys(ACTIONS).join(', ')}); skipped.`);
      continue;
    }
    // A kind named twice: the last entry wins.
    guards.set(kind.replace(/-/g, '_'), make(mode));
  }
  return guards.size ? Array.from(guards.values()) : undefined;
}

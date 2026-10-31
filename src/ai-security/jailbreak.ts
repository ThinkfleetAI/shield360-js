/**
 * Jailbreak detection on what end users send: each user turn with the
 * shared injection rules (roleplay, jailbreak and obfuscation categories
 * among them, see rules.json), and the conversation as a whole for
 * multi-turn escalation.
 *
 * Multi-turn escalation is a heuristic over the last MAX_TURNS user turns,
 * shaped like a flow rule over turns (the idea of Cisco AI Defense's
 * project-quarry, Apache-2.0: rules over message order with counts):
 *
 *   accumulation  two or more turns each match a rule without reaching the
 *                 threshold alone, and together (1 - product(1 - score))
 *                 they do, with at least one roleplay, jailbreak or
 *                 override match among them;
 *   split         the last JOINED turns read together (joined with a
 *                 space) match what no single turn does: a request cut
 *                 into pieces across messages;
 *   continuation  a turn sets up a persona or fiction (a roleplay or
 *                 jailbreak match, or a story or role-play framed as having
 *                 no rules), and a later turn asks to continue it, drop the
 *                 act or do it "for real".
 *
 * Heuristics can be evaded; this raises the cost of the common crescendo
 * patterns, it does not prove a conversation safe.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_jailbreak.py
 */

import { scanForInjection, INJECTION_THRESHOLD } from './injection';

export const MAX_TURNS = 8;
/** Turns read together by the split check. */
export const JOINED = 3;

export type JailbreakVerdict = {
  detected: boolean;
  how: 'none' | 'single_turn' | 'accumulation' | 'split' | 'continuation';
  score: number;
  rules: string[];
  categories: string[];
};

const ESCALATING = new Set(['roleplay', 'jailbreak', 'override']);
const SETUP = new Set(['roleplay', 'jailbreak']);
const FRAME = /\b(?:story|role-?play|pretend|character|fiction(?:al)?|persona|game|scenario)\b/iu;
const LAWLESS = /\b(?:unfiltered|uncensored|unrestricted|amoral|evil|no\s+(?:rules|limits|restrictions|filters|ethics|morals)|without\s+(?:any\s+)?(?:rules|limits|restrictions|filters))\b/iu;
const CONTINUE =
  /\b(?:continue|keep\s+going|go\s+on|stay\s+in\s+character|now\s+(?:do|say|write|tell|explain)\s+(?:it|that|this)\s+(?:for\s+real|without)|drop\s+the\s+(?:act|pretence|pretense|disclaimer)|(?:same|that)\s+but\s+(?:real|for\s+real|detailed|step\s+by\s+step)|what\s+would\s+(?:he|she|they|it|the\s+character)\s+say\s+next)\b/iu;

export function assessTurns(turns: readonly string[]): JailbreakVerdict {
  const recent = turns.filter((t) => typeof t === 'string' && t.trim()).slice(-MAX_TURNS);
  const none: JailbreakVerdict = { detected: false, how: 'none', score: 0, rules: [], categories: [] };
  if (!recent.length) return none;
  const scans = recent.map((t) => scanForInjection(t, { source: 'prompt' }));
  const last = scans[scans.length - 1];
  if (last.detected) {
    return { detected: true, how: 'single_turn', score: last.score, rules: last.matches.map((m) => m.rule), categories: last.categories };
  }
  const hits = scans.filter((s) => s.matches.length > 0);
  const rules = Array.from(new Set(hits.flatMap((s) => s.matches.map((m) => m.rule)))).sort();
  const categories = Array.from(new Set(hits.flatMap((s) => s.categories))).sort();
  if (hits.length >= 2) {
    const combined = Math.round((1 - hits.reduce((keep, s) => keep * (1 - s.score), 1)) * 1000) / 1000;
    if (combined >= INJECTION_THRESHOLD && categories.some((c) => ESCALATING.has(c))) {
      return { detected: true, how: 'accumulation', score: combined, rules, categories };
    }
  }
  if (recent.length >= 2) {
    const joined = scanForInjection(recent.slice(-JOINED).join(' '), { source: 'prompt' });
    if (joined.detected) {
      return { detected: true, how: 'split', score: joined.score, rules: joined.matches.map((m) => m.rule), categories: joined.categories };
    }
  }
  const setupAt = scans.findIndex((s, i) => s.categories.some((c) => SETUP.has(c)) || (FRAME.test(recent[i]) && LAWLESS.test(recent[i])));
  if (setupAt >= 0 && setupAt < recent.length - 1 && CONTINUE.test(recent[recent.length - 1])) {
    const score = Math.max(INJECTION_THRESHOLD, scans[setupAt].score);
    return { detected: true, how: 'continuation', score, rules, categories: categories.length ? categories : ['roleplay'] };
  }
  return none;
}

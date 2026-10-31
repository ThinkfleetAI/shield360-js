/**
 * Passive IAST: the slot a check's detectors write a vulnerability into
 * (README "Passive IAST"). engine.ts arms a slot for one check when passive
 * IAST is on and the check is sampled; the detectors in detect.ts call
 * `noteVulnerability` with a rule from iast-rules.ts, which runs only while a
 * slot is armed. Unarmed, the cost is one comparison per detector call.
 */
import type { Vuln } from './iast-rules';

export type IastSlot = { prev: IastSlot | null; vuln: Vuln | null; closed: boolean };

let current: IastSlot | null = null;

/** Arms a slot for the check about to run (nested checks keep their own). */
export function armIastSlot(): IastSlot {
  const slot: IastSlot = { prev: current, vuln: null, closed: false };
  current = slot;
  return slot;
}

/** Disarms a slot; returns the vulnerability noted in it, once. Idempotent. */
export function closeIastSlot(slot: IastSlot): Vuln | null {
  if (slot.closed) return null;
  slot.closed = true;
  if (current === slot) current = slot.prev;
  return slot.vuln;
}

/** Whether a slot is armed for the running check. */
export function iastArmed(): boolean {
  return current !== null;
}

/**
 * Runs a vulnerability rule when a slot is armed and keeps its first result.
 * Never throws: a rule that fails is ignored.
 */
export function noteVulnerability(rule: () => Vuln | null): void {
  const slot = current;
  if (!slot || slot.vuln) return;
  try {
    slot.vuln = rule();
  } catch {
    // passive IAST never breaks a check
  }
}

/** Runs fn with a slot armed and returns what it returned and the vulnerability noted (tests, conformance). */
export function captureVulnerability<T>(fn: () => T): { result: T; vuln: Vuln | null } {
  const slot = armIastSlot();
  try {
    const result = fn();
    return { result, vuln: closeIastSlot(slot) };
  } finally {
    closeIastSlot(slot);
  }
}

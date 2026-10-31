/**
 * State shared between the zero-code entry (`shield360/register`) and
 * `Shield360.init()`: once the entry has started Shield360, a later
 * `init()` in the app's own code is a no-op. Kept on `globalThis` so that two
 * copies of the package in one process (a bundled one and an installed one)
 * agree.
 */
const STARTED = '__shield360_zero_code_started__';
const WARNED = '__shield360_zero_code_init_warned__';

type ZeroCodeGlobal = typeof globalThis & { [STARTED]?: boolean; [WARNED]?: boolean };

/** Records that the zero-code entry has initialised Shield360. */
export function markZeroCodeStarted(): void {
  (globalThis as ZeroCodeGlobal)[STARTED] = true;
}

/** Whether the zero-code entry has initialised Shield360 in this process. */
export function zeroCodeStarted(): boolean {
  return (globalThis as ZeroCodeGlobal)[STARTED] === true;
}

/** One log line, the first time the app's own `init()` is skipped. */
export function noteSkippedInit(): void {
  const g = globalThis as ZeroCodeGlobal;
  if (g[WARNED]) return;
  g[WARNED] = true;
  console.warn(
    'Shield360: already started by shield360/register from SHIELD360_* environment variables; this Shield360.init() call is ignored.',
  );
}

/** Tests only. */
export function resetZeroCodeState(): void {
  const g = globalThis as ZeroCodeGlobal;
  delete g[STARTED];
  delete g[WARNED];
}

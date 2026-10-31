/**
 * Marks RASP's own library wrappers, so a sink rule never wraps a function a
 * built-in hook already checks (one check per call).
 */
const wrappers = new WeakSet<object>();

export function markRaspWrapper(fn: object): void {
  wrappers.add(fn);
}

export function isRaspWrapper(fn: unknown): boolean {
  return typeof fn === 'function' && wrappers.has(fn);
}

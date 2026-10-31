/**
 * A package the app `import`s reaches an instrumentation through the ESM loader hook as its module
 * namespace. For a CommonJS package the exports object the hooks patch is the namespace's
 * `default` (its named exports are only what Node's static scan found: none for pg's
 * `module.exports = new PG()`), so the hooks patch that.
 */
export function moduleExports(exports: unknown): unknown {
  if (exports && typeof exports === 'object' && (exports as Record<symbol, unknown>)[Symbol.toStringTag] === 'Module') {
    const def = (exports as { default?: unknown }).default;
    if (def && (typeof def === 'object' || typeof def === 'function')) return def;
  }
  return exports;
}

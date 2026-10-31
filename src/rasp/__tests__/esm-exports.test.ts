import { moduleExports } from '../hooks/esm';

const namespace = (props: Record<string, unknown>) =>
  Object.freeze(Object.assign(Object.create(null), props, { [Symbol.toStringTag]: 'Module' }));

describe('moduleExports', () => {
  it("gives a CommonJS package's exports object for its ESM namespace", () => {
    const cjs = { Client: function Client() {} };
    expect(moduleExports(namespace({ default: cjs }))).toBe(cjs);
  });

  it('leaves CommonJS exports, and namespaces without an object default, as they are', () => {
    const cjs = { Client: function Client() {} };
    expect(moduleExports(cjs)).toBe(cjs);
    const esm = namespace({ default: 'text', render: () => '' });
    expect(moduleExports(esm)).toBe(esm);
    const noDefault = namespace({ render: () => '' });
    expect(moduleExports(noDefault)).toBe(noDefault);
    expect(moduleExports(undefined)).toBeUndefined();
  });
});

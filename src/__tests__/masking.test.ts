import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import * as masking from '../masking';
import { maskSnippet } from '../rasp/engine';

/**
 * The masking contract (sdk/rasp/README.md, "Masking"), held to the shared
 * cases in sdk/rasp/testdata/masking.json like every other SDK.
 */
type Cases = {
  text: { name: string; in: string; out: string }[];
  limited: { name: string; in: string; limit: number; out: string }[];
  keys: { key: string; sensitive: boolean }[];
  values: { key: string; value: unknown; out: unknown }[];
  snippets: { in: string; out: string }[];
};

function load(): Cases {
  for (const candidate of [join(__dirname, '../../../rasp/testdata/masking.json'), join(__dirname, '../../rasp/testdata/masking.json')]) {
    if (existsSync(candidate)) return JSON.parse(readFileSync(candidate, 'utf8')) as Cases;
  }
  throw new Error('sdk/rasp/testdata/masking.json not found');
}

const cases = load();
const m = masking as unknown as Record<string, (...args: unknown[]) => unknown>;

describe('masking contract', () => {
  it.each(cases.text.map((c) => [c.name, c] as const))('text: %s', (_name, c) => {
    expect(m.maskSecrets(c.in)).toBe(c.out);
  });

  it.each(cases.limited.map((c) => [c.name, c] as const))('limited: %s', (_name, c) => {
    expect(m.maskText(c.in, c.limit)).toBe(c.out);
  });

  it.each(cases.keys.map((c) => [c.key, c] as const))('key: %s', (_name, c) => {
    expect(m.isSensitiveKey(c.key)).toBe(c.sensitive);
  });

  it.each(cases.values.map((c) => [c.key, c] as const))('value: %s', (_name, c) => {
    expect(m.maskValue(c.key, c.value, 4096)).toEqual(c.out);
  });

  it.each(cases.snippets.map((c) => [c.in.slice(0, 20), c] as const))('snippet: %s', (_name, c) => {
    expect(maskSnippet(c.in)).toBe(c.out);
  });
});

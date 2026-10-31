import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// Fake sensitive values, assembled at run time so no key-shaped literal sits in the repository.
const rep = (s: string, n: number) => s.repeat(n);
export const FAKE: Record<string, string> = {
  OPENAI_KEY: ['sk', 'proj', rep('Ab3dE', 8)].join('-'),
  PG_URL: ['postgres', '://admin:', 'pw', rep('x', 6), '@db.internal.example:5432/prod'].join(''),
  PEM_HEADER: ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' '),
  AWS_KEY: ['AK', 'IA', 'IOSFODNN7', 'EXAMPLE'].join(''),
  GITHUB_TOKEN: ['ghp', rep('A1b2C3', 6)].join('_'),
  CARD: ['4111', '1111', '1111', '1111'].join(' '),
  SSN: ['123', '45', '6789'].join('-'),
  JWT: ['ey' + 'J' + rep('hbGci', 3), 'ey' + 'J' + rep('zdWIi', 3), rep('sIgNaTuRe', 2)].join('.'),
};

export const fill = (text: string) => text.replace(/\{\{([A-Z_]+)\}\}/g, (_m, k: string) => FAKE[k] ?? '');

export const TESTDATA = join(__dirname, 'testdata');
export const readJson = <T>(name: string): T => JSON.parse(readFileSync(join(TESTDATA, name), 'utf8')) as T;

/** The shared injection corpus and golden results, when the repository is checked out whole. */
export const INJECTION_DIR = join(__dirname, '../../../../../cli/internal/coding/injection');
export const haveInjectionCorpus = existsSync(join(INJECTION_DIR, 'testdata/expected.json'));

export function rate(n: number, d: number): string {
  return `${n}/${d} = ${d ? ((n / d) * 100).toFixed(1) : '0.0'}%`;
}

/**
 * Credential masking shared by RASP snippets and application logs.
 *
 * The contract is sdk/rasp/README.md ("Masking"), checked by
 * sdk/rasp/testdata/masking.json; every Shield360 SDK applies it the same
 * way. In short:
 *
 * 1. A credential pair (`password=x`, `"api_key": "x"`, `Authorization:
 *    Bearer x`) keeps its name and loses its value, quotes kept.
 * 2. A `Bearer <credential>` keeps the word and loses the credential.
 * 3. A run of 20 or more token characters (`A-Z a-z 0-9 _ - + / = .`) is
 *    masked when it is opaque: it holds `+`, ends in `=`, or one of its pieces
 *    (split on `. / - _ =`) of 8 or more characters is not a readable word.
 *    Dotted, slashed and CamelCase identifiers (class names, package and file
 *    paths) survive; keys, hashes, base64, JWTs and UUIDs do not.
 *
 * Masking runs over the value plus 1,024 characters of look-ahead before it
 * is cut, so a credential that crosses the cut is never left half visible.
 * An attribute whose name is a credential (`password`, `x-api-key`,
 * `sessionId`...) is masked whole; lists and maps are masked item by item.
 */

export const LOOKAHEAD = 1024;
export const MASK = '***';

const KEY =
  '(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key' +
  '|client[_-]?secret|auth(?:orization)?|bearer|cookie|session(?:[_-]?id)?|credentials?)';
const PAIR = new RegExp(
  '(' +
    KEY +
    `["']?[ \\t]*[=:][ \\t]*)` +
    `("(?:[^"\\\\]|\\\\.)*"?|'(?:[^'\\\\]|\\\\.)*'?` +
    `|(?:(?:bearer|basic|digest|negotiate|token)[ \\t]+)?[^ \\t\\r\\n\\f\\x0B&;,'"]+)`,
  'gi'
);
const BEARER = /(bearer[ \t]+)[A-Za-z0-9._~+/=-]+/gi;
const RUN = /[A-Za-z0-9_\-+/=.]{20,}/g;
const PIECE_SPLIT = /[./\-_=]/;
const READABLE = /^[A-Za-z]+[0-9]{0,4}$/;
const VOWELS = new Set('aeiouyAEIOUY');

const SENSITIVE_WORDS = new Set([
  'password',
  'passwd',
  'passphrase',
  'pwd',
  'secret',
  'token',
  'apikey',
  'authorization',
  'cookie',
  'credential',
  'credentials',
  'bearer',
  'otp',
  'signature',
  'privatekey',
  'sessionid',
  'jwt',
  'accesskey',
  'secretkey',
]);
const SENSITIVE_PAIRS = new Set(['api key', 'private key', 'access key', 'secret key', 'session id']);

const isUpper = (c: string) => c >= 'A' && c <= 'Z';
const isLower = (c: string) => c >= 'a' && c <= 'z';
const isDigit = (c: string) => c >= '0' && c <= '9';

function readable(piece: string): boolean {
  if (!READABLE.test(piece)) return false;
  let letters = 0;
  let vowels = 0;
  let upperRun = 0;
  let longest = 0;
  let transitions = 0;
  let previous = '';
  for (const c of piece) {
    if (isDigit(c)) continue;
    letters += 1;
    if (VOWELS.has(c)) vowels += 1;
    if (isUpper(c)) {
      upperRun += 1;
      longest = Math.max(longest, upperRun);
      if (isLower(previous)) transitions += 1;
    } else {
      upperRun = 0;
    }
    previous = c;
  }
  return vowels * 5 >= letters && longest <= 6 && transitions * 3 <= letters;
}

/** Whether a run of 20+ token characters reads as a secret rather than an identifier. */
export function isOpaque(run: string): boolean {
  if (run.includes('+') || run.endsWith('=')) return true;
  return run.split(PIECE_SPLIT).some((p) => p.length >= 8 && !readable(p));
}

function maskCredentials(value: string): string {
  return value
    .replace(PAIR, (_m, name: string, v: string) => {
      if (v.startsWith('"')) return `${name}"${MASK}"`;
      if (v.startsWith("'")) return `${name}'${MASK}'`;
      return name + MASK;
    })
    .replace(BEARER, (_m, word: string) => word + MASK);
}

/** `value` with credentials and opaque tokens masked; nothing is cut. */
export function maskSecrets(value: string): string {
  return maskCredentials(value).replace(RUN, (run) => (isOpaque(run) ? MASK : run));
}

// Allow-list targets (README "Masking", "Targets"): the strict long-token rule,
// piece by piece between `/` and `.`.
const TARGET_LONG_TOKEN = /[A-Za-z0-9_\-+/]{20,}={0,2}/g;
export const MAX_TARGET_LENGTH = 256;

/**
 * An allow-list target as an event carries it: the credential rules on the
 * whole target, a `/` segment holding `@` (userinfo) as `***`, then the
 * strict long-token rule piece by piece between `/` and `.`; never cut.
 * Undefined when empty, holding a control character or longer than 256
 * characters.
 */
export function maskTarget(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const out = maskCredentials(raw)
    .split('/')
    .map((segment) => (segment.includes('@') ? MASK : segment))
    .join('/')
    .split(/([/.])/)
    .map((piece) => (piece === '/' || piece === '.' ? piece : piece.replace(TARGET_LONG_TOKEN, MASK)))
    .join('');
  // eslint-disable-next-line no-control-regex
  if (!out || out.length > MAX_TARGET_LENGTH || /[\u0000-\u001f\u007f]/.test(out)) return undefined;
  return out;
}

/** At most `limit` characters of `value`, masked before it is cut. */
export function maskText(value: string, limit: number): string {
  return maskSecrets(value.slice(0, limit + LOOKAHEAD)).slice(0, limit);
}

function words(key: string): string[] {
  const out: string[] = [];
  for (const chunk of key.split(/[^A-Za-z0-9]+/)) {
    let start = 0;
    for (let i = 1; i < chunk.length; i++) {
      const a = chunk[i - 1];
      const b = chunk[i];
      const next = i + 1 < chunk.length ? chunk[i + 1] : '';
      const lowerToUpper = (isLower(a) || isDigit(a)) && isUpper(b);
      const acronymEnd = isUpper(a) && isUpper(b) && isLower(next);
      if (lowerToUpper || acronymEnd) {
        out.push(chunk.slice(start, i));
        start = i;
      }
    }
    if (chunk) out.push(chunk.slice(start));
  }
  return out.filter(Boolean).map((w) => w.toLowerCase());
}

/** Whether an attribute name names a credential (`password`, `x-api-key`, `sessionId`). */
export function isSensitiveKey(key: string): boolean {
  const w = words(key);
  if (w.some((word) => SENSITIVE_WORDS.has(word))) return true;
  for (let i = 0; i + 1 < w.length; i++) if (SENSITIVE_PAIRS.has(`${w[i]} ${w[i + 1]}`)) return true;
  return false;
}

/** An attribute value as it may leave the process (strings at most `limit` characters). */
export function maskValue(key: string, value: unknown, limit: number): unknown {
  if (value === null || value === undefined) return value;
  if (isSensitiveKey(key)) return MASK;
  if (typeof value === 'string') return maskText(value, limit);
  if (Array.isArray(value)) return value.map((v) => maskValue(key, v, limit));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = maskValue(k, v, limit);
    return out;
  }
  return value;
}

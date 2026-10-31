/**
 * Pure structural detectors (README "Detection algorithms"). Each takes the
 * sink's argument and the inputs in scope and returns a Finding or null. No
 * I/O, no state: the engine decides what a finding does.
 */
import { tmpdir, homedir } from 'os';
import { posix } from 'path';
import { codeTokens, occurrences, overlapping, shellTokens, SQL_KEYWORDS, sqlTokens, type SqlDialect, type Token } from './lexers';
import { noteVulnerability } from './iast-scope';
import { vulnArgv, vulnCode, vulnData, vulnInclude, vulnPath, vulnShell, vulnSql, vulnSsrf } from './iast-rules';
import type { Finding, RaspInput } from './types';
import dnslog from './data/dnslog-domains.json';

const reqInputs = (inputs: RaspInput[], min: number) => inputs.filter((i) => i.source === 'request' && i.value.length >= min);
const modelInputs = (inputs: RaspInput[], min: number) => inputs.filter((i) => i.source === 'model_output' && i.value.length >= min);

// ---- SQL ----------------------------------------------------------------

const ANTI_DETECT = SQL_KEYWORDS;
const COMMA_LIST = /^(, *)?(([a-zA-Z_]\w*|[0-9+\-x.]+) *, *)+([a-zA-Z_]\w*|[0-9+\-x.]+)$/;
const WRITE_STATEMENTS = new Set('insert update delete drop alter create truncate grant revoke merge replace'.split(' '));
const isComment = (t: Token) => t.kind === 'comment' || t.kind === 'version_comment';

function hasStackedAfter(tokens: Token[], from: Token[]): boolean {
  for (const t of from) {
    if (t.kind !== 'op' || t.text !== ';') continue;
    const at = tokens.indexOf(t);
    if (tokens.slice(at + 1).some((x) => !isComment(x))) return true;
  }
  return false;
}

function sqlWholeIsDangerous(tokens: Token[]): boolean {
  const code = tokens.filter((t) => !isComment(t));
  if (!code.length) return false;
  if (code[0].kind === 'word' && WRITE_STATEMENTS.has(code[0].text.toLowerCase())) return true;
  for (let i = 0; i < code.length - 1; i++) if (code[i].kind === 'op' && code[i].text === ';') return true;
  return false;
}

export function detectSql(query: string, inputs: RaspInput[], dialect: SqlDialect = 'generic'): Finding | null {
  const f = detectSqlRules(query, inputs, dialect);
  return f ? { ...f, dialect } : null;
}

function detectSqlRules(query: string, inputs: RaspInput[], dialect: SqlDialect): Finding | null {
  if (!query || !inputs.length) return null;
  let tokens: Token[] | null = null;
  const toks = () => (tokens ??= sqlTokens(query, dialect));
  const trimmed = query.trim();
  for (const inp of reqInputs(inputs, 3)) {
    const v = inp.value;
    if (v === query || v.trim() === trimmed) continue; // allow_full: a SQL console
    const occ = occurrences(query, v);
    if (!occ.length) continue;
    const commaList = COMMA_LIST.test(v);
    for (const idx of occ) {
      const over = overlapping(toks(), idx, v.length);
      if (!commaList && over.length >= 2) {
        if (over.length >= 10) return { attack: 'sql_injection', rule: 'sqli.userinput', input: inp };
        const plain = over.filter((t) => !(t.kind === 'word' && ANTI_DETECT.has(t.text.toLowerCase())));
        if (plain.length >= 2) return { attack: 'sql_injection', rule: 'sqli.userinput', input: inp };
      }
      if (hasStackedAfter(toks(), over)) return { attack: 'sql_injection', rule: 'sqli.stacked', input: inp };
    }
  }
  for (const inp of modelInputs(inputs, 3)) {
    if (inp.value.trim() === trimmed) {
      if (sqlWholeIsDangerous(toks())) return { attack: 'sql_injection', rule: 'sqli.model_output', input: inp };
      continue;
    }
    for (const idx of occurrences(query, inp.value)) {
      if (overlapping(toks(), idx, inp.value.length).length >= 2) return { attack: 'sql_injection', rule: 'sqli.model_output', input: inp };
    }
  }
  noteVulnerability(() => vulnSql(query, inputs, toks)); // passive IAST (iast-rules.ts)
  return null;
}

// ---- NoSQL ----------------------------------------------------------------

function deepEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (a === b) return true;
  if (depth > 32 || typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], depth + 1));
}

function treeContains(tree: unknown, obj: unknown, depth = 0): boolean {
  if (tree === null || typeof tree !== 'object' || depth > 32) return false;
  if (tree === obj || deepEqual(tree, obj)) return true;
  return Object.values(tree as Record<string, unknown>).some((v) => treeContains(v, obj, depth + 1));
}

export function detectNoSql(doc: unknown, trees: unknown[], inputs: RaspInput[]): Finding | null {
  let found: Finding | null = null;
  const walk = (node: unknown, depth: number) => {
    if (found || node === null || typeof node !== 'object' || depth > 32) return;
    const entries = Object.entries(node as Record<string, unknown>);
    if (!Array.isArray(node) && entries.some(([k]) => k.startsWith('$')) && trees.some((t) => treeContains(t, node))) {
      found = { attack: 'nosql_injection', rule: 'nosqli.operator' };
      return;
    }
    for (const [k, v] of entries) {
      if ((k === '$where' || k === '$function') && !found) {
        const code = typeof v === 'string' ? v : v && typeof v === 'object' && typeof (v as { body?: unknown }).body === 'string' ? (v as { body: string }).body : '';
        const hit = code ? detectCode(code, inputs) : null;
        if (hit) found = { attack: 'nosql_injection', rule: 'nosqli.where', input: hit.input };
      }
      walk(v, depth + 1);
    }
  };
  walk(doc, 0);
  return found;
}

// ---- Command ----------------------------------------------------------------

export const SHELLS = new Set('sh bash zsh dash ksh fish csh tcsh cmd powershell pwsh'.split(' '));
export const DOWNLOADERS = new Set(['curl', 'wget']);
const MULTI_OPS = new Set([';', '&&', '||', '|', '`', '$(']);

export function exeName(p: string): string {
  const base = p.replace(/\\/g, '/').split('/').pop() || '';
  return base.toLowerCase().replace(/\.exe$/, '');
}

function unquoteWord(w: string): string {
  return w.replace(/^['"]|['"]$/g, '');
}

export function detectCommand(command: string, inputs: RaspInput[]): Finding | null {
  if (!command || !inputs.length) return null;
  const { tokens, inSingle } = shellTokens(command);
  const trimmed = command.trim();
  for (const inp of reqInputs(inputs, 3)) {
    for (const idx of occurrences(command, inp.value)) {
      if (overlapping(tokens, idx, inp.value.length).length >= 2) return { attack: 'command_injection', rule: 'cmdi.userinput', input: inp };
    }
  }
  for (const inp of reqInputs(inputs, 3)) {
    const v = inp.value;
    if (v.includes('${IFS}') || v.includes('$IFS')) {
      if (command.includes(v)) return { attack: 'command_injection', rule: 'cmdi.substitution', input: inp };
    }
    if (v.includes('`') || v.includes('$(')) {
      for (const idx of occurrences(command, v)) {
        for (let k = idx; k < idx + v.length; k++) {
          const sub = command[k] === '`' || (command[k] === '$' && command[k + 1] === '(');
          if (sub && !inSingle[k]) return { attack: 'command_injection', rule: 'cmdi.substitution', input: inp };
        }
      }
    }
  }
  for (const inp of reqInputs(inputs, 1)) if (inp.value.trim() === trimmed) return { attack: 'command_injection', rule: 'cmdi.full', input: inp };
  for (const inp of modelInputs(inputs, 3)) {
    if (inp.value.trim() === trimmed) {
      if (tokens.some((t) => t.kind === 'op' && MULTI_OPS.has(t.text))) return { attack: 'command_injection', rule: 'cmdi.model_output', input: inp };
      continue;
    }
    for (const idx of occurrences(command, inp.value)) {
      if (overlapping(tokens, idx, inp.value.length).length >= 2) return { attack: 'command_injection', rule: 'cmdi.model_output', input: inp };
    }
  }
  noteVulnerability(() => vulnShell(command, inputs, tokens)); // passive IAST
  return null;
}

/** argv spawns: the executable equals an input. */
export function detectArgv(argv: string[], inputs: RaspInput[]): Finding | null {
  if (!argv.length) return null;
  for (const inp of inputs) if (inp.value.length >= 1 && inp.value === argv[0]) return { attack: 'command_injection', rule: 'cmdi.executable', input: inp };
  // Passive IAST: a `sh -c <script>` spawn's script is checked as shell text instead.
  noteVulnerability(() => (shellScriptOf(argv) ? null : vulnArgv(argv, inputs)));
  return null;
}

/** shell_spawn: a shell or downloader started during a request, or curl|sh at any time. */
export function detectShellSpawn(opts: { argv0?: string; command?: string; inRequest: boolean; allow: string[] }): Finding | null {
  const allowed = new Set(opts.allow.map(exeName));
  if (opts.command) {
    const words = shellTokens(opts.command).tokens;
    for (let i = 0; i < words.length; i++) {
      if (words[i].kind !== 'word' || !DOWNLOADERS.has(exeName(unquoteWord(words[i].text)))) continue;
      for (let k = i + 1; k < words.length - 1; k++) {
        if (words[k].kind === 'op' && words[k].text === '|' && words[k + 1].kind === 'word' && SHELLS.has(exeName(unquoteWord(words[k + 1].text)))) {
          return { attack: 'shell_spawn', rule: 'shell_spawn.download_exec' };
        }
      }
    }
  }
  if (!opts.inRequest) return null;
  let name = opts.argv0 ? exeName(opts.argv0) : '';
  if (!name && opts.command) {
    const first = shellTokens(opts.command).tokens.find((t) => t.kind === 'word');
    name = first ? exeName(unquoteWord(first.text)) : '';
  }
  if (name && (SHELLS.has(name) || DOWNLOADERS.has(name)) && !allowed.has(name)) return { attack: 'shell_spawn', rule: 'shell_spawn.shell', target: name };
  return null;
}

/** The script of `sh -c <script>` style argv, if any. */
export function shellScriptOf(argv: string[]): string | null {
  if (argv.length < 3 || !SHELLS.has(exeName(argv[0]))) return null;
  const i = argv.findIndex((a, k) => k > 0 && (a === '-c' || a.toLowerCase() === '/c' || a.toLowerCase() === '-command'));
  return i > 0 && i + 1 < argv.length ? argv.slice(i + 1).join(' ') : null;
}

// ---- Path ----------------------------------------------------------------

export function normPath(p: string): string {
  let s = p.replace(/\\/g, '/');
  const unc = s.startsWith('//');
  while (s.includes('/./')) s = s.replace('/./', '/');
  s = s.replace(/\/{2,}/g, '/');
  return unc ? '/' + s : s;
}

export function resolvePath(p: string, cwd = process.cwd()): string {
  const s = p.replace(/\\/g, '/');
  const abs = s.startsWith('/') || /^[A-Za-z]:\//.test(s) ? s : `${cwd.replace(/\\/g, '/')}/${s}`;
  const drive = /^[A-Za-z]:/.test(abs) ? abs.slice(0, 2) : '';
  return drive + posix.normalize('/' + abs.slice(drive.length)).replace(/\/$/, '') || '/';
}

const SENSITIVE = ['/etc/passwd', '/etc/shadow', '/proc/self/environ', '/root/.bash_history', '/var/run/secrets/kubernetes.io/serviceaccount/token'];
export const SCRIPT_FILE = /\.(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)\.?$/i;

export function underRoot(resolved: string, root: string): boolean {
  const r = resolvePath(root);
  return resolved === r || resolved.startsWith(r.endsWith('/') ? r : r + '/');
}

/** The directory path.outside_root reports: the resolved path up to its last `/` (README "Allow-list targets"). */
export function targetDirectory(resolved: string): string {
  const dir = resolved.slice(0, Math.max(0, resolved.lastIndexOf('/')));
  return dir === '' || /^[A-Za-z]:$/.test(dir) ? dir + '/' : dir;
}

export type FileOp = 'read' | 'write' | 'append' | 'delete' | 'rename' | 'list' | 'open';

export function detectPath(path: string, op: FileOp, inputs: RaspInput[], fileRoots: string[] = [], inRequest = true): Finding | null {
  if (typeof path !== 'string' || !path) return null;
  const np = normPath(path);
  const resolved = resolvePath(path);
  const writes = op === 'write' || op === 'append' || op === 'rename' || op === 'open';
  if (writes && /::\$(DATA|INDEX)$/i.test(path)) return { attack: 'file_write', rule: 'file_write.ntfs' };
  const cands = reqInputs(inputs, 3).concat(modelInputs(inputs, 3));
  for (const inp of cands) {
    const ni = normPath(inp.value);
    if (ni.includes('../') && (np.endsWith(ni) || np.includes(ni))) return { attack: 'path_traversal', rule: 'path.traversal', input: inp };
    const absolute = ni.startsWith('/') || /^[A-Za-z]:\//.test(ni) || inp.value.startsWith('file://');
    if (absolute) {
      const target = inp.value.startsWith('file://') ? normPath(inp.value.slice(7)) : ni;
      if (np === target || np.endsWith(target)) return { attack: 'path_traversal', rule: 'path.absolute', input: inp };
    }
    const nul = inp.value.indexOf('\0');
    if (nul > 0 && path.includes(inp.value.slice(0, nul))) return { attack: 'path_traversal', rule: 'path.nullbyte', input: inp };
  }
  const contained = cands.find((i) => path.includes(i.value) || np.includes(normPath(i.value)));
  if (contained && fileRoots.length && !fileRoots.some((r) => underRoot(resolved, r))) {
    return { attack: 'path_traversal', rule: 'path.outside_root', input: contained, target: targetDirectory(resolved) };
  }
  if (contained) {
    const home = homedir().replace(/\\/g, '/');
    if (SENSITIVE.includes(resolved) || resolved === `${home}/.ssh/id_rsa` || resolved.endsWith('/.ssh/id_rsa')) {
      return { attack: 'path_traversal', rule: 'path.sensitive', input: contained };
    }
  }
  if (writes && inRequest && SCRIPT_FILE.test(resolved.split('/').pop() || '')) {
    if (contained || fileRoots.some((r) => underRoot(resolved, r)) || underRoot(resolved, tmpdir())) {
      return { attack: 'file_write', rule: 'file_write.script', input: contained };
    }
  }
  noteVulnerability(() => vulnPath(np, inputs, normPath)); // passive IAST
  return null;
}

// ---- SSRF ----------------------------------------------------------------

const SSRF_PROTOCOLS = new Set('file gopher dict ftp jar netdoc ldap ldaps php phar expect tftp'.split(' '));
export const METADATA_HOSTS = ['169.254.169.254', 'fd00:ec2::254', '100.100.100.200', '168.63.129.16', '169.254.170.2', 'metadata.google.internal', 'metadata'];

/** Scheme and raw host as written (the WHATWG parser would rewrite numeric hosts). */
export function rawUrl(url: string): { scheme: string; host: string } | null {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(url);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  let rest = url.slice(m[0].length);
  if (!rest.startsWith('//')) return { scheme, host: '' };
  rest = rest.slice(2);
  const end = rest.search(/[/?#\\]/);
  let auth = end < 0 ? rest : rest.slice(0, end);
  const at = auth.lastIndexOf('@');
  if (at >= 0) auth = auth.slice(at + 1);
  let host = auth;
  if (host.startsWith('[')) host = host.slice(1, host.indexOf(']') < 0 ? undefined : host.indexOf(']'));
  else if (host.includes(':')) host = host.slice(0, host.indexOf(':'));
  return { scheme, host: host.toLowerCase() };
}

function parseV4(s: string): number[] | null {
  const p = s.split('.');
  if (p.length !== 4) return null;
  const n = p.map((x) => (/^(0|[1-9]\d{0,2})$/.test(x) ? Number(x) : NaN));
  return n.every((x) => x >= 0 && x <= 255) ? n : null;
}

function parseV6(s: string): number[] | null {
  // Returns 16 bytes, or null.
  if (!s.includes(':')) return null;
  let tail: number[] = [];
  let str = s;
  const lastColon = str.lastIndexOf(':');
  const v4 = parseV4(str.slice(lastColon + 1));
  if (v4) {
    tail = v4;
    str = str.slice(0, lastColon) + ':0:0';
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const parse = (h: string) => (h ? h.split(':').map((x) => (/^[0-9a-f]{1,4}$/i.test(x) ? parseInt(x, 16) : NaN)) : []);
  const a = parse(halves[0]);
  const b = halves.length === 2 ? parse(halves[1]) : [];
  if ([...a, ...b].some((x) => Number.isNaN(x))) return null;
  const fill = halves.length === 2 ? 8 - a.length - b.length : 0;
  if (fill < 0 || (halves.length === 1 && a.length !== 8)) return null;
  const words = [...a, ...Array(fill).fill(0), ...b];
  const bytes: number[] = [];
  for (const w of words) bytes.push(w >> 8, w & 255);
  if (tail.length) bytes.splice(12, 4, ...tail);
  return bytes;
}

function v4Private(b: number[]): boolean {
  const [a, c] = b;
  return a === 0 || a === 10 || a === 127 || (a === 100 && c >= 64 && c < 128) || (a === 169 && c === 254) || (a === 172 && c >= 16 && c < 32) || (a === 192 && c === 168) || (a === 198 && (c === 18 || c === 19));
}

/** Private, loopback, link-local or unique-local, IPv4-mapped/compatible decoded. */
export function isPrivateAddress(addr: string): boolean {
  const a = addr.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  const v4 = parseV4(a);
  if (v4) return v4Private(v4);
  const v6 = parseV6(a);
  if (!v6) return false;
  const zero10 = v6.slice(0, 10).every((x) => x === 0);
  if (zero10 && v6[10] === 0xff && v6[11] === 0xff) return v4Private(v6.slice(12));
  const zero12 = zero10 && v6[10] === 0 && v6[11] === 0;
  const loopOrAny = v6.slice(12, 15).every((x) => x === 0) && v6[15] <= 1;
  if (zero12 && !loopOrAny) return v4Private(v6.slice(12));
  if (v6.every((x) => x === 0)) return true;
  if (v6.slice(0, 15).every((x) => x === 0) && v6[15] === 1) return true;
  if ((v6[0] & 0xfe) === 0xfc) return true;
  if (v6[0] === 0xfe && (v6[1] & 0xc0) === 0x80) return true;
  return false;
}

export function isIpLiteral(host: string): boolean {
  return Boolean(parseV4(host) || parseV6(host));
}

function isObfuscatedV4(host: string): boolean {
  if (!host || parseV4(host)) return false;
  if (/^\d+$/.test(host)) return true;
  if (/^0x[0-9a-f]+$/i.test(host)) return true;
  const parts = host.split('.');
  if (parts.length > 4 || parts.length < 2) return false;
  if (!parts.every((p) => /^(0x[0-9a-f]+|\d+)$/i.test(p))) return false;
  return parts.length < 4 || parts.some((p) => /^0\d/.test(p) || /^0x/i.test(p));
}

const DNSLOG_SUFFIXES: string[] = dnslog.domains;
const DNSLOG_HOSTS = new Set<string>(dnslog.hosts);

export function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.toLowerCase();
  if (p.startsWith('*.')) return host.endsWith(p.slice(1)) && host.length > p.length - 1;
  return host === p;
}

/** Whether an input taints the URL's host. */
export function taintOf(url: string, host: string, inputs: RaspInput[]): RaspInput | undefined {
  const cands = inputs.filter((i) => i.value.length >= 3);
  if (host) {
    const hostEnd = url.toLowerCase().indexOf(host) + host.length;
    return cands.find((i) => i.value.toLowerCase().includes(host) || (url.startsWith(i.value) && i.value.length >= hostEnd));
  }
  // No host (file:, gopher: without //): an input that is a prefix past the scheme.
  const schemeEnd = url.indexOf(':') + 1;
  return cands.find((i) => url.startsWith(i.value) && i.value.length > schemeEnd);
}

export function detectSsrf(url: string, inputs: RaspInput[], resolved: string[] = []): Finding | null {
  const raw = rawUrl(url);
  if (!raw) return null;
  const inp = taintOf(url, raw.host, inputs);
  if (!inp) return null;
  const host = raw.host;
  if (SSRF_PROTOCOLS.has(raw.scheme)) return { attack: 'ssrf', rule: 'ssrf.protocol', input: inp };
  if (METADATA_HOSTS.includes(host) || resolved.some((a) => METADATA_HOSTS.includes(a.toLowerCase()))) return { attack: 'ssrf', rule: 'ssrf.metadata', input: inp };
  if (isObfuscatedV4(host)) return { attack: 'ssrf', rule: 'ssrf.obfuscated', input: inp };
  if (host === 'localhost' || host.endsWith('.localhost') || (isIpLiteral(host) && isPrivateAddress(host)) || resolved.some(isPrivateAddress)) {
    return { attack: 'ssrf', rule: 'ssrf.internal', input: inp };
  }
  if (DNSLOG_HOSTS.has(host) || DNSLOG_SUFFIXES.some((s) => host.endsWith(s))) return { attack: 'ssrf', rule: 'ssrf.dnslog', input: inp };
  noteVulnerability(() => vulnSsrf(url, raw, inputs)); // passive IAST
  return null;
}

/** outbound.not_allowed: host matches none of the allow-list (always-allowed hosts aside). */
export function detectOutbound(url: string, allow: string[], alwaysAllowed: string[] = []): Finding | null {
  if (!allow.length) return null;
  const raw = rawUrl(url);
  if (!raw || !raw.host) return null;
  if (alwaysAllowed.includes(raw.host) || allow.some((p) => hostMatches(raw.host, p))) return null;
  return { attack: 'outbound', rule: 'outbound.not_allowed', target: raw.host };
}

// ---- Deserialization, code, XML, XSS ------------------------------------------

/** Data is tainted when equal to an input, contained in one, or containing one of length >= 8. */
export function taintedData(data: string, inputs: RaspInput[]): RaspInput | undefined {
  if (!data) return undefined;
  for (const i of inputs) {
    if (!i.value) continue;
    if (i.value === data || i.value.includes(data) || (i.value.length >= 8 && data.includes(i.value))) return i;
    if (i.value.length >= 8 && /^[A-Za-z0-9+/=_-]+$/.test(i.value)) {
      const dec = Buffer.from(i.value, 'base64').toString('latin1');
      if (dec && (dec === data || (dec.length >= 8 && (dec.includes(data) || data.includes(dec))))) return i;
    }
  }
  return undefined;
}

export type DeserFormat =
  | 'pickle'
  | 'marshal'
  | 'yaml'
  | 'jsonpickle'
  | 'node_serialize'
  | 'funcster'
  | 'binaryformatter'
  | 'typename'
  | 'java'
  | 'snakeyaml';

const JSONPICKLE_MARKS = ['"py/reduce"', '"py/object"', '"py/type"', '"py/function"', '"py/repr"', '"py/newargs"'];

/** A SnakeYAML global tag naming a Java class; standard tags such as `!!str` have no dot and never match. */
const SNAKEYAML_CLASS_TAG = /(?:^|[\s[{,])(?:!!|!<tag:yaml\.org,2002:)[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$]/;

export function detectDeserialization(format: DeserFormat, data: string, inputs: RaspInput[]): Finding | null {
  const inp = taintedData(data, inputs);
  if (!inp) return null;
  // Passive IAST: tainted data reaching an unsafe deserializer, whatever the format check says.
  noteVulnerability(() => vulnData('vuln.deser_input', data, taintedData(data, inputs.filter((i) => i.source === 'request'))));
  const hit = (rule: string): Finding => ({ attack: 'deserialization', rule, input: inp });
  switch (format) {
    case 'pickle':
      return hit('deser.pickle');
    case 'marshal':
      return hit('deser.marshal');
    case 'binaryformatter':
      return hit('deser.binaryformatter');
    case 'java':
      return hit('deser.java');
    case 'snakeyaml':
      return SNAKEYAML_CLASS_TAG.test(data) ? hit('deser.yaml') : null;
    case 'yaml':
      return data.includes('!!python/') || data.includes('!!js/') ? hit('deser.yaml') : null;
    case 'jsonpickle':
      return JSONPICKLE_MARKS.some((m) => data.includes(m)) ? hit('deser.jsonpickle') : null;
    case 'node_serialize':
      return data.includes('_$$ND_FUNC$$_') ? hit('deser.node_serialize') : null;
    case 'funcster':
      return data.includes('__js_function') ? hit('deser.funcster') : null;
    case 'typename':
      return data.includes('"$type"') || data.includes('"__type"') ? hit('deser.typename') : null;
  }
  return null;
}

export function detectCode(code: string, inputs: RaspInput[]): Finding | null {
  if (!code) return null;
  let tokens: Token[] | null = null;
  for (const inp of inputs) {
    if (inp.value.length < 3) continue;
    if (inp.value === code) return { attack: 'code_injection', rule: 'code.eval', input: inp };
    for (const idx of occurrences(code, inp.value)) {
      tokens ??= codeTokens(code);
      if (overlapping(tokens, idx, inp.value.length).length >= 2) return { attack: 'code_injection', rule: 'code.eval', input: inp };
    }
  }
  noteVulnerability(() => vulnCode(code, inputs, () => (tokens ??= codeTokens(code)))); // passive IAST
  return null;
}

const INCLUDE_PATHLIKE = /[/\\]|\.\./;
const INCLUDE_ABSOLUTE = /^(?:\/|[A-Za-z]:[\\/]|\\\\|file:)/i;

/** code.include: a module specifier that is, or carries a path from, an input. */
export function detectInclude(specifier: string, inputs: RaspInput[]): Finding | null {
  if (typeof specifier !== 'string' || !specifier) return null;
  for (const inp of inputs) {
    if (!inp.value) continue;
    if (inp.value === specifier) return { attack: 'code_injection', rule: 'code.include', input: inp };
    if (inp.value.length >= 3 && specifier.includes(inp.value) && (INCLUDE_ABSOLUTE.test(inp.value) || INCLUDE_PATHLIKE.test(inp.value) || inp.value.includes('\0'))) {
      return { attack: 'code_injection', rule: 'code.include', input: inp };
    }
  }
  noteVulnerability(() => vulnInclude(specifier, inputs)); // passive IAST
  return null;
}

/** file_write.upload: an uploaded file whose name is a script (README "Path"). */
export function detectUpload(input: RaspInput): Finding | null {
  const name = input.value.split(/[\\/]/).pop() || '';
  return SCRIPT_FILE.test(name) ? { attack: 'file_write', rule: 'file_write.upload', input } : null;
}

type EntityDecl = { name: string; external: boolean; uri: string; value: string };

/** Reads the DOCTYPE: external DTD id and entity declarations. */
export function parseDoctype(xml: string): { hasDoctype: boolean; externalDtd: string | null; entities: EntityDecl[] } {
  const at = xml.indexOf('<!DOCTYPE');
  if (at < 0) return { hasDoctype: false, externalDtd: null, entities: [] };
  const head = xml.slice(at, at + 64 * 1024);
  const bracket = head.indexOf('[');
  const close = head.indexOf('>');
  const decl = head.slice(0, bracket >= 0 && bracket < close ? bracket : close);
  const ext = /\s(SYSTEM|PUBLIC)\s/.exec(decl);
  let externalDtd: string | null = null;
  if (ext) {
    const lits = decl.slice(ext.index).match(/"[^"]*"|'[^']*'/g) || [];
    externalDtd = (lits[ext[1] === 'PUBLIC' ? 1 : 0] || lits[0] || '').slice(1, -1);
  }
  const entities: EntityDecl[] = [];
  let from = 0;
  while (entities.length < 1000) {
    const i = head.indexOf('<!ENTITY', from);
    if (i < 0) break;
    const end = head.indexOf('>', i);
    const body = head.slice(i + 8, end < 0 ? undefined : end).trim();
    from = end < 0 ? head.length : end + 1;
    const m = /^(%\s+)?([^\s]+)\s+(.*)$/s.exec(body);
    if (!m) continue;
    const rest = m[3].trim();
    const lits = rest.match(/"[^"]*"|'[^']*'/g) || [];
    const external = /^(SYSTEM|PUBLIC)\b/.test(rest);
    const uri = external ? (lits[rest.startsWith('PUBLIC') ? 1 : 0] || '').slice(1, -1) : '';
    entities.push({ name: m[2], external, uri, value: external ? '' : (lits[0] || '').slice(1, -1) });
  }
  return { hasDoctype: true, externalDtd, entities };
}

const XXE_PROTOCOLS = new Set('ftp dict gopher netdoc mailto jar php expect'.split(' '));

export function detectXml(xml: string, inputs: RaspInput[], resolvesExternal: boolean): Finding | null {
  // Passive IAST: request data parsed by a parser that resolves external entities, DOCTYPE or not.
  if (xml && resolvesExternal) noteVulnerability(() => vulnData('vuln.xml_external', xml, taintedData(xml, inputs.filter((i) => i.source === 'request'))));
  if (!xml || !xml.includes('<!DOCTYPE')) return null;
  const inp = taintedData(xml, inputs);
  if (!inp) return null;
  const d = parseDoctype(xml);
  const uris = d.entities.filter((e) => e.external).map((e) => e.uri);
  if (d.externalDtd !== null) uris.push(d.externalDtd);
  for (const u of uris) {
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(u)?.[1]?.toLowerCase();
    if ((scheme && XXE_PROTOCOLS.has(scheme)) || u.startsWith('\\\\')) return { attack: 'xxe', rule: 'xxe.protocol', input: inp };
    if (scheme === 'file') {
      const p = u.replace(/^file:(\/\/)?/i, '');
      if ((p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.includes('../')) && !/\.(dtd|xsd|xml)$/i.test(p)) return { attack: 'xxe', rule: 'xxe.file', input: inp };
    }
  }
  if (uris.length) return { attack: 'xxe', rule: resolvesExternal ? 'xxe.external_entity' : 'xxe.doctype', input: inp };
  const referencing = d.entities.filter((e) => !e.external && /[&%][^\s;]+;/.test(e.value));
  if (referencing.length >= 3) return { attack: 'xxe', rule: 'xxe.billion_laughs', input: inp };
  return null;
}

// The contract's tag pattern (OpenRASP xss_userinput) includes control characters on purpose.
// eslint-disable-next-line no-control-regex
const XSS_TAG = /<![-[A-Za-z]|<([A-Za-z]{1,12})[/>\x00-\x20]/;
const XSS_HANDLER = /\bon[a-z]{3,}\s*=/i;
export const MAX_XSS_BODY = 1024 * 1024;

export function detectXss(contentType: string | undefined, body: string, inputs: RaspInput[]): Finding | null {
  if (!contentType || !contentType.toLowerCase().includes('html') || !body || body.length > MAX_XSS_BODY) return null;
  for (const inp of inputs) {
    const v = inp.value;
    if (v.length < 15) continue;
    if (!(XSS_TAG.test(v) || v.toLowerCase().includes('javascript:') || XSS_HANDLER.test(v))) continue;
    if (body.includes(v)) return { attack: 'xss', rule: 'xss.reflected', input: inp };
  }
  return null;
}

export type { SqlDialect };

// SHIELD: template-source detector uses the same code_injection attack mode.
export { detectTemplate, type TemplateEngine } from './template';

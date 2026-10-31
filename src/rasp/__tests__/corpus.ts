/**
 * Shared-corpus runner (sdk/rasp/testdata, README "Fixtures"): runs one case
 * of a section through the detectors and returns what fired, if anything.
 * `request` inputs go through the normaliser (percent-decoded forms added);
 * `model_output` inputs through the model-output fragmenter.
 */
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import {
  detectArgv,
  detectCode,
  detectTemplate,
  type TemplateEngine,
  detectCommand,
  detectDeserialization,
  detectNoSql,
  detectPath,
  detectShellSpawn,
  detectSql,
  detectSsrf,
  detectXml,
  detectXss,
  shellScriptOf,
  type DeserFormat,
  type FileOp,
} from '../detect';
import type { SqlDialect } from '../lexers';
import { addInput, addModelOutput, flatten } from '../normalize';
import type { Finding, RaspInput } from '../types';
import { BUILT_IN_RULES, matchVirtualPatches, type VirtualPatch, type VpRequest } from '../vpatch';

// sdk/rasp in the monorepo; rasp/ at the root of the public mirror (shield360-js).
export const RASP_DIR = [join(__dirname, '..', '..', '..', '..', 'rasp'), join(__dirname, '..', '..', '..', 'rasp')]
  .find((dir) => existsSync(join(dir, 'testdata'))) ?? join(__dirname, '..', '..', '..', '..', 'rasp');
export const loadJson = (rel: string): any => JSON.parse(readFileSync(join(RASP_DIR, rel), 'utf8'));

export const SECTIONS = ['sql', 'nosql', 'command', 'path', 'ssrf', 'code', 'template', 'xml', 'deser', 'xss', 'requests'] as const;
export type Section = (typeof SECTIONS)[number];

export function normalise(raw: RaspInput[] | undefined): RaspInput[] {
  const out: RaspInput[] = [];
  for (const i of raw || []) {
    if (i.source === 'model_output') addModelOutput(out, i.value, i.key);
    else addInput(out, i.value, i.key);
  }
  return out;
}

/** Node versions the request cases run under: this one, and one inside each runtimeVersions range. */
export function nodeVersions(): string[] {
  const out = new Set<string>([process.versions.node]);
  for (const r of BUILT_IN_RULES) for (const [from] of r.runtimeVersions?.node ?? []) out.add(from);
  return [...out];
}

/** Runs one case; returns the first finding (null = nothing fired). */
export function runCase(section: Section, c: any): Finding | null {
  const inputs = normalise(c.inputs);
  switch (section) {
    case 'sql':
      return detectSql(c.query, inputs, c.dialect as SqlDialect);
    case 'nosql': {
      const ins: RaspInput[] = [];
      flatten(ins, c.body, 'body');
      flatten(ins, c.query, 'query');
      const trees = [c.body, c.query];
      return detectNoSql(c.filter, trees, ins) ?? (c.update ? detectNoSql(c.update, trees, ins) : null);
    }
    case 'command': {
      if (typeof c.command === 'string') {
        return detectCommand(c.command, inputs) ?? detectShellSpawn({ command: c.command, inRequest: true, allow: [] });
      }
      const argv: string[] = c.argv;
      const script = shellScriptOf(argv);
      return detectArgv(argv, inputs) ?? (script ? detectCommand(script, inputs) : null) ?? detectShellSpawn({ argv0: argv[0], inRequest: true, allow: [] });
    }
    case 'path':
      return detectPath(c.path, c.op as FileOp, inputs, c.fileRoots || []);
    case 'ssrf':
      return detectSsrf(c.url, inputs, c.resolved || []);
    case 'template': // SHIELD: source only; data is never passed to the detector.
      return detectTemplate(c.template, inputs, c.engine as TemplateEngine);
    case 'code':
      return detectCode(c.code, inputs);
    case 'xml':
      return detectXml(c.xml, inputs, Boolean(c.resolvesExternal));
    case 'deser': {
      const data = c.dataEncoding === 'base64' ? Buffer.from(c.data, 'base64').toString('latin1') : c.data;
      return detectDeserialization(c.format as DeserFormat, data, inputs);
    }
    case 'xss':
      return detectXss(c.contentType, c.body, inputs);
    case 'requests': {
      const req: VpRequest = { method: c.method, path: c.path, query: c.query, headers: c.headers, cookie: c.cookie, body: c.body };
      for (const v of nodeVersions()) {
        const f = matchVirtualPatches(req, BUILT_IN_RULES, 'all', 'node', v);
        if (f) return f;
      }
      return null;
    }
  }
}

/** A request that satisfies a rule's clauses, built from the rule itself. */
export function requestFor(rule: VirtualPatch): VpRequest {
  const req: VpRequest = { method: 'GET', path: '/', query: '', headers: {}, cookie: '', body: '' };
  for (const c of rule.match) {
    const value = c.values?.[0] ?? c.value ?? 'x';
    if (c.target === 'method') req.method = value;
    else if (c.target.startsWith('header:')) req.headers[c.target.slice(7)] = c.op === 'present' ? 'x' : value;
    else if (c.target === 'body' || c.target === 'request') req.body += value;
    else if (c.target === 'query') req.query += value;
    else if (c.target === 'cookie') req.cookie += value;
    else if (c.target === 'path') req.path = value;
  }
  return req;
}

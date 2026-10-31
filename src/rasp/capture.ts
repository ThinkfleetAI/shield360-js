/**
 * Request capture shared by every framework middleware: turns a request into
 * the context's inputs (README "Sources of untrusted input") and runs the
 * virtual patches. Inputs stay in memory, in the request's context only.
 */
import { currentContext, newContext, storage, type RaspContext } from './context';
import { detectUpload } from './detect';
import { customFinding, matchRequestRules, requestSubject } from './custom-rules';
import { applicationName, check, customRules, handleFinding, modeFor, virtualPatches } from './engine';
import { addInput, flatten, MAX_RAW_BODY, parseCookies } from './normalize';
import { RaspBlockedError } from './types';
import { MAX_VP_TEXT, matchVirtualPatches, type VpRequest } from './vpatch';

/** Headers the contract treats as input (OpenRASP's headerInjection). */
export const INPUT_HEADERS = ['user-agent', 'referer', 'x-forwarded-for'] as const;
export const VP_SINK = 'server.request';

export type Headers = Record<string, string | string[] | undefined>;

/** A request, framework-neutral. */
export type RequestShape = {
  framework: string;
  method: string;
  /** Path and query as received (`/a/b?x=1`). */
  url: string;
  /** Lower-case header names. */
  headers: Headers;
  /** The parsed query, when the framework has one (else parsed from `url`). */
  query?: unknown;
  /** Route or path parameters. */
  params?: unknown;
  /** The route template, when known. */
  route?: string;
  /** The client address as the framework reports it (custom rules' `request.ip`). */
  ip?: string;
};

/** What is known about the body. */
export type BodyShape = {
  /** A parsed body (object), or raw text / bytes. */
  body?: unknown;
  contentType?: string;
  /** Uploaded files a multipart parser set aside (multer's `req.file` / `req.files`). */
  files?: unknown;
};

const MAX_UPLOAD_SCAN = 1024 * 1024;
const MAX_UPLOADS = 32;
const PART_FILENAME = /content-disposition:[^\r\n]*?\bname="([^"\r\n]*)"[^\r\n]*?\bfilename="([^"\r\n]*)"/gi;

/** The names of uploaded files: from raw multipart part headers, or a parser's file objects. */
export function uploadNames(b: BodyShape, raw: string): { field: string; name: string }[] {
  const out: { field: string; name: string }[] = [];
  const ct = (b.contentType || '').toLowerCase();
  if (raw && ct.includes('multipart/form-data')) {
    for (const m of raw.slice(0, MAX_UPLOAD_SCAN).matchAll(PART_FILENAME)) {
      if (out.length >= MAX_UPLOADS) break;
      if (m[2]) out.push({ field: m[1] || 'file', name: m[2] });
    }
  }
  const visit = (f: unknown, field: string) => {
    if (out.length >= MAX_UPLOADS || !f || typeof f !== 'object') return;
    const o = f as Record<string, unknown>;
    const name = [o.originalname, o.originalFilename, o.filename, o.name].find((v) => typeof v === 'string' && v);
    if (typeof name === 'string') out.push({ field: typeof o.fieldname === 'string' ? o.fieldname : field, name });
  };
  const files = b.files;
  if (Array.isArray(files)) files.forEach((f) => visit(f, 'file'));
  else if (files && typeof files === 'object') {
    const one = files as Record<string, unknown>;
    if (typeof one.originalname === 'string' || typeof one.fieldname === 'string') visit(files, 'file');
    else for (const [field, v] of Object.entries(one)) (Array.isArray(v) ? v : [v]).forEach((f) => visit(f, field));
  }
  return out;
}

/**
 * Runs fn with ctx as the current context. Capture runs before the entry
 * point enters the request's context, and the checks it makes (virtual
 * patches, request rules, uploads) report findings that custom finding rules
 * judge with the current request's fields.
 */
function inContext<T>(ctx: RaspContext, fn: () => T): T {
  return currentContext() === ctx ? fn() : storage.run(ctx, fn);
}

/** Records uploaded file names as request input and checks each (file_write.upload). Throws the block error when blocking. */
function captureUploads(ctx: RaspContext, b: BodyShape, raw: string): void {
  for (const { field, name } of uploadNames(b, raw)) {
    const key = `body.${field}.filename`;
    addInput(ctx.inputs, name, key);
    inContext(ctx, () => check('request.upload', () => detectUpload({ value: name, key, source: 'request' })));
  }
}

const header = (h: Headers, name: string): string => {
  const v = h[name];
  return v === undefined ? '' : Array.isArray(v) ? v.join(', ') : String(v);
};

function splitUrl(url: string): { path: string; query: string } {
  const q = url.indexOf('?');
  const hash = url.indexOf('#');
  const end = hash >= 0 ? hash : url.length;
  return q >= 0 && q < end ? { path: url.slice(0, q), query: url.slice(q + 1, end) } : { path: url.slice(0, end), query: '' };
}

/** Lower-cases header names (Node already does; other sources may not). */
export function lowerHeaders(h: unknown): Headers {
  const out: Headers = {};
  if (!h || typeof h !== 'object') return out;
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (typeof v === 'string' || Array.isArray(v)) out[k.toLowerCase()] = v as string | string[];
    else if (v != null) out[k.toLowerCase()] = String(v);
  }
  return out;
}

/** Builds the request's context: query, params, cookies, the input headers. */
export function captureRequest(shape: RequestShape): RaspContext {
  const { path, query } = splitUrl(shape.url || '/');
  const ctx = newContext({ inRequest: true, method: shape.method, path, route: shape.route, framework: shape.framework });
  if (typeof shape.ip === 'string' && shape.ip) ctx.ip = shape.ip;
  const inputs = ctx.inputs;
  if (shape.query && typeof shape.query === 'object') {
    flatten(inputs, shape.query, 'query');
    ctx.trees.push(shape.query);
  } else if (query) {
    const tree: Record<string, string | string[]> = {};
    for (const [k, v] of new URLSearchParams(query)) {
      addInput(inputs, v, `query.${k}`);
      const prev = tree[k];
      tree[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
    }
    ctx.trees.push(tree);
  }
  if (shape.params && typeof shape.params === 'object') flatten(inputs, shape.params, 'params');
  const cookie = header(shape.headers, 'cookie');
  for (const [name, value] of parseCookies(cookie)) addInput(inputs, value, `cookie.${name}`);
  for (const h of INPUT_HEADERS) {
    const v = header(shape.headers, h);
    if (v) addInput(inputs, v, `header.${h}`);
  }
  // SHIELD: inside the zero-code capture's context, the phases it already judged are not judged again,
  // and its custom-rule state carries over, so a rule matches at most once per request.
  const auto = currentContext()?.auto ? currentContext() : undefined;
  ctx.vp = {
    req: { method: shape.method, path, query, headers: shape.headers, cookie, body: '' },
    bodyKnown: false,
    ranHead: Boolean(auto?.vp?.ranHead),
    ranBody: Boolean(auto?.vp?.ranBody),
  };
  if (auto?.rules) ctx.rules = auto.rules;
  return ctx;
}

/**
 * Whether the request has no body, by its headers: neither `Transfer-Encoding`
 * nor a non-zero `Content-Length` (HTTP/1.x; body parsers use the same test).
 * Over HTTP/2 a body needs no length, so only `Content-Length: 0` says so.
 */
export function bodyAbsent(h: Headers, httpVersionMajor?: number): boolean {
  if (h['transfer-encoding'] !== undefined) return false;
  const len = header(h, 'content-length').trim();
  if (len === '0') return true;
  return len === '' && !(typeof httpVersionMajor === 'number' && httpVersionMajor >= 2);
}

/** Records that the request has no body: the body is known and empty, so the body phase runs. */
export function captureNoBody(ctx: RaspContext): void {
  if (ctx.vp) ctx.vp.bodyKnown = true;
}

function isFormType(ct: string): boolean {
  return ct.includes('application/x-www-form-urlencoded');
}

/**
 * Adds the body to the context: string leaves of a parsed body (`body.a.b`),
 * form fields, or the raw text when it is text, unparsed and at most 8 KiB.
 * Also gives the virtual patches the body text.
 */
export function captureBody(ctx: RaspContext, b: BodyShape): void {
  const body = b.body;
  if (body === undefined || body === null) return;
  // Inputs added from here on are body inputs: head rules never see them.
  ctx.headInputs ??= ctx.inputs.length;
  const ct = (b.contentType || '').toLowerCase();
  let raw = '';
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    raw = typeof body === 'string' ? body : Buffer.from(body as Uint8Array).toString('utf8');
    let parsed: unknown;
    if (ct.includes('json')) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = undefined;
      }
    } else if (isFormType(ct)) {
      const tree: Record<string, string> = {};
      for (const [k, v] of new URLSearchParams(raw.slice(0, 1024 * 1024))) tree[k] = v;
      parsed = tree;
    }
    if (parsed !== undefined && parsed !== null && typeof parsed === 'object') {
      flatten(ctx.inputs, parsed, 'body');
      ctx.trees.push(parsed);
    } else if (raw.length <= MAX_RAW_BODY) {
      addInput(ctx.inputs, raw, 'body');
    }
  } else if (typeof body === 'object') {
    flatten(ctx.inputs, body, 'body');
    ctx.trees.push(body);
    try {
      raw = JSON.stringify(body) ?? '';
    } catch {
      raw = '';
    }
  }
  if (ctx.vp) {
    ctx.vp.req.body = raw.length > MAX_VP_TEXT ? raw.slice(0, MAX_VP_TEXT) : raw;
    ctx.vp.bodyKnown = true;
  }
  captureUploads(ctx, b, raw);
}

/**
 * Runs the virtual patches the request can be judged by so far: rules that
 * do not read the body at once, rules that do once the body is known. Each
 * rule set runs once. Throws the block error when a blocking rule matches;
 * any other failure lets the request through.
 */
export function runVirtualPatches(ctx: RaspContext): void {
  inContext(ctx, () => runPhases(ctx));
}

function runPhases(ctx: RaspContext): void {
  const vp = ctx.vp;
  if (!vp) return;
  const phases: ('head' | 'body')[] = [];
  if (!vp.ranHead) {
    vp.ranHead = true;
    phases.push('head');
  }
  if (vp.bodyKnown && !vp.ranBody) {
    vp.ranBody = true;
    phases.push('body');
  }
  for (const phase of phases) {
    let finding = null;
    try {
      finding = matchVirtualPatches(vp.req as VpRequest, virtualPatches(), phase);
    } catch {
      finding = null;
    }
    // A monitored match is reported and the next phase still runs; a blocked one throws.
    if (finding) handleFinding(finding, VP_SINK, { framework: ctx.framework, route: ctx.route, method: ctx.method, path: ctx.path });
    runRequestRules(ctx, phase);
  }
}

/**
 * Custom request rules (README "Custom rules"): each match is reported in
 * order; the first that blocks throws the block error. Any other failure
 * lets the request through.
 */
export function runRequestRules(ctx: RaspContext, phase: 'head' | 'body'): void {
  let matches;
  try {
    const rules = customRules();
    // Mode off skips custom rules: nothing is evaluated.
    if (!rules.length || modeFor('custom_rule') === 'off') return;
    const inputs = phase === 'head' && ctx.headInputs !== undefined ? ctx.inputs.slice(0, ctx.headInputs) : ctx.inputs;
    matches = matchRequestRules(rules, ctx, phase, requestSubject(ctx, applicationName(), inputs));
  } catch {
    return;
  }
  const extra = { framework: ctx.framework, route: ctx.route, method: ctx.method, path: ctx.path };
  for (const m of matches) handleFinding(customFinding(m.rule, m.input), VP_SINK, extra);
}

/**
 * Sets up late body capture: when a sink first reads the inputs, a body a
 * parser set after the middleware ran is captured and judged.
 */
export function captureLater(ctx: RaspContext, read: () => BodyShape | undefined): void {
  if (ctx.vp?.bodyKnown) return;
  ctx.late = () => {
    try {
      const b = read();
      if (!b || b.body === undefined || b.body === null) return false;
      captureBody(ctx, b);
    } catch (e) {
      // An upload check that blocks stops the call; any other failure lets it through.
      if (e instanceof RaspBlockedError) throw e;
      return true;
    }
    runVirtualPatches(ctx);
    return true;
  };
}

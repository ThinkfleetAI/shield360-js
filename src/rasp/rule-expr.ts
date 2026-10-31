/**
 * Custom RASP rule expressions (sdk/rasp/README.md "Custom rules").
 *
 * A small, sandboxed, CEL-style expression language: a fixed set of fields,
 * string literals, comparison, `in`, a handful of string methods, a safe
 * regular-expression subset matched in linear time, and CIDR matching,
 * joined by `&&`, `||` and `!`. No loops, no function definitions, no I/O,
 * nothing outside the fields. Expressions are parsed and type-checked once
 * and evaluated as data; nothing downloaded is ever run as code.
 *
 * This file is shared: `sdk/typescript/src/rasp/rule-expr.ts` and
 * `src/client/src/lib/security/rasp/rule-expr.ts` are byte-identical (a test
 * in each tree says so), so the platform accepts exactly what the SDK runs.
 * It imports nothing.
 */

/** Hard limits, identical on the platform and in every SDK. */
export const RULE_EXPR_LIMITS = Object.freeze({
	/** UTF-8 bytes of the whole expression. */
	expressionBytes: 2048,
	/** AST depth (a leaf is 1), and parenthesis nesting. */
	depth: 12,
	/** AST nodes. */
	nodes: 128,
	/** UTF-8 bytes of one string literal, after escapes. */
	stringBytes: 1024,
	/** Items in one `in [...]` list. */
	listItems: 64,
	/** `matches` calls in one expression. */
	regexes: 8,
	/** UTF-8 bytes of one pattern. */
	regexBytes: 256,
	/** Atoms of one pattern once counted repetitions are expanded. */
	regexAtoms: 256,
	/** The largest bound in `{n}`, `{n,}`, `{n,m}`. */
	regexRepeat: 100,
	/** `matches` reads at most this many code points of its subject. */
	matchCodePoints: 4096,
});

export type RuleExprErrorCode =
	| "empty"
	| "too_long"
	| "syntax"
	| "depth"
	| "nodes"
	| "string_too_long"
	| "list_too_long"
	| "unknown_field"
	| "unknown_method"
	| "type"
	| "regex"
	| "too_many_regexes"
	| "cidr"
	/** A context this parser does not know (README "Collector contexts"). */
	| "context";

export type RuleExprError = { code: RuleExprErrorCode; pos: number };

export type RuleFieldType = "string" | "map";

/** The fields an expression may read (README "Custom rules: fields"). */
export const RULE_FIELDS: Readonly<Record<string, RuleFieldType>> = Object.freeze({
	"request.method": "string",
	"request.path": "string",
	"request.route": "string",
	"request.ip": "string",
	"request.headers": "map",
	"request.query": "map",
	"request.body": "map",
	"input.value": "string",
	"input.key": "string",
	"input.source": "string",
	"sink.name": "string",
	"attack.type": "string",
	"attack.rule": "string",
	"app.name": "string",
});

/**
 * Where an expression runs, which decides the fields it may read (README
 * "Collector contexts"): an app's RASP (`app`, the fields above), a coding
 * agent's tool call (`agent_tool`) or a request through the AI proxy
 * (`ai_proxy`). The grammar, types and limits are the same everywhere.
 */
export type RuleContext = "app" | "agent_tool" | "ai_proxy";

/** The fields of each collector context. None is a map. */
export const COLLECTOR_RULE_FIELDS: Readonly<Record<Exclude<RuleContext, "app">, Readonly<Record<string, RuleFieldType>>>> = Object.freeze({
	agent_tool: Object.freeze({
		"tool.name": "string",
		"tool.command": "string",
		"tool.path": "string",
		"agent.name": "string",
		"user.id": "string",
		"device.os": "string",
	} as Record<string, RuleFieldType>),
	ai_proxy: Object.freeze({
		"ai.provider": "string",
		"ai.model": "string",
		"ai.tokens": "string",
		"user.id": "string",
		"device.os": "string",
	} as Record<string, RuleFieldType>),
});

/** The fields an expression may read in a context, or null for one this parser does not know. */
export function ruleContextFields(context: RuleContext): Readonly<Record<string, RuleFieldType>> | null {
	if (context === "app") return RULE_FIELDS;
	return Object.prototype.hasOwnProperty.call(COLLECTOR_RULE_FIELDS, context) ? COLLECTOR_RULE_FIELDS[context] : null;
}

/** One untrusted input of the request (the SDK's input list). */
export type RuleInput = { value: string; key: string; source: string };

/** What an expression is evaluated against. Missing parts read as null. */
export type RuleSubject = {
	app?: string | null;
	request?: {
		method?: string | null;
		path?: string | null;
		route?: string | null;
		ip?: string | null;
		/** Lower-case header names. */
		headers?: Record<string, string>;
		/** Query parameter name -> first value. */
		query?: Record<string, string>;
		/** Flattened body path (`user.name`) -> string leaf. */
		body?: Record<string, string>;
	} | null;
	inputs?: RuleInput[];
	sink?: string | null;
	attack?: { type?: string | null; rule?: string | null } | null;
	/** The collector contexts' fields (README "Collector contexts"). */
	collector?: {
		tool?: { name?: string | null; command?: string | null; path?: string | null } | null;
		agent?: { name?: string | null } | null;
		ai?: { provider?: string | null; model?: string | null; tokens?: string | null } | null;
		user?: { id?: string | null } | null;
		device?: { os?: string | null } | null;
	} | null;
};

type CmpOp = "==" | "!=" | "<" | "<=" | ">" | ">=";
type StrMethod = "startsWith" | "endsWith" | "contains";

/** Regular-expression program (Pike VM). */
type Inst =
	| { op: "char"; c: number }
	| { op: "any" }
	| { op: "class"; r: number[]; neg: boolean }
	| { op: "split"; x: number; y: number }
	| { op: "jmp"; x: number }
	| { op: "bol" }
	| { op: "eol" }
	| { op: "match" };

type Net = { bytes: number[]; prefix: number };

export type RuleNode =
	| { k: "str"; v: string }
	| { k: "bool"; v: boolean }
	| { k: "null" }
	| { k: "field"; name: string; key?: string }
	| { k: "not"; x: RuleNode }
	| { k: "and" | "or"; xs: RuleNode[] }
	| { k: "cmp"; op: CmpOp; l: RuleNode; r: RuleNode }
	| { k: "in"; l: RuleNode; items: string[] }
	| { k: "str_method"; m: StrMethod; t: RuleNode; arg: string }
	| { k: "lower"; t: RuleNode }
	| { k: "matches"; t: RuleNode; prog: Inst[] }
	| { k: "cidr"; t: RuleNode; net: Net };

export type CompiledRuleExpr = {
	ast: RuleNode;
	/** Field names read (without map keys). */
	fields: string[];
	/** `finding` when the expression reads `sink.*` or `attack.*`, else `request`. */
	phase: "request" | "finding";
	/** Reads `input.*`: evaluated once per input, true when any input makes it true. */
	usesInput: boolean;
	/** Reads `request.body[...]`. */
	usesBody: boolean;
	/** The context it was compiled for. */
	context: RuleContext;
};

export type RuleExprResult = { ok: true; expr: CompiledRuleExpr } | { ok: false; error: RuleExprError };

class ExprError extends Error {
	constructor(readonly code: RuleExprErrorCode, readonly pos: number) {
		super(code);
	}
}

/** UTF-8 length of a JS string (a lone surrogate counts 3, as its U+FFFD replacement). */
export function utf8Length(s: string): number {
	let n = 0;
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c < 0x80) n += 1;
		else if (c < 0x800) n += 2;
		else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff) {
			n += 4;
			i++;
		} else n += 3;
	}
	return n;
}

/** The code points of a string, at most `max`. */
function codePoints(s: string, max: number): number[] {
	const out: number[] = [];
	for (let i = 0; i < s.length && out.length < max; ) {
		const c = s.codePointAt(i) as number;
		out.push(c);
		i += c > 0xffff ? 2 : 1;
	}
	return out;
}

// ---- lexer ------------------------------------------------------------------

type Tok = { t: "ident" | "str" | "op" | "eof"; v: string; pos: number };

const OPS2 = ["==", "!=", "<=", ">=", "&&", "||"];
const OPS1 = "()[],.<>!";
const isIdentStart = (c: string) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_";
const isIdentPart = (c: string) => isIdentStart(c) || (c >= "0" && c <= "9");
const HEX = /^[0-9A-Fa-f]{4}$/;

function lex(src: string): Tok[] {
	const toks: Tok[] = [];
	let i = 0;
	while (i < src.length) {
		const c = src[i];
		if (c === " " || c === "\t" || c === "\n" || c === "\r") {
			i++;
			continue;
		}
		const start = i;
		const raw = (c === "r" || c === "R") && (src[i + 1] === '"' || src[i + 1] === "'");
		if (c === '"' || c === "'" || raw) {
			if (raw) i++;
			const quote = src[i];
			i++;
			let v = "";
			for (;;) {
				if (i >= src.length) throw new ExprError("syntax", start);
				const d = src[i];
				if (d === quote) {
					i++;
					break;
				}
				if (d.charCodeAt(0) < 0x20) throw new ExprError("syntax", i);
				if (d === "\\" && !raw) {
					const e = src[i + 1];
					if (e === "\\" || e === '"' || e === "'") v += e;
					else if (e === "n") v += "\n";
					else if (e === "r") v += "\r";
					else if (e === "t") v += "\t";
					else if (e === "u") {
						const h = src.slice(i + 2, i + 6);
						if (!HEX.test(h)) throw new ExprError("syntax", i);
						const code = parseInt(h, 16);
						if (code >= 0xd800 && code <= 0xdfff) throw new ExprError("syntax", i);
						v += String.fromCharCode(code);
						i += 4;
					} else throw new ExprError("syntax", i);
					i += 2;
					continue;
				}
				v += d;
				i++;
			}
			if (utf8Length(v) > RULE_EXPR_LIMITS.stringBytes) throw new ExprError("string_too_long", start);
			toks.push({ t: "str", v, pos: start });
			continue;
		}
		if (isIdentStart(c)) {
			while (i < src.length && isIdentPart(src[i])) i++;
			toks.push({ t: "ident", v: src.slice(start, i), pos: start });
			continue;
		}
		const two = src.slice(i, i + 2);
		if (OPS2.includes(two)) {
			toks.push({ t: "op", v: two, pos: start });
			i += 2;
			continue;
		}
		if (OPS1.includes(c)) {
			toks.push({ t: "op", v: c, pos: start });
			i++;
			continue;
		}
		throw new ExprError("syntax", i);
	}
	toks.push({ t: "eof", v: "", pos: src.length });
	return toks;
}

// ---- parser -----------------------------------------------------------------

const KEYWORDS = new Set(["true", "false", "null", "in"]);
const STR_METHODS = new Set(["startsWith", "endsWith", "contains"]);
const METHODS = new Set(["startsWith", "endsWith", "contains", "lowerAscii", "matches", "inCidr"]);

class Parser {
	private i = 0;
	private nodes = 0;
	/** Parenthesis nesting, and nested `!` (each adds AST depth): both bounded while parsing. */
	private parens = 0;
	private nots = 0;
	regexes = 0;
	constructor(
		private readonly toks: Tok[],
		private readonly fields: Readonly<Record<string, RuleFieldType>> = RULE_FIELDS
	) {}

	private peek(o = 0): Tok {
		return this.toks[Math.min(this.i + o, this.toks.length - 1)];
	}
	private next(): Tok {
		const t = this.peek();
		if (this.i < this.toks.length - 1) this.i++;
		return t;
	}
	private isOp(v: string, o = 0): boolean {
		const t = this.peek(o);
		return t.t === "op" && t.v === v;
	}
	private expectOp(v: string): Tok {
		const t = this.next();
		if (t.t !== "op" || t.v !== v) throw new ExprError("syntax", t.pos);
		return t;
	}
	private count(n: number, pos: number): void {
		this.nodes += n;
		if (this.nodes > RULE_EXPR_LIMITS.nodes) throw new ExprError("nodes", pos);
	}

	parse(): RuleNode {
		const n = this.or();
		const t = this.peek();
		if (t.t !== "eof") throw new ExprError("syntax", t.pos);
		return n;
	}

	private or(): RuleNode {
		const pos = this.peek().pos;
		const xs = [this.and()];
		while (this.isOp("||")) {
			this.next();
			xs.push(this.and());
		}
		if (xs.length === 1) return xs[0];
		this.count(1, pos);
		return { k: "or", xs };
	}

	private and(): RuleNode {
		const pos = this.peek().pos;
		const xs = [this.relation()];
		while (this.isOp("&&")) {
			this.next();
			xs.push(this.relation());
		}
		if (xs.length === 1) return xs[0];
		this.count(1, pos);
		return { k: "and", xs };
	}

	private relation(): RuleNode {
		const l = this.unary();
		const t = this.peek();
		if (t.t === "op" && (t.v === "==" || t.v === "!=" || t.v === "<" || t.v === "<=" || t.v === ">" || t.v === ">=")) {
			this.next();
			const r = this.unary();
			this.count(1, t.pos);
			return { k: "cmp", op: t.v as CmpOp, l, r };
		}
		if (t.t === "ident" && t.v === "in") {
			this.next();
			this.expectOp("[");
			const items: string[] = [];
			while (!this.isOp("]")) {
				const s = this.next();
				if (s.t !== "str") throw new ExprError("syntax", s.pos);
				items.push(s.v);
				if (items.length > RULE_EXPR_LIMITS.listItems) throw new ExprError("list_too_long", s.pos);
				if (this.isOp(",")) this.next();
				else if (!this.isOp("]")) throw new ExprError("syntax", this.peek().pos);
			}
			this.next();
			this.count(2 + items.length, t.pos);
			return { k: "in", l, items };
		}
		return l;
	}

	private unary(): RuleNode {
		const t = this.peek();
		if (this.isOp("!")) {
			this.next();
			if (++this.nots > RULE_EXPR_LIMITS.depth) throw new ExprError("depth", t.pos);
			const x = this.unary();
			this.nots--;
			this.count(1, t.pos);
			return { k: "not", x };
		}
		return this.member();
	}

	private member(): RuleNode {
		let n = this.primary();
		while (this.isOp(".")) {
			this.next();
			const name = this.next();
			if (name.t !== "ident") throw new ExprError("syntax", name.pos);
			if (!this.isOp("(")) throw new ExprError("syntax", this.peek().pos);
			this.next();
			let arg: string | undefined;
			if (this.peek().t === "str") arg = this.next().v;
			this.expectOp(")");
			if (!METHODS.has(name.v)) throw new ExprError("unknown_method", name.pos);
			if (name.v === "lowerAscii") {
				if (arg !== undefined) throw new ExprError("type", name.pos);
				this.count(1, name.pos);
				n = { k: "lower", t: n };
				continue;
			}
			if (arg === undefined) throw new ExprError("type", name.pos);
			this.count(2, name.pos);
			if (STR_METHODS.has(name.v)) n = { k: "str_method", m: name.v as StrMethod, t: n, arg };
			else if (name.v === "matches") {
				this.regexes++;
				if (this.regexes > RULE_EXPR_LIMITS.regexes) throw new ExprError("too_many_regexes", name.pos);
				const prog = compileRegex(arg);
				if (!prog) throw new ExprError("regex", name.pos);
				n = { k: "matches", t: n, prog };
			} else {
				const net = parseCidr(arg);
				if (!net) throw new ExprError("cidr", name.pos);
				n = { k: "cidr", t: n, net };
			}
		}
		return n;
	}

	private primary(): RuleNode {
		const t = this.next();
		if (t.t === "str") {
			this.count(1, t.pos);
			return { k: "str", v: t.v };
		}
		if (t.t === "op" && t.v === "(") {
			if (++this.parens > RULE_EXPR_LIMITS.depth) throw new ExprError("depth", t.pos);
			const n = this.or();
			this.parens--;
			this.expectOp(")");
			return n;
		}
		if (t.t === "ident") {
			if (t.v === "true" || t.v === "false") {
				this.count(1, t.pos);
				return { k: "bool", v: t.v === "true" };
			}
			if (t.v === "null") {
				this.count(1, t.pos);
				return { k: "null" };
			}
			if (KEYWORDS.has(t.v)) throw new ExprError("syntax", t.pos);
			// A dotted field name; a segment followed by `(` is a method call.
			let name = t.v;
			while (this.isOp(".") && this.peek(1).t === "ident" && !(this.peek(2).t === "op" && this.peek(2).v === "(")) {
				this.next();
				name += `.${this.next().v}`;
			}
			const type = Object.prototype.hasOwnProperty.call(this.fields, name) ? this.fields[name] : undefined;
			if (!type) throw new ExprError("unknown_field", t.pos);
			let key: string | undefined;
			if (this.isOp("[")) {
				const open = this.next();
				const s = this.next();
				if (s.t !== "str") throw new ExprError("syntax", s.pos);
				this.expectOp("]");
				if (type !== "map") throw new ExprError("type", open.pos);
				// Header names are case-insensitive: ASCII lower-cased here, as the SDKs record them.
				key = name === "request.headers" ? asciiLower(s.v) : s.v;
			} else if (type === "map") throw new ExprError("type", t.pos);
			this.count(1, t.pos);
			return key === undefined ? { k: "field", name } : { k: "field", name, key };
		}
		throw new ExprError("syntax", t.pos);
	}
}

// ---- types ------------------------------------------------------------------

type Ty = "string" | "bool" | "null";

function typeOf(n: RuleNode): Ty {
	switch (n.k) {
		case "str":
			return "string";
		case "bool":
			return "bool";
		case "null":
			return "null";
		case "field":
			return "string";
		case "not":
			if (typeOf(n.x) !== "bool") throw new ExprError("type", 0);
			return "bool";
		case "and":
		case "or":
			for (const x of n.xs) if (typeOf(x) !== "bool") throw new ExprError("type", 0);
			return "bool";
		case "cmp": {
			const l = typeOf(n.l);
			const r = typeOf(n.r);
			if (n.op === "==" || n.op === "!=") {
				const strish = (t: Ty) => t === "string" || t === "null";
				if (!((strish(l) && strish(r)) || (l === "bool" && r === "bool"))) throw new ExprError("type", 0);
			} else if (l !== "string" || r !== "string") throw new ExprError("type", 0);
			return "bool";
		}
		case "in":
		case "str_method":
		case "matches":
		case "cidr":
			if (typeOf(n.k === "in" ? n.l : n.t) !== "string") throw new ExprError("type", 0);
			return "bool";
		case "lower":
			if (typeOf(n.t) !== "string") throw new ExprError("type", 0);
			return "string";
	}
}

function depthOf(n: RuleNode): number {
	switch (n.k) {
		case "not":
			return 1 + depthOf(n.x);
		case "and":
		case "or":
			return 1 + Math.max(...n.xs.map(depthOf));
		case "cmp":
			return 1 + Math.max(depthOf(n.l), depthOf(n.r));
		case "in":
			return 1 + Math.max(depthOf(n.l), 2);
		case "str_method":
		case "matches":
		case "cidr":
			return 1 + Math.max(depthOf(n.t), 1);
		case "lower":
			return 1 + depthOf(n.t);
		default:
			return 1;
	}
}

function collectFields(n: RuleNode, out: Set<string>): void {
	switch (n.k) {
		case "field":
			out.add(n.name);
			return;
		case "not":
			collectFields(n.x, out);
			return;
		case "and":
		case "or":
			n.xs.forEach((x) => collectFields(x, out));
			return;
		case "cmp":
			collectFields(n.l, out);
			collectFields(n.r, out);
			return;
		case "in":
			collectFields(n.l, out);
			return;
		case "str_method":
		case "matches":
		case "cidr":
		case "lower":
			collectFields(n.t, out);
			return;
		default:
			return;
	}
}

/**
 * Parses and type-checks an expression. Every limit is checked here; an
 * expression that compiles is safe to evaluate on any input.
 */
export function compileRuleExpr(src: unknown, context: RuleContext = "app"): RuleExprResult {
	try {
		const fieldsOf = ruleContextFields(context);
		if (!fieldsOf) return { ok: false, error: { code: "context", pos: 0 } };
		if (typeof src !== "string" || src.trim() === "") return { ok: false, error: { code: "empty", pos: 0 } };
		if (utf8Length(src) > RULE_EXPR_LIMITS.expressionBytes) return { ok: false, error: { code: "too_long", pos: 0 } };
		const p = new Parser(lex(src), fieldsOf);
		const ast = p.parse();
		if (typeOf(ast) !== "bool") throw new ExprError("type", 0);
		if (depthOf(ast) > RULE_EXPR_LIMITS.depth) throw new ExprError("depth", 0);
		const set = new Set<string>();
		collectFields(ast, set);
		const fields = Array.from(set).sort();
		const phase = fields.some((f) => f.startsWith("sink.") || f.startsWith("attack.")) ? "finding" : "request";
		return { ok: true, expr: { ast, fields, phase, usesInput: fields.some((f) => f.startsWith("input.")), usesBody: set.has("request.body"), context } };
	} catch (e) {
		if (e instanceof ExprError) return { ok: false, error: { code: e.code, pos: e.pos } };
		return { ok: false, error: { code: "syntax", pos: 0 } };
	}
}

// ---- evaluation -------------------------------------------------------------

/** Work left for one evaluation (regex steps); exhausting it ends the evaluation as no match. */
export type RuleBudget = { steps: number };
export const DEFAULT_RULE_BUDGET = 4_000_000;

class BudgetExhausted extends Error {}

type Val = string | boolean | null;

const asciiLower = (s: string) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

function own(map: Record<string, string> | undefined, key: string): string | null {
	if (!map || typeof map !== "object" || !Object.prototype.hasOwnProperty.call(map, key)) return null;
	const v = map[key];
	return typeof v === "string" ? v : null;
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** Compares two strings by Unicode code point. */
function cmpCodePoints(a: string, b: string): number {
	let i = 0;
	let j = 0;
	while (i < a.length && j < b.length) {
		const x = a.codePointAt(i) as number;
		const y = b.codePointAt(j) as number;
		if (x !== y) return x < y ? -1 : 1;
		i += x > 0xffff ? 2 : 1;
		j += y > 0xffff ? 2 : 1;
	}
	return i < a.length ? 1 : j < b.length ? -1 : 0;
}

function field(n: { name: string; key?: string }, s: RuleSubject, input: RuleInput | null): string | null {
	const r = s.request && typeof s.request === "object" ? s.request : null;
	switch (n.name) {
		case "request.method":
			return str(r?.method);
		case "request.path":
			return str(r?.path);
		case "request.route":
			return str(r?.route);
		case "request.ip":
			return str(r?.ip);
		case "request.headers":
			return own(r?.headers, n.key as string);
		case "request.query":
			return own(r?.query, n.key as string);
		case "request.body":
			return own(r?.body, n.key as string);
		case "input.value":
			return str(input?.value);
		case "input.key":
			return str(input?.key);
		case "input.source":
			return str(input?.source);
		case "sink.name":
			return str(s.sink);
		case "attack.type":
			return str(s.attack?.type);
		case "attack.rule":
			return str(s.attack?.rule);
		case "app.name":
			return str(s.app);
		default:
			return collectorField(n.name, s);
	}
}

function collectorField(name: string, s: RuleSubject): string | null {
	const c = s.collector && typeof s.collector === "object" ? s.collector : null;
	if (!c) return null;
	switch (name) {
		case "tool.name":
			return str(c.tool?.name);
		case "tool.command":
			return str(c.tool?.command);
		case "tool.path":
			return str(c.tool?.path);
		case "agent.name":
			return str(c.agent?.name);
		case "ai.provider":
			return str(c.ai?.provider);
		case "ai.model":
			return str(c.ai?.model);
		case "ai.tokens":
			return str(c.ai?.tokens);
		case "user.id":
			return str(c.user?.id);
		case "device.os":
			return str(c.device?.os);
		default:
			return null;
	}
}

function ev(n: RuleNode, s: RuleSubject, input: RuleInput | null, budget: RuleBudget): Val {
	switch (n.k) {
		case "str":
		case "bool":
			return n.v;
		case "null":
			return null;
		case "field":
			return field(n, s, input);
		case "not":
			return !ev(n.x, s, input, budget);
		case "and":
			for (const x of n.xs) if (!ev(x, s, input, budget)) return false;
			return true;
		case "or":
			for (const x of n.xs) if (ev(x, s, input, budget)) return true;
			return false;
		case "cmp": {
			const l = ev(n.l, s, input, budget);
			const r = ev(n.r, s, input, budget);
			if (n.op === "==") return l === r;
			if (n.op === "!=") return l !== r;
			if (typeof l !== "string" || typeof r !== "string") return false;
			const c = cmpCodePoints(l, r);
			return n.op === "<" ? c < 0 : n.op === "<=" ? c <= 0 : n.op === ">" ? c > 0 : c >= 0;
		}
		case "in": {
			const l = ev(n.l, s, input, budget);
			return typeof l === "string" && n.items.includes(l);
		}
		case "str_method": {
			const t = ev(n.t, s, input, budget);
			if (typeof t !== "string") return false;
			return n.m === "startsWith" ? t.startsWith(n.arg) : n.m === "endsWith" ? t.endsWith(n.arg) : t.includes(n.arg);
		}
		case "lower": {
			const t = ev(n.t, s, input, budget);
			return typeof t === "string" ? asciiLower(t) : null;
		}
		case "matches": {
			const t = ev(n.t, s, input, budget);
			return typeof t === "string" && runRegex(n.prog, codePoints(t, RULE_EXPR_LIMITS.matchCodePoints), budget);
		}
		case "cidr": {
			const t = ev(n.t, s, input, budget);
			return typeof t === "string" && inCidr(t, n.net);
		}
	}
}

export type RuleEvalResult = { matched: boolean; input?: RuleInput; exhausted?: boolean };

/**
 * Evaluates a compiled expression. An expression that reads `input.*` is
 * evaluated once per input, in order, and matches when any input makes it
 * true (with no inputs, once with the input fields null). Never throws: an
 * evaluation that runs out of budget, or fails in any way, is no match.
 */
export function evaluateRuleExpr(expr: CompiledRuleExpr, subject: RuleSubject, budget: RuleBudget = { steps: DEFAULT_RULE_BUDGET }): RuleEvalResult {
	try {
		if (!expr.usesInput) return { matched: ev(expr.ast, subject, null, budget) === true };
		const inputs = Array.isArray(subject.inputs) ? subject.inputs : [];
		if (!inputs.length) return { matched: ev(expr.ast, subject, null, budget) === true };
		for (const input of inputs) {
			if (input && typeof input === "object" && ev(expr.ast, subject, input, budget) === true) return { matched: true, input };
		}
		return { matched: false };
	} catch (e) {
		return { matched: false, exhausted: e instanceof BudgetExhausted };
	}
}

// ---- regular expressions ----------------------------------------------------

type RNode =
	| { t: "char"; c: number }
	| { t: "any" }
	| { t: "class"; r: number[]; neg: boolean }
	| { t: "bol" }
	| { t: "eol" }
	| { t: "cat"; xs: RNode[] }
	| { t: "alt"; xs: RNode[] }
	| { t: "rep"; x: RNode; min: number; max: number };

const MAX_CP = 0x10ffff;
const DIGIT = [0x30, 0x39];
const WORD = [0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a];
const SPACE = [0x09, 0x0d, 0x20, 0x20];
const META = "\\.^$|?*+()[]{}";
const ESCAPABLE = "\\.^$|?*+()[]{}/-";

class RegexError extends Error {}

function complement(r: number[]): number[] {
	const sorted: [number, number][] = [];
	for (let i = 0; i < r.length; i += 2) sorted.push([r[i], r[i + 1]]);
	sorted.sort((a, b) => a[0] - b[0]);
	const out: number[] = [];
	let next = 0;
	for (const [lo, hi] of sorted) {
		if (lo > next) out.push(next, lo - 1);
		next = Math.max(next, hi + 1);
	}
	if (next <= MAX_CP) out.push(next, MAX_CP);
	return out;
}

class RegexParser {
	private i = 0;
	constructor(private readonly cp: number[]) {}

	private peek(): number | undefined {
		return this.cp[this.i];
	}
	private ch(c: string): boolean {
		return this.cp[this.i] === c.charCodeAt(0);
	}

	parse(): RNode {
		const n = this.alt();
		if (this.i < this.cp.length) throw new RegexError();
		return n;
	}

	private alt(): RNode {
		const xs = [this.cat()];
		while (this.ch("|")) {
			this.i++;
			xs.push(this.cat());
		}
		return xs.length === 1 ? xs[0] : { t: "alt", xs };
	}

	private cat(): RNode {
		const xs: RNode[] = [];
		while (this.i < this.cp.length && !this.ch("|") && !this.ch(")")) xs.push(this.piece());
		return xs.length === 1 ? xs[0] : { t: "cat", xs };
	}

	private piece(): RNode {
		const atom = this.atom();
		const q = this.quant();
		if (!q) return atom;
		if (atom.t === "bol" || atom.t === "eol") throw new RegexError();
		if (hasRep(atom)) throw new RegexError(); // nested quantifier
		if (atomsOf(atom) === 0) throw new RegexError(); // nothing to repeat
		return { t: "rep", x: atom, min: q.min, max: q.max };
	}

	private num(): number | null {
		let s = "";
		while (this.peek() !== undefined && (this.peek() as number) >= 0x30 && (this.peek() as number) <= 0x39) {
			s += String.fromCharCode(this.peek() as number);
			this.i++;
			if (s.length > 3) throw new RegexError();
		}
		return s ? parseInt(s, 10) : null;
	}

	private quant(): { min: number; max: number } | null {
		let q: { min: number; max: number } | null = null;
		if (this.ch("*")) q = { min: 0, max: -1 };
		else if (this.ch("+")) q = { min: 1, max: -1 };
		else if (this.ch("?")) q = { min: 0, max: 1 };
		if (q) this.i++;
		else if (this.ch("{")) {
			this.i++;
			const min = this.num();
			if (min === null) throw new RegexError();
			let max = min;
			if (this.ch(",")) {
				this.i++;
				const m = this.num();
				max = m === null ? -1 : m;
			}
			if (!this.ch("}")) throw new RegexError();
			this.i++;
			const L = RULE_EXPR_LIMITS.regexRepeat;
			if (min > L || max > L || (max !== -1 && max < min)) throw new RegexError();
			q = { min, max };
		} else return null;
		if (this.ch("?")) this.i++; // lazy: the same language, so the same answer
		if (this.ch("*") || this.ch("+") || this.ch("?") || this.ch("{")) throw new RegexError();
		return q;
	}

	private escape(): RNode {
		this.i++; // the backslash
		const c = this.peek();
		if (c === undefined) throw new RegexError();
		this.i++;
		// Only ASCII has meaning after a backslash; a code point above U+FFFF must never alias one.
		const e = c < 0x80 ? String.fromCharCode(c) : "";
		if (e === "d" || e === "D") return { t: "class", r: DIGIT.slice(), neg: e === "D" };
		if (e === "w" || e === "W") return { t: "class", r: WORD.slice(), neg: e === "W" };
		if (e === "s" || e === "S") return { t: "class", r: SPACE.slice(), neg: e === "S" };
		if (e === "n") return { t: "char", c: 0x0a };
		if (e === "r") return { t: "char", c: 0x0d };
		if (e === "t") return { t: "char", c: 0x09 };
		if (e === "f") return { t: "char", c: 0x0c };
		if (e === "v") return { t: "char", c: 0x0b };
		if (e === "x" || e === "u") {
			const n = e === "x" ? 2 : 4;
			const digits = this.cp.slice(this.i, this.i + n);
			if (digits.length !== n || digits.some((d) => d >= 0x80)) throw new RegexError();
			const h = String.fromCharCode(...digits);
			if (!/^[0-9A-Fa-f]+$/.test(h)) throw new RegexError();
			const code = parseInt(h, 16);
			if (code >= 0xd800 && code <= 0xdfff) throw new RegexError();
			this.i += n;
			return { t: "char", c: code };
		}
		if (e && ESCAPABLE.includes(e)) return { t: "char", c };
		throw new RegexError();
	}

	private atom(): RNode {
		const c = this.peek() as number;
		// Operators are ASCII; any other code point (U+1002E included) is a literal.
		const s = c < 0x80 ? String.fromCharCode(c) : "";
		if (s === "(") {
			this.i++;
			if (this.ch("?")) {
				this.i++;
				if (!this.ch(":")) throw new RegexError(); // lookaround, named groups, flags
				this.i++;
			}
			const inner = this.alt();
			if (!this.ch(")")) throw new RegexError();
			this.i++;
			return inner;
		}
		if (s === "[") return this.cls();
		if (s === ".") {
			this.i++;
			return { t: "any" };
		}
		if (s === "^") {
			this.i++;
			return { t: "bol" };
		}
		if (s === "$") {
			this.i++;
			return { t: "eol" };
		}
		if (s === "\\") return this.escape();
		if (s && META.includes(s)) throw new RegexError();
		this.i++;
		return { t: "char", c };
	}

	private clsItem(): RNode {
		const c = this.peek();
		if (c === undefined) throw new RegexError();
		if (c === 0x5c) return this.escape();
		if (c === 0x5b) throw new RegexError(); // unescaped [ inside a class
		this.i++;
		return { t: "char", c };
	}

	private cls(): RNode {
		this.i++; // [
		let neg = false;
		if (this.ch("^")) {
			neg = true;
			this.i++;
		}
		const r: number[] = [];
		while (!this.ch("]")) {
			if (this.i >= this.cp.length) throw new RegexError();
			const a = this.clsItem();
			// `-` between two items is a range; at the start or right before `]` it is literal.
			if (this.ch("-") && this.cp[this.i + 1] !== undefined && this.cp[this.i + 1] !== 0x5d) {
				this.i++; // -
				const b = this.clsItem();
				if (a.t !== "char" || b.t !== "char" || a.c > b.c) throw new RegexError();
				r.push(a.c, b.c);
			} else if (a.t === "char") r.push(a.c, a.c);
			else if (a.t === "class") {
				const parts = a.neg ? complement(a.r) : a.r;
				r.push(...parts);
			} else throw new RegexError();
		}
		this.i++; // ]
		if (!r.length) throw new RegexError();
		return { t: "class", r, neg };
	}
}

function hasRep(n: RNode): boolean {
	if (n.t === "rep") return true;
	if (n.t === "cat" || n.t === "alt") return n.xs.some(hasRep);
	return false;
}

/** Atoms once counted repetitions are expanded (README "Regular expressions"). */
function atomsOf(n: RNode): number {
	switch (n.t) {
		case "char":
		case "any":
		case "class":
			return 1;
		case "bol":
		case "eol":
			return 0;
		case "cat":
		case "alt":
			return n.xs.reduce((a, x) => a + atomsOf(x), 0);
		case "rep": {
			// The copies the program holds: min, then one loop (unbounded) or max - min optional ones.
			return atomsOf(n.x) * (n.max === -1 ? n.min + 1 : n.max);
		}
	}
}

function emit(n: RNode, prog: Inst[]): void {
	switch (n.t) {
		case "char":
			prog.push({ op: "char", c: n.c });
			return;
		case "any":
			prog.push({ op: "any" });
			return;
		case "class":
			prog.push({ op: "class", r: n.r, neg: n.neg });
			return;
		case "bol":
			prog.push({ op: "bol" });
			return;
		case "eol":
			prog.push({ op: "eol" });
			return;
		case "cat":
			n.xs.forEach((x) => emit(x, prog));
			return;
		case "alt": {
			// split L1, next; L1: x0; jmp end; next: split ... ; last
			const jumps: Inst[] = [];
			for (let k = 0; k < n.xs.length; k++) {
				if (k < n.xs.length - 1) {
					const split: Inst = { op: "split", x: prog.length + 1, y: -1 };
					prog.push(split);
					emit(n.xs[k], prog);
					const j: Inst = { op: "jmp", x: -1 };
					prog.push(j);
					jumps.push(j);
					(split as { y: number }).y = prog.length;
				} else emit(n.xs[k], prog);
			}
			for (const j of jumps) (j as { x: number }).x = prog.length;
			return;
		}
		case "rep": {
			for (let k = 0; k < n.min; k++) emit(n.x, prog);
			if (n.max === -1) {
				// L: split body, end; body; jmp L
				const L = prog.length;
				const split: Inst = { op: "split", x: L + 1, y: -1 };
				prog.push(split);
				emit(n.x, prog);
				prog.push({ op: "jmp", x: L });
				(split as { y: number }).y = prog.length;
			} else {
				for (let k = n.min; k < n.max; k++) {
					const split: Inst = { op: "split", x: prog.length + 1, y: -1 };
					prog.push(split);
					emit(n.x, prog);
					(split as { y: number }).y = prog.length;
				}
			}
			return;
		}
	}
}

/** Checks a pattern against the safe subset and compiles it; null when refused. */
export function compileRegex(pattern: string): Inst[] | null {
	try {
		if (typeof pattern !== "string" || utf8Length(pattern) > RULE_EXPR_LIMITS.regexBytes) return null;
		const ast = new RegexParser(codePoints(pattern, Infinity)).parse();
		if (atomsOf(ast) > RULE_EXPR_LIMITS.regexAtoms) return null;
		const prog: Inst[] = [];
		emit(ast, prog);
		prog.push({ op: "match" });
		return prog;
	} catch {
		return null;
	}
}

/** Whether a pattern is in the safe subset. */
export function isSafeRegex(pattern: string): boolean {
	return compileRegex(pattern) !== null;
}

function classHas(r: number[], c: number): boolean {
	for (let k = 0; k < r.length; k += 2) if (c >= r[k] && c <= r[k + 1]) return true;
	return false;
}

/**
 * Pike VM: every thread advances in lock step, one code point at a time, so
 * the work is at most (subject length + 1) x (program size). True when some
 * substring of the subject (respecting `^` and `$`) is in the pattern's language.
 */
function runRegex(prog: Inst[], subject: number[], budget: RuleBudget): boolean {
	const size = prog.length;
	const mark = new Int32Array(size).fill(-1);
	let gen = 0;
	let clist: number[] = [];
	let nlist: number[] = [];
	const stack: number[] = [];
	const len = subject.length;

	const add = (list: number[], pc0: number, pos: number): boolean => {
		stack.length = 0;
		stack.push(pc0);
		while (stack.length) {
			const pc = stack.pop() as number;
			if (mark[pc] === gen) continue;
			mark[pc] = gen;
			if (--budget.steps < 0) throw new BudgetExhausted();
			const inst = prog[pc];
			switch (inst.op) {
				case "jmp":
					stack.push(inst.x);
					break;
				case "split":
					stack.push(inst.y, inst.x);
					break;
				case "bol":
					if (pos === 0) stack.push(pc + 1);
					break;
				case "eol":
					if (pos === len) stack.push(pc + 1);
					break;
				case "match":
					return true;
				default:
					list.push(pc);
			}
		}
		return false;
	};

	for (let pos = 0; ; pos++) {
		// Threads already in clist were marked with this generation when added.
		if (add(clist, 0, pos)) return true;
		if (pos === len) return false;
		const c = subject[pos];
		gen++;
		nlist = [];
		for (const pc of clist) {
			const inst = prog[pc];
			const ok = inst.op === "any" || (inst.op === "char" && inst.c === c) || (inst.op === "class" && classHas(inst.r, c) !== inst.neg);
			if (ok && add(nlist, pc + 1, pos + 1)) return true;
		}
		clist = nlist;
	}
}

// ---- CIDR -------------------------------------------------------------------

const V4_PART = /^(0|[1-9][0-9]{0,2})$/;

function parseV4(s: string): number[] | null {
	const parts = s.split(".");
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const p of parts) {
		if (!V4_PART.test(p)) return null;
		const n = parseInt(p, 10);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

/** An IPv4 or IPv6 address as 16 bytes (IPv4 as `::ffff:a.b.c.d`); null when not an address. */
export function parseIpBytes(s: string): number[] | null {
	if (typeof s !== "string" || s.length > 64) return null;
	const v4 = parseV4(s);
	if (v4) return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4];
	if (!s.includes(":")) return null;
	const halves = s.split("::");
	if (halves.length > 2) return null;
	const groups = (h: string): number[] | null => {
		if (h === "") return [];
		const out: number[] = [];
		const parts = h.split(":");
		for (let k = 0; k < parts.length; k++) {
			const p = parts[k];
			if (k === parts.length - 1 && p.includes(".")) {
				const t = parseV4(p);
				if (!t) return null;
				out.push((t[0] << 8) | t[1], (t[2] << 8) | t[3]);
			} else {
				if (!/^[0-9A-Fa-f]{1,4}$/.test(p)) return null;
				out.push(parseInt(p, 16));
			}
		}
		return out;
	};
	const head = groups(halves[0]);
	const tail = halves.length === 2 ? groups(halves[1]) : [];
	if (!head || !tail) return null;
	if (halves.length === 2 && halves[0] !== "" && halves[0].includes(".")) return null;
	let words: number[];
	if (halves.length === 2) {
		if (head.length + tail.length > 7) return null;
		words = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
	} else {
		if (head.length !== 8) return null;
		words = head;
	}
	const bytes: number[] = [];
	for (const w of words) bytes.push(w >> 8, w & 0xff);
	return bytes;
}

/** `a.b.c.d/n`, `x:y::z/n`, or a bare address (all bits). Null when malformed. */
export function parseCidr(s: string): Net | null {
	if (typeof s !== "string") return null;
	const slash = s.indexOf("/");
	const addr = slash === -1 ? s : s.slice(0, slash);
	if (addr.includes("%")) return null;
	const bytes = parseIpBytes(addr);
	if (!bytes) return null;
	const v4 = parseV4(addr) !== null;
	let prefix = 128;
	if (slash !== -1) {
		const p = s.slice(slash + 1);
		if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
		const n = parseInt(p, 10);
		if (n > (v4 ? 32 : 128)) return null;
		prefix = v4 ? n + 96 : n;
	}
	return { bytes, prefix };
}

function inCidr(ip: string, net: Net): boolean {
	const pct = ip.indexOf("%");
	const bytes = parseIpBytes(pct === -1 ? ip : ip.slice(0, pct));
	if (!bytes) return false;
	let bits = net.prefix;
	for (let k = 0; k < 16 && bits > 0; k++, bits -= 8) {
		const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
		if ((bytes[k] & mask) !== (net.bytes[k] & mask)) return false;
	}
	return true;
}

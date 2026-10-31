import { createHmac } from 'crypto';
import RULES_FILE from './injection-rules.json';

// Prompt-injection and jailbreak detection for the SDK's AI security pack.
//
// A copy of src/client/src/lib/security/injection/detector.ts (itself a port
// of cli/internal/coding/injection/detector.go) loading a byte-identical copy
// of the shared rules.json (`npm run injection:sync-rules` in src/client
// writes every copy; tests check them). The shared corpus's golden results
// (cli/internal/coding/injection/testdata/expected.json) must come out the
// same here, so the CLI, the platform and the SDKs never disagree about what
// is an injection. Change one, change all.
//
// Deterministic and local: nothing leaves the process. What it reports is a
// score, the rules that matched and where, and a short masked snippet, never
// the text itself. Heuristics can be evaded; this catches the common and the
// published, not everything.
//
// Must stay in sync with: sdk/python/src/shield360/ai_security/_injection.py

export type InjectionSource =
	| "prompt"
	| "tool_result"
	| "tool_description"
	| "tool_args"
	| "context"
	| "document"
	| "file";

export const INJECTION_SOURCES: readonly InjectionSource[] = [
	"prompt",
	"tool_result",
	"tool_description",
	"tool_args",
	"context",
	"document",
	"file",
];

type RuleDef = {
	id: string;
	category: string;
	kind?: string;
	description: string;
	weight: number;
	weights?: Record<string, number>;
	sources?: string[];
	/** Literal substrings (folded) one of which a text must contain for the patterns to be tried. */
	any?: string[];
	patterns?: string[];
	within?: string[];
	decoded?: boolean;
	min?: number;
};

type RuleSetDef = {
	version: string;
	threshold: number;
	maxScanChars: number;
	snippetChars: number;
	maxSpans: number;
	rules: RuleDef[];
};

type Rule = RuleDef & { compiled: RegExp[]; withinCompiled: RegExp[] };

/** Code-point offsets into the scanned text, as the Go detector reports them. */
export type Span = [number, number];

export type InjectionMatch = {
	rule: string;
	category: string;
	weight: number;
	spans: Span[];
	/** A short, masked view of the first match. */
	snippet: string;
	/** Keyed hash of the matched text. Absent without a key. */
	fingerprint?: string;
};

export type InjectionResult = {
	version: string;
	score: number;
	threshold: number;
	detected: boolean;
	categories: string[];
	matches: InjectionMatch[];
};

export type ScanOptions = {
	source?: InjectionSource;
	fingerprintKey?: string;
};

const DEF = RULES_FILE as unknown as RuleSetDef;

/**
 * ASCII case folded, with the two non-ASCII letters case-insensitive matching
 * folds onto ASCII (ſ to s, the Kelvin sign to k), so a prefilter can never
 * skip text a pattern would match.
 */
function fold(s: string): string {
	return s.replace(/[A-Z\u017f\u212a]/g, (ch) => (ch === "\u017f" ? "s" : ch === "\u212a" ? "k" : ch.toLowerCase()));
}

const RULES: Rule[] = DEF.rules.map((rule) => ({
	...rule,
	any: rule.any?.map(fold),
	compiled: (rule.patterns || []).map((p) => new RegExp(p, "giu")),
	withinCompiled: (rule.within || []).map((p) => new RegExp(p, "iu")),
}));
const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export const INJECTION_RULES_VERSION = DEF.version;
/** The most characters one scan reads; the rest of a longer text is not scanned. */
export const INJECTION_MAX_SCAN_CHARS: number = DEF.maxScanChars > 0 ? DEF.maxScanChars : 200_000;
export const INJECTION_THRESHOLD = DEF.threshold;

/** Rule ids and what each looks for, for display. */
export function injectionRuleCatalog(): { id: string; category: string; description: string }[] {
	return RULES.map(({ id, category, description }) => ({ id, category, description }));
}

const appliesTo = (rule: Rule, source: InjectionSource) => !rule.sources?.length || rule.sources.includes(source);
const weightFor = (rule: Rule, source: InjectionSource) =>
	rule.weights && Object.prototype.hasOwnProperty.call(rule.weights, source) ? rule.weights[source] : rule.weight;

// ---------------------------------------------------------------------------
// Characters (code points).

function isJSWhitespace(r: number): boolean {
	switch (r) {
		case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x20:
		case 0xa0: case 0x1680: case 0x2028: case 0x2029: case 0x202f: case 0x205f: case 0x3000: case 0xfeff:
			return true;
	}
	return r >= 0x2000 && r <= 0x200a;
}

function normaliseRune(r: number): number {
	if (r === 0x0a || r === 0x0d || r === 0x2028 || r === 0x2029) return 0x0a;
	if (isJSWhitespace(r)) return 0x20;
	return r;
}

const isTag = (r: number) => r >= 0xe0000 && r <= 0xe007f;
const isBidi = (r: number) => (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069);
function isZeroWidth(r: number): boolean {
	switch (r) {
		case 0x200b: case 0x2060: case 0x2061: case 0x2062: case 0x2063: case 0x2064: case 0x180e: case 0xfeff:
			return true;
	}
	return false;
}
const isInvisible = (r: number) =>
	isZeroWidth(r) || r === 0x200c || r === 0x200d || isTag(r) || isBidi(r) || r === 0xad || r === 0x200e || r === 0x200f;
const isASCIILetter = (r: number) => (r >= 0x61 && r <= 0x7a) || (r >= 0x41 && r <= 0x5a);

function codePoints(text: string): number[] {
	const out: number[] = [];
	for (let i = 0; i < text.length; i++) {
		const cp = text.codePointAt(i) as number;
		out.push(cp);
		if (cp > 0xffff) i++;
	}
	return out;
}

function fromCodePoints(cps: number[], start = 0, end = cps.length): string {
	let s = "";
	for (let i = start; i < end; i += 4096) {
		s += String.fromCodePoint(...cps.slice(i, Math.min(end, i + 4096)));
	}
	return s;
}

// ---------------------------------------------------------------------------
// Views.

type View = {
	text: string;
	folded: string;
	/** cpAt[u]: the code-point index of UTF-16 unit u. */
	cpAt: Int32Array;
	origin: number[] | null;
};

function newView(runes: number[], origin: number[] | null): View {
	const text = fromCodePoints(runes);
	const cpAt = new Int32Array(text.length + 1);
	let cp = 0;
	for (let u = 0; u < text.length; u++) {
		cpAt[u] = cp;
		const code = text.charCodeAt(u);
		if (code >= 0xd800 && code <= 0xdbff && u + 1 < text.length) {
			const next = text.charCodeAt(u + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				cpAt[u + 1] = cp;
				u++;
			}
		}
		cp++;
	}
	cpAt[text.length] = cp;
	return { text, folded: fold(text), cpAt, origin };
}

function viewSpan(v: View, start: number, end: number): Span {
	const rs = v.cpAt[start];
	const re = v.cpAt[end];
	if (!v.origin) return [rs, re];
	const os = v.origin[rs];
	const oe = re > rs ? v.origin[re - 1] + 1 : os + 1;
	return [os, oe];
}

// ---------------------------------------------------------------------------
// Scanning.

type Hit = { rule: Rule; spans: Span[]; text: string; snippet: string };

class Collector {
	hits = new Map<string, Hit>();
	constructor(readonly source: InjectionSource) {}

	add(rule: Rule, span: Span, text: string, snippet: string) {
		let hit = this.hits.get(rule.id);
		if (!hit) {
			hit = { rule, spans: [], text, snippet };
			this.hits.set(rule.id, hit);
		}
		if (hit.spans.length < DEF.maxSpans) hit.spans.push(span);
	}

	regexMatches(v: View, decodedOnly: boolean): Map<string, Span[]> {
		const found = new Map<string, Span[]>();
		for (const rule of RULES) {
			if (rule.kind || !appliesTo(rule, this.source) || (decodedOnly && !rule.decoded)) continue;
			if (rule.any?.length && !rule.any.some((lit) => v.folded.includes(lit))) continue;
			for (const re of rule.compiled) {
				re.lastIndex = 0;
				let taken = 0;
				while (taken < 20) {
					const m = re.exec(v.text);
					if (!m) break;
					taken++;
					if (m[0].length === 0) {
						re.lastIndex = m.index + 1;
						continue;
					}
					const matched = m[0];
					if (rule.withinCompiled.every((w) => w.test(matched))) {
						const list = found.get(rule.id) || [];
						list.push(viewSpan(v, m.index, m.index + matched.length));
						found.set(rule.id, list);
					}
				}
			}
		}
		return found;
	}
}

const sortedKeys = (m: Map<string, unknown>) => Array.from(m.keys()).sort(byString);
function byString(a: string, b: string) {
	return a < b ? -1 : a > b ? 1 : 0;
}

/** Scans text for prompt injection with the shared rule set. */
export function scanForInjection(text: string, opts: ScanOptions = {}): InjectionResult {
	const source: InjectionSource = opts.source || "prompt";
	let original = codePoints(typeof text === "string" ? text : "");
	if (DEF.maxScanChars > 0 && original.length > DEF.maxScanChars) original = original.slice(0, DEF.maxScanChars);
	const c = new Collector(source);
	const textOf = (s: Span) => fromCodePoints(original, s[0], s[1]);

	// 1. As written, whitespace made uniform.
	const norm = original.map(normaliseRune);
	const base = newView(norm, null);
	const direct = c.regexMatches(base, false);
	for (const id of sortedKeys(direct)) {
		const rule = BY_ID.get(id) as Rule;
		for (const s of direct.get(id) as Span[]) c.add(rule, s, textOf(s), "");
	}

	// 2. Cleaned: invisible characters removed, fullwidth narrowed.
	const cleaned: number[] = [];
	const origin: number[] = [];
	let changed = false;
	original.forEach((r0, i) => {
		let r = r0;
		if (isInvisible(r)) {
			changed = true;
			return;
		}
		if (r >= 0xff01 && r <= 0xff5e) {
			r -= 0xfee0;
			changed = true;
		}
		cleaned.push(normaliseRune(r));
		origin.push(i);
	});
	if (changed) {
		const hidden = c.regexMatches(newView(cleaned, origin), false);
		for (const id of sortedKeys(hidden)) {
			if (direct.has(id)) continue;
			const spans = hidden.get(id) as Span[];
			const rule = BY_ID.get(id) as Rule;
			for (const s of spans) c.add(rule, s, textOf(s), "");
			for (const split of RULES.filter((r) => r.kind === "invisible_split")) {
				if (appliesTo(split, source)) c.add(split, spans[0], textOf(spans[0]), "");
			}
		}
	}

	// 3. Invisible characters.
	invisible(c, original);

	// 4. Encoded blobs.
	encoded(c, base);

	// 5. Respelled text: look-alike letters, leetspeak and ROT13.
	respelled(c, norm, direct, textOf);

	return result(c, original, opts.fingerprintKey || "");
}

// Views in which each code point is replaced by at most one other, so spans
// stay where they are: look-alike letters from other scripts (Cyrillic,
// Greek, mathematical and circled letters) read as ASCII, leetspeak digits
// read as letters, and ROT13 undone. A rule that only matches in such a view
// was disguised on purpose; the rule of that kind is reported with it. Only
// the instruction rules (those also read in decoded text) are tried.
function respelled(c: Collector, norm: number[], direct: Map<string, Span[]>, textOf: (s: Span) => string) {
	for (const rule of RULES) {
		if (!appliesTo(rule, c.source)) continue;
		let mapped: number[] | null;
		let snippet = "";
		if (rule.kind === "homoglyph") mapped = respellHomoglyphs(norm);
		else if (rule.kind === "leetspeak") mapped = respellLeet(norm);
		else if (rule.kind === "rot13") {
			const folded = fold(fromCodePoints(norm));
			if (rule.any?.length && !rule.any.some((lit) => folded.includes(lit))) continue;
			mapped = rot13(norm);
			snippet = "⟨ROT13 text⟩";
		} else continue;
		if (!mapped) continue;
		const found = c.regexMatches(newView(mapped, null), true);
		let first: Span | null = null;
		for (const id of sortedKeys(found)) {
			if (direct.has(id)) continue;
			if (c.hits.has(id) && snippet === "") continue;
			for (const s of found.get(id) as Span[]) {
				c.add(BY_ID.get(id) as Rule, s, textOf(s), snippet);
				if (!first || s[0] < first[0]) first = s;
			}
		}
		if (first) c.add(rule, first, textOf(first), snippet);
	}
}

/** Letters of other scripts that read as an ASCII letter; mapped only inside a word that also has an ASCII letter. */
const HOMOGLYPHS = new Map<number, number>(
	(
		[
			[0x0430, "a"], [0x0435, "e"], [0x043e, "o"], [0x0440, "p"], [0x0441, "c"], [0x0443, "y"], [0x0445, "x"],
			[0x0456, "i"], [0x0458, "j"], [0x0455, "s"], [0x0501, "d"], [0x0261, "g"], [0x04bb, "h"], [0x051b, "q"], [0x051d, "w"],
			[0x0410, "A"], [0x0412, "B"], [0x0415, "E"], [0x041a, "K"], [0x041c, "M"], [0x041d, "H"], [0x041e, "O"], [0x0420, "P"],
			[0x0421, "C"], [0x0422, "T"], [0x0425, "X"], [0x0406, "I"], [0x0408, "J"], [0x0405, "S"],
			[0x03bf, "o"], [0x03b1, "a"], [0x03bd, "v"], [0x03b9, "i"], [0x03ba, "k"], [0x03c1, "p"], [0x03c5, "u"],
			[0x039f, "O"], [0x0391, "A"], [0x0392, "B"], [0x0395, "E"], [0x0397, "H"], [0x0399, "I"], [0x039a, "K"], [0x039c, "M"],
			[0x039d, "N"], [0x03a1, "P"], [0x03a4, "T"], [0x03a7, "X"], [0x03a5, "Y"], [0x0396, "Z"],
		] as [number, string][]
	).map(([cp, ch]) => [cp, ch.charCodeAt(0)])
);

/** A mathematical alphanumeric or circled letter read as ASCII, or -1. */
function styledLetter(r: number): number {
	if (r >= 0x1d400 && r <= 0x1d6a3) {
		const i = (r - 0x1d400) % 52;
		return i < 26 ? 0x41 + i : 0x61 + i - 26;
	}
	if (r >= 0x24b6 && r <= 0x24cf) return 0x41 + r - 0x24b6;
	if (r >= 0x24d0 && r <= 0x24e9) return 0x61 + r - 0x24d0;
	return -1;
}

function respellHomoglyphs(norm: number[]): number[] | null {
	const out = norm.slice();
	let changed = false;
	const inWord = (r: number) => isASCIILetter(r) || HOMOGLYPHS.has(r);
	for (let i = 0; i < norm.length; ) {
		if (!inWord(norm[i])) {
			const r = styledLetter(norm[i]);
			if (r >= 0) {
				out[i] = r;
				changed = true;
			}
			i++;
			continue;
		}
		let j = i;
		let ascii = false;
		while (j < norm.length && inWord(norm[j])) {
			ascii = ascii || isASCIILetter(norm[j]);
			j++;
		}
		if (ascii) {
			for (let k = i; k < j; k++) {
				const r = HOMOGLYPHS.get(norm[k]);
				if (r !== undefined) {
					out[k] = r;
					changed = true;
				}
			}
		}
		i = j;
	}
	return changed ? out : null;
}

const LEET = new Map<number, number>(
	([["0", "o"], ["1", "i"], ["3", "e"], ["4", "a"], ["5", "s"], ["7", "t"], ["@", "a"], ["$", "s"]] as [string, string][]).map(([a, b]) => [
		a.charCodeAt(0),
		b.charCodeAt(0),
	])
);

/** Leetspeak digits read as letters inside a word that has both. */
function respellLeet(norm: number[]): number[] | null {
	const out = norm.slice();
	let changed = false;
	const isWord = (r: number) => isASCIILetter(r) || (r >= 0x30 && r <= 0x39) || LEET.has(r);
	for (let i = 0; i < norm.length; ) {
		if (!isWord(norm[i])) {
			i++;
			continue;
		}
		let j = i;
		let letters = 0;
		let digits = 0;
		while (j < norm.length && isWord(norm[j])) {
			if (isASCIILetter(norm[j])) letters++;
			else if (LEET.has(norm[j])) digits++;
			j++;
		}
		if (letters > 0 && digits > 0) {
			for (let k = i; k < j; k++) {
				const r = LEET.get(norm[k]);
				if (r !== undefined) {
					out[k] = r;
					changed = true;
				}
			}
		}
		i = j;
	}
	return changed ? out : null;
}

function rot13(norm: number[]): number[] {
	return norm.map((r) => {
		if (r >= 0x61 && r <= 0x7a) return 0x61 + ((r - 0x61 + 13) % 26);
		if (r >= 0x41 && r <= 0x5a) return 0x41 + ((r - 0x41 + 13) % 26);
		return r;
	});
}

function invisible(c: Collector, original: number[]) {
	const tagSpans: Span[] = [];
	const zwSpans: Span[] = [];
	const bidiSpans: Span[] = [];
	const smuggled: number[] = [];
	const smuggledOrigin: number[] = [];
	for (let i = 0; i < original.length; i++) {
		const r = original[i];
		if (isTag(r)) {
			let j = i;
			while (j < original.length && isTag(original[j])) j++;
			const flag = i > 0 && original[i - 1] === 0x1f3f4 && original[j - 1] === 0xe007f && j - i <= 8;
			if (!flag) {
				tagSpans.push([i, j]);
				for (let k = i; k < j; k++) {
					if (original[k] >= 0xe0020 && original[k] <= 0xe007e) {
						smuggled.push(original[k] - 0xe0000);
						smuggledOrigin.push(k);
					}
				}
				smuggled.push(0x20);
				smuggledOrigin.push(j - 1);
			}
			i = j - 1;
		} else if (isZeroWidth(r) && !(r === 0xfeff && i === 0)) {
			zwSpans.push([i, i + 1]);
		} else if ((r === 0x200c || r === 0x200d) && i > 0 && i + 1 < original.length && isASCIILetter(original[i - 1]) && isASCIILetter(original[i + 1])) {
			zwSpans.push([i, i + 1]);
		} else if (isBidi(r)) {
			bidiSpans.push([i, i + 1]);
		}
	}
	const count = (spans: Span[]) => spans.reduce((n, s) => n + s[1] - s[0], 0);
	const concat = (spans: Span[]) => spans.map((s) => fromCodePoints(original, s[0], s[1])).join("");
	for (const rule of RULES) {
		if (!appliesTo(rule, c.source)) continue;
		let spans: Span[];
		let what: string;
		if (rule.kind === "tag") [spans, what] = [tagSpans, "hidden tag characters"];
		else if (rule.kind === "zero_width") [spans, what] = [zwSpans, "zero-width characters"];
		else if (rule.kind === "bidi") [spans, what] = [bidiSpans, "bidirectional control characters"];
		else continue;
		const n = count(spans);
		if (n === 0 || n < Math.max(rule.min || 0, 1)) continue;
		const snippet = `⟨${n} ${what}⟩`;
		const text = concat(spans);
		for (const s of spans) c.add(rule, s, text, snippet);
	}
	if (smuggled.length) {
		const spelled = c.regexMatches(newView(smuggled, smuggledOrigin), true);
		for (const id of sortedKeys(spelled)) {
			const rule = BY_ID.get(id) as Rule;
			for (const s of spelled.get(id) as Span[]) {
				c.add(rule, s, fromCodePoints(original, s[0], s[1]), "⟨instruction in hidden tag characters⟩");
			}
		}
	}
}

const MAX_BLOBS = 20;

function encoded(c: Collector, base: View) {
	for (const rule of RULES) {
		if ((rule.kind !== "base64" && rule.kind !== "hex") || !appliesTo(rule, c.source)) continue;
		const re = rule.kind === "hex" ? /(?:[0-9A-Fa-f]{2}){8,}/g : /[A-Za-z0-9+/_-]{16,}={0,2}/g;
		const decode = rule.kind === "hex" ? decodeHex : decodeBase64;
		const label = rule.kind;
		let seen = 0;
		let m: RegExpExecArray | null;
		while ((m = re.exec(base.text))) {
			const blob = m[0];
			if (blob.length < (rule.min || 0)) continue;
			if (seen >= MAX_BLOBS) break;
			seen++;
			const plain = decode(blob);
			if (plain === null) continue;
			const inner = c.regexMatches(newView(codePoints(plain).map(normaliseRune), null), true);
			if (!inner.size) continue;
			const span = viewSpan(base, m.index, m.index + blob.length);
			const snippet = `⟨${label} blob, ${span[1] - span[0]} characters⟩`;
			for (const id of sortedKeys(inner)) c.add(BY_ID.get(id) as Rule, span, plain, snippet);
			c.add(rule, span, plain, snippet);
		}
	}
}

function printable(bytes: number[]): boolean {
	if (bytes.length < 12) return false;
	let ok = 0;
	for (const ch of bytes) if ((ch >= 0x20 && ch <= 0x7e) || ch === 0x0a || ch === 0x0d || ch === 0x09) ok++;
	return ok * 10 >= bytes.length * 9;
}

function utf8(bytes: number[]): string | null {
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
	} catch {
		return null;
	}
}

function decodeBase64(input: string): string | null {
	const s = input.replace(/=+$/, "");
	if (s.length % 4 === 1) return null;
	const out: number[] = [];
	let acc = 0;
	let bits = 0;
	for (let i = 0; i < s.length; i++) {
		const ch = s.charCodeAt(i);
		let v: number;
		if (ch >= 65 && ch <= 90) v = ch - 65;
		else if (ch >= 97 && ch <= 122) v = ch - 97 + 26;
		else if (ch >= 48 && ch <= 57) v = ch - 48 + 52;
		else if (ch === 43 || ch === 45) v = 62;
		else if (ch === 47 || ch === 95) v = 63;
		else return null;
		acc = ((acc << 6) | v) & 0xffff;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push((acc >> bits) & 0xff);
			acc &= (1 << bits) - 1;
		}
	}
	return printable(out) ? utf8(out) : null;
}

function decodeHex(s: string): string | null {
	if (s.length % 2) return null;
	const out: number[] = [];
	for (let i = 0; i < s.length; i += 2) out.push(parseInt(s.slice(i, i + 2), 16));
	return printable(out) ? utf8(out) : null;
}

function result(c: Collector, original: number[], key: string): InjectionResult {
	const res: InjectionResult = {
		version: DEF.version,
		score: 0,
		threshold: DEF.threshold,
		detected: false,
		categories: [],
		matches: [],
	};
	let keep = 1;
	const cats = new Set<string>();
	for (const id of Array.from(c.hits.keys()).sort(byString)) {
		const hit = c.hits.get(id) as Hit;
		const w = weightFor(hit.rule, c.source);
		if (w <= 0) continue;
		hit.spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
		keep *= 1 - w;
		cats.add(hit.rule.category);
		const fingerprint = injectionFingerprint(key, id, hit.text);
		res.matches.push({
			rule: id,
			category: hit.rule.category,
			weight: w,
			spans: hit.spans,
			snippet: hit.snippet || maskSnippet(original, hit.spans[0][0], hit.spans[0][1], DEF.snippetChars),
			...(fingerprint ? { fingerprint } : {}),
		});
	}
	res.categories = Array.from(cats).sort(byString);
	res.score = Math.round((1 - keep) * 1000) / 1000;
	res.detected = res.matches.length > 0 && res.score >= DEF.threshold;
	return res;
}

// ---------------------------------------------------------------------------
// What a reviewer sees.

/**
 * The start of a match, at most n code points, with invisible characters
 * named, whitespace collapsed, and anything shaped like a key, token or long
 * number cut short.
 */
export function maskSnippet(original: number[], start: number, end: number, n: number): string {
	const s0 = Math.max(0, start);
	const e0 = Math.min(end, original.length);
	const cut = n > 0 && e0 - s0 > n ? s0 + n : e0;
	let out = "";
	for (let i = s0; i < cut; i++) {
		const r = original[i];
		if (isInvisible(r)) out += `⟨U+${r.toString(16).toUpperCase().padStart(4, "0")}⟩`;
		else if (r < 0x20 || (r >= 0x7f && r <= 0x9f) || isJSWhitespace(r)) out += " ";
		else out += String.fromCodePoint(r);
	}
	let s = out
		.replace(/ {2,}/g, " ")
		.replace(/[A-Za-z0-9+/=_-]{16,}/g, "[redacted]")
		.replace(/[0-9]{6,}/g, "•••")
		.trim();
	if (cut < e0) s += "…";
	const cps = codePoints(s);
	if (cps.length > 160) s = `${fromCodePoints(cps, 0, 160)}…`;
	return s;
}

/** Keyed hash of what a rule matched; whitespace and ASCII case folded. */
export function injectionFingerprint(key: string, rule: string, text: string): string {
	if (!key) return "";
	const cps = codePoints(text).slice(0, 500);
	let folded = "";
	let space = false;
	for (const r0 of cps) {
		if (isJSWhitespace(r0)) {
			space = true;
			continue;
		}
		if (space && folded.length > 0) folded += " ";
		space = false;
		const r = r0 >= 0x41 && r0 <= 0x5a ? r0 + 0x20 : r0;
		folded += String.fromCodePoint(r);
	}
	return createHmac("sha256", key).update(`${rule}\u0000${folded}`, "utf8").digest("hex").slice(0, 16);
}

/**
 * Shield360 feature flags: the evaluation engine.
 *
 * Canonical source: sdk/flags-core/src/engine.ts. Byte-identical copies live at
 * sdk/typescript/src/flags/engine.ts (the TypeScript SDK) and
 * src/client/src/lib/platform/flags/engine.ts (the server); tests in both fail
 * when a copy differs. The Python, Go and .NET SDKs port it
 * (sdk/python/src/shield360/flags/_engine.py, sdk/go/flags/engine.go,
 * sdk/dotnet/src/Shield360/Flags/FlagEngine.cs), and every implementation is
 * held to sdk/flags-core/testdata/vectors.json. Change the canonical file,
 * copy it, port it, and add vectors.
 *
 * Pure and dependency-free: no imports, no Node built-ins, no clock, no
 * randomness. The same flag and context always give the same answer.
 */

export type FlagType = 'boolean' | 'string' | 'number' | 'json';
export const FLAG_TYPES: readonly FlagType[] = ['boolean', 'string', 'number', 'json'];

export type FlagValue = boolean | string | number | null | FlagValue[] | { [key: string]: FlagValue };

export type Variation = { key: string; name?: string; value: FlagValue };

export const OPERATORS = [
  'equals',
  'not_equals',
  'in',
  'not_in',
  'contains',
  'starts_with',
  'lt',
  'lte',
  'gt',
  'gte',
  'semver_eq',
  'semver_lt',
  'semver_lte',
  'semver_gt',
  'semver_gte',
  'in_segment',
  'not_in_segment',
] as const;
export type Operator = (typeof OPERATORS)[number];

/**
 * Segment operators: the condition's attribute is the literal `segment` and its
 * values are segment keys. `in_segment` holds when the context is in any of
 * them, `not_in_segment` when it is in none. A condition naming a segment the
 * caller did not pass (or one that does not validate) never holds, either way.
 */
export const SEGMENT_OPERATORS: readonly Operator[] = ['in_segment', 'not_in_segment'];
export const SEGMENT_ATTRIBUTE = 'segment';
export const isSegmentOperator = (v: unknown): boolean =>
  typeof v === 'string' && (SEGMENT_OPERATORS as readonly string[]).indexOf(v) >= 0;

export type ConditionValue = string | number | boolean;
export type Condition = { attribute: string; operator: Operator; values: ConditionValue[] };

export type RolloutWeight = { variation: string; weight: number };
export type Rollout = { bucketBy?: string; weights: RolloutWeight[] };
export type Serve = { variation: string } | { rollout: Rollout };

export type Rule = { id: string; description?: string; conditions: Condition[]; serve: Serve };

/**
 * A named, reusable set of conditions of one environment: the context is in
 * the segment when every condition holds. Segments do not reference segments.
 */
export type Segment = { key: string; conditions: Condition[]; version?: number };

export type FlagDefinition = {
  key: string;
  type: FlagType;
  variations: Variation[];
  /** The variation served while the flag is off (and while it is archived). */
  offVariation: string;
  on: boolean;
  rules: Rule[];
  /** Served when the flag is on and no rule matches. */
  fallthrough: Serve;
  salt: string;
  archived?: boolean;
  version?: number;
  /** service.name of the one app this flag is for; null for every app. */
  appName?: string | null;
};

export type ContextValue = string | number | boolean | null | undefined | ConditionValue[];
export type EvaluationContext = { [attribute: string]: ContextValue };

export type ReasonKind = 'OFF' | 'ARCHIVED' | 'RULE_MATCH' | 'FALLTHROUGH' | 'ERROR';
export type Reason = {
  kind: ReasonKind;
  ruleIndex?: number;
  ruleId?: string;
  inRollout?: boolean;
  bucket?: number;
  errorKind?: 'MALFORMED_FLAG';
};

export type Evaluation = {
  /** The served variation's key; null only when the flag is malformed. */
  variation: string | null;
  value: FlagValue;
  reason: Reason;
};

/** Buckets run 0..99,999: a rollout weight of 1 is a thousandth of a percent. */
export const BUCKETS = 100000;
export const DEFAULT_BUCKET_BY = 'key';

/**
 * Counts every implementation checks alike. Lengths and sizes (names, text
 * values, JSON size) are the server's to limit: string length is counted
 * differently from one language to the next.
 */
export const LIMITS = {
  variations: 20,
  rules: 50,
  conditions: 20,
  conditionValues: 100,
  /** Segments one condition may name. */
  segmentsPerCondition: 20,
};

const FLAG_KEY = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const VARIATION_KEY = /^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/;
const RULE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const ATTRIBUTE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const SALT = /^[A-Za-z0-9_-]{1,64}$/;

export const isFlagKey = (v: unknown): v is string => typeof v === 'string' && FLAG_KEY.test(v);
export const isVariationKey = (v: unknown): v is string =>
  typeof v === 'string' && VARIATION_KEY.test(v);
export const isAttributeName = (v: unknown): v is string =>
  typeof v === 'string' && ATTRIBUTE.test(v);
export const isOperator = (v: unknown): v is Operator =>
  typeof v === 'string' && (OPERATORS as readonly string[]).indexOf(v) >= 0;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** The context's own attribute; never one inherited from Object.prototype (`constructor`, `toString`). */
const own = (context: EvaluationContext, attribute: string): ContextValue =>
  Object.prototype.hasOwnProperty.call(context, attribute) ? context[attribute] : undefined;

// ------------------------------------------------------------------ hashing

/** UTF-8 bytes of a string, without TextEncoder (so nothing global is assumed). */
export function utf8(text: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd; // a lone surrogate, as TextEncoder writes it
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 63),
        0x80 | ((c >> 6) & 63),
        0x80 | (c & 63)
      );
  }
  return out;
}

/** MurmurHash3 (x86, 32-bit, seed 0) of the UTF-8 bytes of `text`, unsigned. */
export function murmur3(text: string): number {
  const bytes = utf8(text);
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h = 0;
  const blocks = bytes.length - (bytes.length % 4);
  for (let i = 0; i < blocks; i += 4) {
    let k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  const tail = bytes.length % 4;
  if (tail === 3) k ^= bytes[blocks + 2] << 16;
  if (tail >= 2) k ^= bytes[blocks + 1] << 8;
  if (tail >= 1) {
    k ^= bytes[blocks];
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
  }
  h ^= bytes.length;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

/** The bucket (0..99,999) a value falls in for a flag: stable across runs, processes and SDKs. */
export function bucketOf(flagKey: string, salt: string, value: string): number {
  return murmur3(flagKey + '.' + salt + '.' + value) % BUCKETS;
}

// ----------------------------------------------------------- attribute text

/**
 * The text of a scalar, the same in every SDK: strings as they are, booleans
 * as true/false, integers without a decimal point, other numbers as their
 * shortest round-trip form. Null for anything else.
 */
export function textOf(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return isFinite(v) ? String(v) : null;
  return null;
}

const NUMBER_TEXT = /^-?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$/;

/** A finite number, or the text of one (no spaces); null otherwise. */
export function numberOf(v: unknown): number | null {
  if (typeof v === 'number') return isFinite(v) ? v : null;
  if (typeof v === 'string' && NUMBER_TEXT.test(v)) {
    const n = Number(v);
    return isFinite(n) ? n : null;
  }
  return null;
}

type SemVer = { major: number; minor: number; patch: number; pre: string[] };
const SEMVER =
  /^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** A semantic version; a missing minor or patch is 0, build metadata is ignored. */
export function parseSemver(v: unknown): SemVer | null {
  if (typeof v !== 'string') return null;
  const m = SEMVER.exec(v);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: m[2] === undefined ? 0 : Number(m[2]),
    patch: m[3] === undefined ? 0 : Number(m[3]),
    pre: m[4] === undefined ? [] : m[4].split('.'),
  };
}

const NUMERIC_ID = /^[0-9]+$/;

/** -1, 0 or 1, by semver precedence. */
export function compareSemver(a: SemVer, b: SemVer): number {
  for (const part of ['major', 'minor', 'patch'] as const) {
    if (a[part] !== b[part]) return a[part] < b[part] ? -1 : 1;
  }
  if (!a.pre.length || !b.pre.length) {
    if (a.pre.length === b.pre.length) return 0;
    return a.pre.length ? -1 : 1; // a pre-release comes before its release
  }
  const n = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < n; i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    if (x === y) continue;
    const xn = NUMERIC_ID.test(x);
    const yn = NUMERIC_ID.test(y);
    if (xn && yn) return Number(x) < Number(y) ? -1 : 1;
    if (xn !== yn) return xn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  if (a.pre.length === b.pre.length) return 0;
  return a.pre.length < b.pre.length ? -1 : 1;
}

// ---------------------------------------------------------------- matching

/** Whether one scalar attribute value satisfies a positive operator against the condition's values. */
function scalarMatches(op: Operator, actual: unknown, values: ConditionValue[]): boolean {
  switch (op) {
    case 'equals':
    case 'in': {
      const text = textOf(actual);
      return text !== null && values.some((v) => textOf(v) === text);
    }
    case 'contains':
    case 'starts_with': {
      const text = textOf(actual);
      if (text === null) return false;
      return values.some((v) => {
        const want = textOf(v);
        if (want === null) return false;
        return op === 'contains' ? text.indexOf(want) >= 0 : text.slice(0, want.length) === want;
      });
    }
    case 'lt':
    case 'lte':
    case 'gt':
    case 'gte': {
      const n = numberOf(actual);
      if (n === null) return false;
      return values.some((v) => {
        const w = numberOf(v);
        if (w === null) return false;
        return op === 'lt' ? n < w : op === 'lte' ? n <= w : op === 'gt' ? n > w : n >= w;
      });
    }
    case 'semver_eq':
    case 'semver_lt':
    case 'semver_lte':
    case 'semver_gt':
    case 'semver_gte': {
      const a = parseSemver(actual);
      if (!a) return false;
      return values.some((v) => {
        const b = parseSemver(v);
        if (!b) return false;
        const c = compareSemver(a, b);
        if (op === 'semver_eq') return c === 0;
        if (op === 'semver_lt') return c < 0;
        if (op === 'semver_lte') return c <= 0;
        if (op === 'semver_gt') return c > 0;
        return c >= 0;
      });
    }
    default:
      return false;
  }
}

const NEGATED: Partial<Record<Operator, Operator>> = { not_equals: 'equals', not_in: 'in' };

/**
 * Whether the context satisfies one condition. A missing (or null) attribute
 * never matches, negated operators included. An array attribute matches a
 * positive operator when any element does, and a negated one when none does.
 */
export function conditionMatches(
  condition: Condition,
  context: EvaluationContext,
  segments?: Segment[]
): boolean {
  if (isSegmentOperator(condition.operator)) return segmentConditionMatches(condition, context, segments);
  const actual = own(context, condition.attribute);
  if (actual === undefined || actual === null) return false;
  const items: unknown[] = Array.isArray(actual) ? actual : [actual];
  if (!items.length) return false;
  const positive = NEGATED[condition.operator];
  if (positive) return !items.some((item) => scalarMatches(positive, item, condition.values));
  return items.some((item) => scalarMatches(condition.operator, item, condition.values));
}

/** The valid segment of this key among `segments`, or null. */
export function findSegment(segments: Segment[] | undefined, key: unknown): Segment | null {
  if (!Array.isArray(segments) || typeof key !== 'string') return null;
  for (const s of segments) {
    if (isRecord(s) && s.key === key) return validateSegment(s).length ? null : s;
  }
  return null;
}

/** Whether the context is in the segment: every one of its conditions holds. */
export function segmentMatches(segment: Segment, context: EvaluationContext): boolean {
  if (!segment.conditions.length) return false;
  return segment.conditions.every((c) => !isSegmentOperator(c.operator) && conditionMatches(c, context));
}

function segmentConditionMatches(
  condition: Condition,
  context: EvaluationContext,
  segments: Segment[] | undefined
): boolean {
  let inAny = false;
  for (const key of condition.values) {
    const segment = findSegment(segments, key);
    if (!segment) return false; // an unknown segment never matches, either way
    if (segmentMatches(segment, context)) inAny = true;
  }
  return condition.operator === 'in_segment' ? inAny : !inAny;
}

/** Every condition holds (a rule with none never matches). */
export function ruleMatches(rule: Rule, context: EvaluationContext, segments?: Segment[]): boolean {
  if (!rule.conditions.length) return false;
  return rule.conditions.every((c) => conditionMatches(c, context, segments));
}

/** The segment keys a flag's rules name, each once, in order of first use. */
export function segmentKeysOf(flag: Pick<FlagDefinition, 'rules'>): string[] {
  const keys: string[] = [];
  if (!Array.isArray(flag.rules)) return keys;
  for (const rule of flag.rules) {
    if (!isRecord(rule) || !Array.isArray(rule.conditions)) continue;
    for (const c of rule.conditions) {
      if (!isRecord(c) || !isSegmentOperator(c.operator) || !Array.isArray(c.values)) continue;
      for (const v of c.values) if (typeof v === 'string' && keys.indexOf(v) < 0) keys.push(v);
    }
  }
  return keys;
}

/** The variation a rollout serves this context, and the bucket it fell in. */
export function rolloutVariation(
  flag: Pick<FlagDefinition, 'key' | 'salt'>,
  rollout: Rollout,
  context: EvaluationContext
): { variation: string; bucket: number } {
  const by = rollout.bucketBy || DEFAULT_BUCKET_BY;
  const text = textOf(own(context, by));
  // Without the attribute everyone is bucket 0: the first variation with weight.
  const bucket = text === null ? 0 : bucketOf(flag.key, flag.salt, text);
  let upper = 0;
  for (const w of rollout.weights) {
    upper += w.weight;
    if (bucket < upper) return { variation: w.variation, bucket };
  }
  // Weights are validated to sum to BUCKETS; this is unreachable for a valid flag.
  const last = rollout.weights[rollout.weights.length - 1];
  return { variation: last ? last.variation : '', bucket };
}

// -------------------------------------------------------------- validation

export type ValidationError = { path: string; code: string };

/** Whether `value` is of the flag's type. */
export function valueMatchesType(type: FlagType, value: unknown): boolean {
  if (type === 'boolean') return typeof value === 'boolean';
  if (type === 'string') return typeof value === 'string';
  if (type === 'number') return typeof value === 'number' && isFinite(value);
  if (type === 'json') return plainJson(value, 0);
  return false;
}

/** Null, a string, a boolean, a finite number, or arrays and plain objects of them, at most 20 deep. */
export function plainJson(v: unknown, depth: number): boolean {
  if (depth > 20) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return true;
  if (typeof v === 'number') return isFinite(v);
  if (Array.isArray(v)) return v.every((x) => plainJson(x, depth + 1));
  if (isRecord(v)) {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return false;
    return Object.keys(v).every((k) => plainJson(v[k], depth + 1));
  }
  return false;
}

function validateServe(
  serve: unknown,
  path: string,
  variationKeys: string[],
  errors: ValidationError[]
): void {
  if (!isRecord(serve)) {
    errors.push({ path, code: 'serve_invalid' });
    return;
  }
  const hasVariation = serve.variation !== undefined;
  const hasRollout = serve.rollout !== undefined;
  if (hasVariation === hasRollout) {
    errors.push({ path, code: 'serve_invalid' });
    return;
  }
  if (hasVariation) {
    if (typeof serve.variation !== 'string' || variationKeys.indexOf(serve.variation) < 0)
      errors.push({ path: path + '.variation', code: 'variation_unknown' });
    return;
  }
  const rollout = serve.rollout;
  if (!isRecord(rollout) || !Array.isArray(rollout.weights) || !rollout.weights.length) {
    errors.push({ path: path + '.rollout', code: 'rollout_invalid' });
    return;
  }
  if (rollout.bucketBy !== undefined && !isAttributeName(rollout.bucketBy))
    errors.push({ path: path + '.rollout.bucketBy', code: 'attribute_invalid' });
  if (rollout.weights.length > LIMITS.variations)
    errors.push({ path: path + '.rollout.weights', code: 'too_many' });
  let total = 0;
  const seen: string[] = [];
  rollout.weights.forEach((w: unknown, i: number) => {
    const at = path + '.rollout.weights.' + i;
    if (!isRecord(w)) {
      errors.push({ path: at, code: 'rollout_invalid' });
      return;
    }
    if (typeof w.variation !== 'string' || variationKeys.indexOf(w.variation) < 0)
      errors.push({ path: at + '.variation', code: 'variation_unknown' });
    else if (seen.indexOf(w.variation) >= 0)
      errors.push({ path: at + '.variation', code: 'duplicate' });
    else seen.push(w.variation);
    if (
      typeof w.weight !== 'number' ||
      !Number.isInteger(w.weight) ||
      w.weight < 0 ||
      w.weight > BUCKETS
    )
      errors.push({ path: at + '.weight', code: 'weight_invalid' });
    else total += w.weight;
  });
  if (total !== BUCKETS) errors.push({ path: path + '.rollout.weights', code: 'weights_sum' });
}

function validateCondition(c: unknown, path: string, errors: ValidationError[], inSegment: boolean): void {
  if (!isRecord(c)) {
    errors.push({ path, code: 'condition_invalid' });
    return;
  }
  if (isSegmentOperator(c.operator)) {
    if (inSegment) {
      errors.push({ path: path + '.operator', code: 'segment_nested' });
      return;
    }
    if (c.attribute !== SEGMENT_ATTRIBUTE) errors.push({ path: path + '.attribute', code: 'attribute_invalid' });
    const keys = c.values;
    if (!Array.isArray(keys) || !keys.length || keys.length > LIMITS.segmentsPerCondition) {
      errors.push({ path: path + '.values', code: 'values_invalid' });
      return;
    }
    const seen: string[] = [];
    keys.forEach((v: unknown, i: number) => {
      if (!isFlagKey(v)) errors.push({ path: path + '.values.' + i, code: 'value_not_segment' });
      else if (seen.indexOf(v) >= 0) errors.push({ path: path + '.values.' + i, code: 'duplicate' });
      else seen.push(v);
    });
    return;
  }
  if (!isAttributeName(c.attribute)) errors.push({ path: path + '.attribute', code: 'attribute_invalid' });
  if (!isOperator(c.operator)) errors.push({ path: path + '.operator', code: 'operator_invalid' });
  const values = c.values;
  if (!Array.isArray(values) || !values.length || values.length > LIMITS.conditionValues) {
    errors.push({ path: path + '.values', code: 'values_invalid' });
    return;
  }
  const single = c.operator === 'equals' || c.operator === 'not_equals';
  if (single && values.length !== 1) errors.push({ path: path + '.values', code: 'values_invalid' });
  values.forEach((v: unknown, i: number) => {
    const at = path + '.values.' + i;
    const scalar =
      typeof v === 'string' ||
      typeof v === 'boolean' ||
      (typeof v === 'number' && isFinite(v));
    if (!scalar) {
      errors.push({ path: at, code: 'value_invalid' });
      return;
    }
    const op = String(c.operator);
    if ((op === 'lt' || op === 'lte' || op === 'gt' || op === 'gte') && numberOf(v) === null)
      errors.push({ path: at, code: 'value_not_number' });
    if (op.indexOf('semver_') === 0 && !parseSemver(v))
      errors.push({ path: at, code: 'value_not_semver' });
  });
}

/**
 * Everything wrong with a flag definition, by path; empty when it is valid.
 * The server refuses to save an invalid flag; the SDKs and the engine treat
 * one as malformed and serve the caller's default.
 */
export function validateFlag(input: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (!isRecord(input)) return [{ path: '', code: 'flag_invalid' }];
  const f = input;
  if (!isFlagKey(f.key)) errors.push({ path: 'key', code: 'key_invalid' });
  const type = f.type as FlagType;
  if (FLAG_TYPES.indexOf(type) < 0) errors.push({ path: 'type', code: 'type_invalid' });
  if (typeof f.on !== 'boolean') errors.push({ path: 'on', code: 'on_invalid' });
  if (typeof f.salt !== 'string' || !SALT.test(f.salt)) errors.push({ path: 'salt', code: 'salt_invalid' });
  if (f.archived !== undefined && typeof f.archived !== 'boolean')
    errors.push({ path: 'archived', code: 'archived_invalid' });

  const keys: string[] = [];
  if (!Array.isArray(f.variations) || f.variations.length < 2 || f.variations.length > LIMITS.variations) {
    errors.push({ path: 'variations', code: 'variations_count' });
  } else {
    f.variations.forEach((v: unknown, i: number) => {
      const at = 'variations.' + i;
      if (!isRecord(v)) {
        errors.push({ path: at, code: 'variation_invalid' });
        return;
      }
      if (!isVariationKey(v.key)) errors.push({ path: at + '.key', code: 'variation_key_invalid' });
      else if (keys.indexOf(v.key) >= 0) errors.push({ path: at + '.key', code: 'duplicate' });
      else keys.push(v.key);
      if (v.name !== undefined && typeof v.name !== 'string')
        errors.push({ path: at + '.name', code: 'name_invalid' });
      if (FLAG_TYPES.indexOf(type) >= 0 && !valueMatchesType(type, v.value))
        errors.push({ path: at + '.value', code: 'value_type' });
    });
    const variationErrors = errors.some((e) => e.path.indexOf('variations') === 0);
    if (type === 'boolean' && !variationErrors) {
      const values = f.variations.map((v: unknown) => (v as Variation).value);
      if (f.variations.length !== 2 || values[0] === values[1])
        errors.push({ path: 'variations', code: 'boolean_variations' });
    }
  }

  if (typeof f.offVariation !== 'string' || keys.indexOf(f.offVariation) < 0)
    errors.push({ path: 'offVariation', code: 'variation_unknown' });

  if (!Array.isArray(f.rules) || f.rules.length > LIMITS.rules) {
    errors.push({ path: 'rules', code: 'rules_invalid' });
  } else {
    const ids: string[] = [];
    f.rules.forEach((r: unknown, i: number) => {
      const at = 'rules.' + i;
      if (!isRecord(r)) {
        errors.push({ path: at, code: 'rule_invalid' });
        return;
      }
      if (typeof r.id !== 'string' || !RULE_ID.test(r.id)) errors.push({ path: at + '.id', code: 'rule_id_invalid' });
      else if (ids.indexOf(r.id) >= 0) errors.push({ path: at + '.id', code: 'duplicate' });
      else ids.push(r.id);
      if (r.description !== undefined && typeof r.description !== 'string')
        errors.push({ path: at + '.description', code: 'description_invalid' });
      if (!Array.isArray(r.conditions) || !r.conditions.length || r.conditions.length > LIMITS.conditions)
        errors.push({ path: at + '.conditions', code: 'conditions_count' });
      else r.conditions.forEach((c: unknown, j: number) => validateCondition(c, at + '.conditions.' + j, errors, false));
      validateServe(r.serve, at + '.serve', keys, errors);
    });
  }
  validateServe(f.fallthrough, 'fallthrough', keys, errors);
  return errors;
}

/**
 * Everything wrong with a segment, by path; empty when it is valid. A segment
 * has a key (the flag key pattern) and 1..20 conditions with the same
 * operators as a rule's, except the segment operators: segments do not nest.
 */
export function validateSegment(input: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (!isRecord(input)) return [{ path: '', code: 'segment_invalid' }];
  if (!isFlagKey(input.key)) errors.push({ path: 'key', code: 'key_invalid' });
  const conditions = input.conditions;
  if (!Array.isArray(conditions) || !conditions.length || conditions.length > LIMITS.conditions)
    errors.push({ path: 'conditions', code: 'conditions_count' });
  else conditions.forEach((c: unknown, j: number) => validateCondition(c, 'conditions.' + j, errors, true));
  return errors;
}

// -------------------------------------------------------------- evaluation

function variationValue(flag: FlagDefinition, key: string): Variation | null {
  for (const v of flag.variations) if (v.key === key) return v;
  return null;
}

function malformed(): Evaluation {
  return { variation: null, value: null, reason: { kind: 'ERROR', errorKind: 'MALFORMED_FLAG' } };
}

/**
 * The variation a flag serves a context (`segments` are the environment's
 * segments, for rules that name them):
 *   archived  -> the off variation (ARCHIVED)
 *   off       -> the off variation (OFF)
 *   on        -> the first rule, in order, whose conditions all hold (RULE_MATCH),
 *                else the fallthrough (FALLTHROUGH)
 * A rollout picks by bucket. A malformed flag serves nothing (ERROR): the
 * caller's default applies. Never throws.
 */
export function evaluate(
  flag: FlagDefinition,
  context: EvaluationContext = {},
  segments?: Segment[]
): Evaluation {
  try {
    if (validateFlag(flag).length) return malformed();
    const ctx: EvaluationContext = isRecord(context) ? context : {};
    const segs: Segment[] = Array.isArray(segments) ? segments : [];
    const off = (kind: 'OFF' | 'ARCHIVED'): Evaluation => {
      const v = variationValue(flag, flag.offVariation) as Variation;
      return { variation: v.key, value: v.value, reason: { kind } };
    };
    if (flag.archived) return off('ARCHIVED');
    if (!flag.on) return off('OFF');
    const serve = (s: Serve, reason: Reason): Evaluation => {
      const fixed = (s as { variation?: string }).variation;
      if (fixed !== undefined) {
        const v = variationValue(flag, fixed) as Variation;
        return { variation: v.key, value: v.value, reason };
      }
      const picked = rolloutVariation(flag, (s as { rollout: Rollout }).rollout, ctx);
      const v = variationValue(flag, picked.variation) as Variation;
      return { variation: v.key, value: v.value, reason: { ...reason, inRollout: true, bucket: picked.bucket } };
    };
    for (let i = 0; i < flag.rules.length; i++) {
      const rule = flag.rules[i];
      if (ruleMatches(rule, ctx, segs)) return serve(rule.serve, { kind: 'RULE_MATCH', ruleIndex: i, ruleId: rule.id });
    }
    return serve(flag.fallthrough, { kind: 'FALLTHROUGH' });
  } catch {
    return malformed();
  }
}

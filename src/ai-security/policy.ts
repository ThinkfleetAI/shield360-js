/**
 * The AI security policy: what each check does, for one app.
 *
 * Every check is `monitor` by default: it reports what it finds and changes
 * nothing. `enforce` is opt-in per check and applies the check's action
 * (strip, redact, drop, block or deny). `off` skips the check. The policy
 * comes from code (init({ aiSecurity })) and from the platform (Shield360 ->
 * the app -> Security -> AI security), which wins where it sets a value.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_policy.py and
 * src/client/src/lib/platform/ai-security/policy.ts (the platform's parser).
 */

export type CheckMode = 'off' | 'monitor' | 'enforce';
export const CHECK_MODES: readonly CheckMode[] = ['off', 'monitor', 'enforce'];

export type LimitWindow = {
  requestsPerMinute?: number | null;
  tokensPerDay?: number | null;
  costPerDayUsd?: number | null;
};

export type ToolRule = {
  /** The end user needs one of these roles. */
  roles?: string[];
  /** Each attribute must have one of the listed values. */
  attributes?: Record<string, string[]>;
  /** Only these tenants may use the tool. */
  tenants?: string[];
  /** Nobody may use it. */
  deny?: boolean;
};

export type McpServerPin = { name: string; publisher?: string; version?: string };
export type McpToolPin = { server: string; name: string; descriptionHash: string; schemaHash: string };

/** The organisation's own kinds of data (Settings -> Sensitive data), as the platform stores them. */
export type CustomDataKindDef = {
  id: string;
  name: string;
  match: { type: 'keywords'; keywords: string[] } | { type: 'masks'; masks: string[] };
};

export type AiSecurityPolicy = {
  /** The platform's version of this policy; 0 for a policy from code only. */
  version: number;
  indirectInjection: { mode: CheckMode; action: 'strip' | 'block'; threshold: number | null };
  jailbreak: { mode: CheckMode; multiTurn: boolean };
  output: {
    mode: CheckMode;
    action: 'redact' | 'block';
    pii: boolean;
    secrets: boolean;
    customKinds: boolean;
    crossTenant: boolean;
    exfilLinks: boolean;
    systemPromptLeak: boolean;
    /** Link and image domains output may point to (a leading `*.` allows subdomains). */
    allowedDomains: string[];
    /** A marker placed in the system prompt; output containing it leaked the prompt. Not a secret. */
    canary: string | null;
  };
  toolPermissions: {
    mode: CheckMode;
    /** A tool with no rule is refused (enforce) or reported (monitor). */
    defaultDeny: boolean;
    rules: Record<string, ToolRule>;
  };
  limits: {
    mode: CheckMode;
    perUser: LimitWindow;
    perTenant: LimitWindow;
    /** How often local counts are merged with the platform's. */
    syncSeconds: number;
  };
  mcp: {
    mode: CheckMode;
    /** Refuse servers and tools that are not pinned (enforce); otherwise they are reported. */
    blockUnknown: boolean;
    servers: McpServerPin[];
    tools: McpToolPin[];
  };
  rag: {
    mode: CheckMode;
    action: 'drop' | 'block';
    /** The metadata field that names a chunk's tenant. */
    tenantField: string;
    hubness: boolean;
  };
  customDataKinds: CustomDataKindDef[];
};

export const DEFAULT_POLICY: Readonly<AiSecurityPolicy> = Object.freeze({
  version: 0,
  indirectInjection: { mode: 'monitor', action: 'strip', threshold: null },
  jailbreak: { mode: 'monitor', multiTurn: true },
  output: {
    mode: 'monitor',
    action: 'redact',
    pii: true,
    secrets: true,
    customKinds: true,
    crossTenant: true,
    exfilLinks: true,
    systemPromptLeak: true,
    allowedDomains: [],
    canary: null,
  },
  toolPermissions: { mode: 'monitor', defaultDeny: false, rules: {} },
  limits: { mode: 'monitor', perUser: {}, perTenant: {}, syncSeconds: 10 },
  mcp: { mode: 'monitor', blockUnknown: false, servers: [], tools: [] },
  rag: { mode: 'monitor', action: 'drop', tenantField: 'tenant_id', hubness: true },
  customDataKinds: [],
} as AiSecurityPolicy);

/** A partial policy, as given in code or sent by the platform. */
export type AiSecurityPolicyInput = {
  version?: number;
  indirectInjection?: Partial<AiSecurityPolicy['indirectInjection']>;
  jailbreak?: Partial<AiSecurityPolicy['jailbreak']>;
  output?: Partial<AiSecurityPolicy['output']>;
  toolPermissions?: Partial<AiSecurityPolicy['toolPermissions']>;
  limits?: Partial<AiSecurityPolicy['limits']>;
  mcp?: Partial<AiSecurityPolicy['mcp']>;
  rag?: Partial<AiSecurityPolicy['rag']>;
  customDataKinds?: CustomDataKindDef[];
};

const MAX_LIST = 500;
const MAX_STR = 256;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const mode = (v: unknown, d: CheckMode): CheckMode => (CHECK_MODES.includes(v as CheckMode) ? (v as CheckMode) : d);
const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() && v.length <= MAX_STR ? v.trim() : null);
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(str).filter((s): s is string => !!s).slice(0, MAX_LIST) : [];
const oneOf = <T extends string>(v: unknown, opts: readonly T[], d: T): T => (opts.includes(v as T) ? (v as T) : d);

function limitNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : null;
}

function limitWindow(v: unknown, d: LimitWindow): LimitWindow {
  if (!isObj(v)) return { ...d };
  const out: LimitWindow = { ...d };
  for (const key of ['requestsPerMinute', 'tokensPerDay', 'costPerDayUsd'] as const) {
    if (key in v) out[key] = limitNumber(v[key]);
  }
  return out;
}

function toolRule(v: unknown): ToolRule | null {
  if (!isObj(v)) return null;
  const rule: ToolRule = {};
  if (v.deny === true) rule.deny = true;
  const roles = strList(v.roles);
  if (roles.length) rule.roles = roles;
  const tenants = strList(v.tenants);
  if (tenants.length) rule.tenants = tenants;
  if (isObj(v.attributes)) {
    const attrs: Record<string, string[]> = {};
    for (const [k, list] of Object.entries(v.attributes).slice(0, 50)) {
      const name = str(k);
      const values = Array.isArray(list) ? strList(list) : str(list) ? [str(list) as string] : [];
      if (name && values.length) attrs[name] = values;
    }
    if (Object.keys(attrs).length) rule.attributes = attrs;
  }
  return rule;
}

const HASH = /^[0-9a-f]{64}$/;

/**
 * Merges a partial policy over a base. Anything malformed is ignored, so a
 * bad value can never switch a check off or on by accident.
 */
export function mergePolicy(base: AiSecurityPolicy, input: unknown): AiSecurityPolicy {
  const p: AiSecurityPolicy = JSON.parse(JSON.stringify(base));
  if (!isObj(input)) return p;
  if (typeof input.version === 'number' && Number.isInteger(input.version) && input.version >= 0) p.version = input.version;

  const ii = input.indirectInjection;
  if (isObj(ii)) {
    p.indirectInjection.mode = mode(ii.mode, p.indirectInjection.mode);
    p.indirectInjection.action = oneOf(ii.action, ['strip', 'block'] as const, p.indirectInjection.action);
    if (ii.threshold === null) p.indirectInjection.threshold = null;
    else if (typeof ii.threshold === 'number' && ii.threshold > 0 && ii.threshold <= 1) p.indirectInjection.threshold = ii.threshold;
  }
  const jb = input.jailbreak;
  if (isObj(jb)) {
    p.jailbreak.mode = mode(jb.mode, p.jailbreak.mode);
    p.jailbreak.multiTurn = bool(jb.multiTurn, p.jailbreak.multiTurn);
  }
  const out = input.output;
  if (isObj(out)) {
    p.output.mode = mode(out.mode, p.output.mode);
    p.output.action = oneOf(out.action, ['redact', 'block'] as const, p.output.action);
    for (const k of ['pii', 'secrets', 'customKinds', 'crossTenant', 'exfilLinks', 'systemPromptLeak'] as const) {
      p.output[k] = bool(out[k], p.output[k]);
    }
    if (Array.isArray(out.allowedDomains)) p.output.allowedDomains = strList(out.allowedDomains).map((d) => d.toLowerCase());
    if (out.canary === null) p.output.canary = null;
    else if (str(out.canary) && (out.canary as string).length >= 8) p.output.canary = (out.canary as string).trim();
  }
  const tp = input.toolPermissions;
  if (isObj(tp)) {
    p.toolPermissions.mode = mode(tp.mode, p.toolPermissions.mode);
    p.toolPermissions.defaultDeny = bool(tp.defaultDeny, p.toolPermissions.defaultDeny);
    if (isObj(tp.rules)) {
      for (const [name, raw] of Object.entries(tp.rules).slice(0, MAX_LIST)) {
        const rule = toolRule(raw);
        if (str(name) && rule) p.toolPermissions.rules[name] = rule;
      }
    }
  }
  const lim = input.limits;
  if (isObj(lim)) {
    p.limits.mode = mode(lim.mode, p.limits.mode);
    p.limits.perUser = limitWindow(lim.perUser, p.limits.perUser);
    p.limits.perTenant = limitWindow(lim.perTenant, p.limits.perTenant);
    if (typeof lim.syncSeconds === 'number' && lim.syncSeconds >= 2 && lim.syncSeconds <= 300) p.limits.syncSeconds = Math.round(lim.syncSeconds);
  }
  const mcp = input.mcp;
  if (isObj(mcp)) {
    p.mcp.mode = mode(mcp.mode, p.mcp.mode);
    p.mcp.blockUnknown = bool(mcp.blockUnknown, p.mcp.blockUnknown);
    if (Array.isArray(mcp.servers)) {
      const servers: McpServerPin[] = [];
      for (const s of mcp.servers.filter(isObj).slice(0, MAX_LIST)) {
        const name = str(s.name);
        if (!name) continue;
        const pin: McpServerPin = { name };
        if (str(s.publisher)) pin.publisher = str(s.publisher) as string;
        if (str(s.version)) pin.version = str(s.version) as string;
        servers.push(pin);
      }
      p.mcp.servers = servers;
    }
    if (Array.isArray(mcp.tools)) {
      p.mcp.tools = mcp.tools
        .filter(isObj)
        .map((t) => ({ server: str(t.server), name: str(t.name), descriptionHash: String(t.descriptionHash || ''), schemaHash: String(t.schemaHash || '') }))
        .filter((t): t is McpToolPin => !!t.server && !!t.name && HASH.test(t.descriptionHash) && HASH.test(t.schemaHash))
        .slice(0, MAX_LIST * 4);
    }
  }
  const rag = input.rag;
  if (isObj(rag)) {
    p.rag.mode = mode(rag.mode, p.rag.mode);
    p.rag.action = oneOf(rag.action, ['drop', 'block'] as const, p.rag.action);
    p.rag.tenantField = str(rag.tenantField) || p.rag.tenantField;
    p.rag.hubness = bool(rag.hubness, p.rag.hubness);
  }
  if (Array.isArray(input.customDataKinds)) {
    const kinds: CustomDataKindDef[] = [];
    for (const k of input.customDataKinds.filter(isObj).slice(0, 50)) {
      const id = str(k.id);
      const m = k.match;
      if (!id || !/^[a-z0-9_]{1,32}$/.test(id) || !isObj(m)) continue;
      const name = str(k.name) || id;
      if (m.type === 'keywords' && strList(m.keywords).length) kinds.push({ id, name, match: { type: 'keywords', keywords: strList(m.keywords) } });
      else if (m.type === 'masks' && strList(m.masks).length) kinds.push({ id, name, match: { type: 'masks', masks: strList(m.masks).slice(0, 20) } });
    }
    p.customDataKinds = kinds;
  }
  return p;
}

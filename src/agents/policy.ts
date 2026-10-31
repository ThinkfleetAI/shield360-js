/**
 * The receiver's policy: defaults, the console policy (GET
 * /api/inbound-agents/policy, cached 60 s) and the local policy, in that order
 * of precedence from lowest to highest. A failed fetch keeps the last good
 * console policy, or the defaults when there never was one.
 */

import { fetchJson } from './passport';
import { AgentPolicy, ASSURANCE_LEVELS, DEFAULT_BASE_URL, DEFAULT_POLICY, Shield360Connection } from './types';

const CACHE_MS = 60 * 1000;
const MAX_OPERATORS = 1000;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The well-typed fields of a policy-like value; unknown or ill-typed ones are dropped. */
export function sanitisePolicy(value: unknown): Partial<AgentPolicy> {
  if (!isObject(value)) return {};
  const out: Partial<AgentPolicy> = {};
  if (value.mode === 'observe' || value.mode === 'enforce') out.mode = value.mode;
  if (typeof value.requireAgent === 'boolean') out.requireAgent = value.requireAgent;
  if (typeof value.requireOnBehalfOf === 'boolean') out.requireOnBehalfOf = value.requireOnBehalfOf;
  if (typeof value.online === 'boolean') out.online = value.online;
  if (value.minAssurance === 'none' || (ASSURANCE_LEVELS as readonly unknown[]).includes(value.minAssurance)) {
    out.minAssurance = value.minAssurance as AgentPolicy['minAssurance'];
  }
  if (Array.isArray(value.operators)) {
    out.operators = value.operators
      .filter((o): o is string => typeof o === 'string' && o.trim().length > 0 && o.length <= 256)
      .map((o) => o.trim())
      .slice(0, MAX_OPERATORS);
  }
  return out;
}

export function baseUrlOf(conn: Shield360Connection): string {
  const env = typeof process !== 'undefined' ? process.env?.SHIELD360_URL : undefined;
  return (conn.baseUrl || env || DEFAULT_BASE_URL).replace(/\/+$/, '');
}

export class PolicySource {
  private readonly local: Partial<AgentPolicy>;
  private remote: Partial<AgentPolicy> | undefined;
  private fetchedAt = -Infinity;
  private inflight: Promise<void> | undefined;

  constructor(
    local: Partial<AgentPolicy> | undefined,
    private readonly from: Shield360Connection | undefined,
    private readonly fetchImpl: () => typeof fetch,
    private readonly now: () => number,
  ) {
    this.local = sanitisePolicy(local);
  }

  /** The policy in force now. The first call with policyFrom waits for the console policy. */
  async current(): Promise<AgentPolicy> {
    if (this.from?.apiKey && this.now() - this.fetchedAt >= CACHE_MS) {
      const refresh = this.refresh();
      // After the first answer, a stale policy is served while it refreshes.
      if (this.remote === undefined) await refresh;
    }
    return this.merged();
  }

  private merged(): AgentPolicy {
    const p = { ...DEFAULT_POLICY, ...(this.remote ?? {}), ...this.local };
    return { ...p, operators: [...p.operators] };
  }

  private refresh(): Promise<void> {
    if (this.inflight) return this.inflight;
    const from = this.from as Shield360Connection;
    this.inflight = (async () => {
      const got = await fetchJson(this.fetchImpl(), `${baseUrlOf(from)}/api/inbound-agents/policy`, {
        method: 'GET',
        headers: { Accept: 'application/json', Authorization: `Bearer ${from.apiKey}` },
      });
      // Failures also wait out the cache period, so a down console is not hammered.
      this.fetchedAt = this.now();
      if (!got || got.status !== 200 || !isObject(got.body)) {
        console.warn(`Shield360 agents: could not load the inbound agents policy${got ? ` (HTTP ${got.status})` : ''}; using the last known policy`);
        return;
      }
      const body = got.body;
      this.remote = sanitisePolicy(isObject(body.policy) ? body.policy : body);
    })()
      .catch(() => undefined)
      .finally(() => {
        this.inflight = undefined;
      });
    return this.inflight;
  }
}

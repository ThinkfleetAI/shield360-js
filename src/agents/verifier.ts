/**
 * The agent passport verifier: reads the Shield360-Agent header, verifies the
 * passport offline (optionally online too), applies the receiver's policy and
 * reports the result. A passport proves who the agent is, who runs it and for
 * whom it acts; it never grants access by itself.
 *
 * Verification order and reason codes are the contract in the agent passports
 * spec; every verifier (this one, the Python one, the issuer's verify route)
 * follows the same order.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_verifier.py
 */

import { assuranceOf, audienceMatches, fetchJson, KeyCache, normaliseIssuer, parsePassport, ParsedPassport, scopesOf, verifySignature } from './passport';
import { PolicySource } from './policy';
import { MemoryReplayStore } from './replay';
import { DecisionReporter } from './report';
import {
  AGENT_HEADER,
  AgentCheck,
  AgentCheckInput,
  AgentCheckOptions,
  AgentCheckReason,
  AgentPolicy,
  AgentVerifierOptions,
  Assurance,
  assuranceRank,
  DEFAULT_ISSUERS,
  MAX_LIFETIME_SECONDS,
  ReplayStore,
} from './types';

const HEADER_LC = AGENT_HEADER.toLowerCase();
const REASON = /^[a-z][a-z0-9_]{0,63}$/;

type Lookup = { token?: string; multiple?: boolean };

function fromValue(v: unknown): Lookup {
  if (Array.isArray(v)) {
    const values = v.filter((x) => typeof x === 'string' && x.trim());
    if (values.length > 1) return { multiple: true };
    return { token: values[0]?.trim() };
  }
  return typeof v === 'string' && v.trim() ? { token: v.trim() } : {};
}

function fromRecord(rec: Record<string, unknown>): Lookup {
  for (const k of Object.keys(rec)) if (k.toLowerCase() === HEADER_LC) return fromValue(rec[k]);
  return {};
}

/** Finds the passport in a Request, IncomingMessage, Headers, header record or string. */
export function readPassport(input: AgentCheckInput): Lookup {
  try {
    if (input === null || input === undefined) return {};
    if (typeof input === 'string') return fromValue(input);
    if (typeof input !== 'object') return {};
    const anyInput = input as { headers?: unknown; get?: unknown };
    if (typeof anyInput.get === 'function') return fromValue((anyInput.get as (n: string) => unknown).call(input, AGENT_HEADER));
    if ('headers' in anyInput && typeof anyInput.headers === 'object' && anyInput.headers !== null) {
      const h = anyInput.headers as { get?: unknown };
      if (typeof h.get === 'function') return fromValue((h.get as (n: string) => unknown).call(h, AGENT_HEADER));
      return fromRecord(h as Record<string, unknown>);
    }
    return fromRecord(input as Record<string, unknown>);
  } catch {
    return {};
  }
}

/** The path of a request URL, without its query (which may carry secrets). */
function pathOf(url: unknown): string | undefined {
  if (typeof url !== 'string' || !url) return undefined;
  const q = url.search(/[?#]/);
  const path = q === -1 ? url : url.slice(0, q);
  try {
    return path.includes('://') ? new URL(path).pathname : path.slice(0, 512);
  } catch {
    return undefined;
  }
}

export type AgentVerifier = {
  /** Checks the passport an input carries. Never throws. */
  check(input: AgentCheckInput, opts?: AgentCheckOptions): Promise<AgentCheck>;
  /** Express/Connect middleware: sets req.shield360Agent, answers 403 when blocked. */
  middleware(): (req: any, res: any, next: (err?: unknown) => void) => void;
  /** The policy in force now (defaults, console, local). */
  policy(): Promise<AgentPolicy>;
  /** Sends queued reports now. */
  flush(): Promise<void>;
  /** Stops the report timer and sends what is queued. */
  close(): Promise<void>;
};

type Failure = { reason: AgentCheckReason | string; passport?: ParsedPassport };

export function agentVerifier(options: AgentVerifierOptions): AgentVerifier {
  const audiences = (Array.isArray(options.audience) ? options.audience : [options.audience]).filter((a) => typeof a === 'string' && a.trim());
  if (!audiences.length) throw new TypeError('agentVerifier: an audience (the receiver host or origin) is required');
  const issuers = new Set((options.issuers?.length ? options.issuers : DEFAULT_ISSUERS).map(normaliseIssuer));
  const skew = Math.max(0, options.clockSkewSeconds ?? 60);
  const now = options.clock ?? Date.now;
  const getFetch = (): typeof fetch => options.fetch ?? globalThis.fetch;
  const keys = new KeyCache(getFetch, now);
  const replay: ReplayStore = options.replay ?? new MemoryReplayStore({ clock: now });
  const policies = new PolicySource(options.policy, options.policyFrom, getFetch, now);
  const reporter = options.report?.apiKey ? new DecisionReporter(options.report, getFetch) : undefined;
  const onlineFailure = options.onlineFailure ?? 'allow';

  type OnlineAnswer = { unreachable: true } | { invalid: string } | { valid: true; assurance?: Assurance; note?: string };

  async function online(p: ParsedPassport, token: string): Promise<OnlineAnswer> {
    const got = await fetchJson(getFetch(), `${normaliseIssuer(p.claims.iss)}/api/agent-passports/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ passport: token, audience: p.claims.aud }),
    });
    const body = got?.body as { valid?: unknown; reason?: unknown; assurance?: unknown } | undefined;
    if (!got || got.status !== 200 || typeof body !== 'object' || body === null || typeof body.valid !== 'boolean') return { unreachable: true };
    const reason = typeof body.reason === 'string' && REASON.test(body.reason) ? body.reason : undefined;
    if (!body.valid) return { invalid: reason ?? 'revoked' };
    // Still valid, but the issuer may lower the on-behalf-of assurance (e.g. reason "mandate_revoked").
    return {
      valid: true,
      ...(body.assurance !== undefined && body.assurance !== null ? { assurance: assuranceOf(body.assurance) } : {}),
      ...(reason ? { note: reason } : {}),
    };
  }

  /** Steps 1-7 of the contract. Returns the failure, or the passport and any non-denying note. */
  async function verify(token: string, wantOnline: boolean): Promise<{ ok: ParsedPassport; note?: string; assurance?: Assurance } | Failure> {
    const parsed = parsePassport(token);
    if (!parsed.ok) return { reason: parsed.reason };
    const p = parsed.passport;
    const c = p.claims;

    const iss = normaliseIssuer(c.iss);
    if (!issuers.has(iss)) return { reason: 'untrusted_issuer' };

    const key = await keys.get(iss, p.kid);
    if (!key) return { reason: 'unknown_key' };
    if (!verifySignature(p, key)) return { reason: 'bad_signature' };

    const t = now() / 1000;
    if (!(c.exp > t - skew)) return { reason: 'expired', passport: p };
    if (!(c.iat <= t + skew)) return { reason: 'not_yet_valid', passport: p };
    if (c.exp - c.iat > MAX_LIFETIME_SECONDS) return { reason: 'lifetime_too_long', passport: p };

    if (!audienceMatches(c.aud, audiences)) return { reason: 'wrong_audience', passport: p };

    try {
      if (await replay.seen(c.jti, (c.exp + skew) * 1000)) return { reason: 'replayed', passport: p };
    } catch {
      return { reason: 'replay_check_failed', passport: p };
    }

    if (wantOnline) {
      const answer = await online(p, token);
      if ('unreachable' in answer) {
        if (onlineFailure === 'deny') return { reason: 'issuer_unreachable', passport: p };
        return { ok: p, note: 'issuer_unreachable' };
      }
      if ('invalid' in answer) return { reason: answer.invalid, passport: p };
      return { ok: p, note: answer.note, assurance: answer.assurance };
    }
    return { ok: p };
  }

  function identity(p: ParsedPassport | undefined, lowered?: Assurance): Partial<AgentCheck> {
    if (!p) return {};
    const c = p.claims;
    let onBehalfOf: AgentCheck['onBehalfOf'];
    if (c.act) {
      // The issuer can only lower the assurance online, never raise it.
      const downgraded = lowered && assuranceRank(lowered) < assuranceRank(c.act.assurance);
      const assurance = downgraded ? (lowered as Assurance) : c.act.assurance;
      onBehalfOf = {
        id: c.act.sub,
        domain: c.act.domain,
        assurance,
        ...(c.act.mandate && !downgraded ? { mandate: { ...c.act.mandate } } : {}),
      };
    }
    let expiresAt: string | undefined;
    try {
      expiresAt = new Date(c.exp * 1000).toISOString();
    } catch {
      expiresAt = undefined;
    }
    return {
      agent: { ...c.agent, ...(c.agent.owner ? { owner: { ...c.agent.owner } } : {}) },
      operator: { ...c.operator },
      ...(onBehalfOf ? { onBehalfOf } : {}),
      scopes: scopesOf(c.scope),
      issuer: normaliseIssuer(c.iss),
      passportId: c.jti,
      ...(expiresAt ? { expiresAt } : {}),
    };
  }

  function operatorAllowed(policy: AgentPolicy, op: { id: string; domain: string | null }): boolean {
    if (!policy.operators.length) return true;
    const id = op.id.toLowerCase();
    const domain = op.domain?.toLowerCase();
    return policy.operators.some((o) => {
      const v = o.toLowerCase();
      return v === id || (!!domain && v === domain);
    });
  }

  async function evaluate(input: AgentCheckInput, opts: AgentCheckOptions): Promise<AgentCheck> {
    const policy = await policies.current();
    const finish = (r: Omit<AgentCheck, 'blocked'>): AgentCheck => ({ ...r, blocked: r.decision === 'deny' && policy.mode === 'enforce' });
    const found = readPassport(input);

    if (found.multiple) return finish({ status: 'invalid', decision: 'deny', reason: 'malformed', scopes: [] });
    if (!found.token) return finish({ status: 'absent', decision: policy.requireAgent ? 'deny' : 'allow', reason: 'absent', scopes: [] });

    const v = await verify(found.token, Boolean(opts.online || policy.online));
    if (!('ok' in v)) return finish({ status: 'invalid', decision: 'deny', reason: v.reason, scopes: [], ...identity(v.passport) });

    const base = { status: 'verified' as const, scopes: [], ...identity(v.ok, v.assurance) };
    if (!operatorAllowed(policy, v.ok.claims.operator)) return finish({ ...base, decision: 'deny', reason: 'operator_not_allowed' });
    if (policy.requireOnBehalfOf && !v.ok.claims.act) return finish({ ...base, decision: 'deny', reason: 'on_behalf_of_required' });
    const need = assuranceRank(policy.minAssurance);
    if (need > 0 && assuranceRank(base.onBehalfOf?.assurance) < need) return finish({ ...base, decision: 'deny', reason: 'assurance_too_low' });
    return finish({ ...base, decision: 'allow', ...(v.note ? { reason: v.note } : {}) });
  }

  function report(result: AgentCheck, opts: AgentCheckOptions): void {
    if (!reporter) return;
    // Calls without a passport are only worth a log line when the policy denied them.
    if (result.status === 'absent' && result.decision === 'allow') return;
    try {
      reporter.add({
        ...result,
        at: new Date(now()).toISOString(),
        ...(opts.route ? { route: String(opts.route).slice(0, 512) } : {}),
        ...(opts.method ? { method: String(opts.method).slice(0, 16).toUpperCase() } : {}),
        receiver: audiences[0],
      });
    } catch {
      // reporting never affects the call
    }
  }

  async function check(input: AgentCheckInput, opts: AgentCheckOptions = {}): Promise<AgentCheck> {
    let result: AgentCheck;
    try {
      result = await evaluate(input, opts ?? {});
    } catch {
      // Unreachable by design; a verifier bug must still deny, never throw.
      result = { status: 'invalid', decision: 'deny', blocked: false, reason: 'malformed', scopes: [] };
      try {
        result.blocked = (await policies.current()).mode === 'enforce';
      } catch {
        result.blocked = false;
      }
    }
    report(result, opts ?? {});
    return result;
  }

  function middleware() {
    return (req: any, res: any, next: (err?: unknown) => void): void => {
      const route = pathOf(req?.originalUrl ?? req?.url);
      check(req, { route, method: typeof req?.method === 'string' ? req.method : undefined }).then(
        (result) => {
          if (req && typeof req === 'object') req.shield360Agent = result;
          if (!result.blocked) return next();
          const body = JSON.stringify({ error: 'agent_not_allowed', reason: result.reason });
          res.statusCode = 403;
          res.setHeader?.('Content-Type', 'application/json; charset=utf-8');
          res.end(body);
        },
        (err) => next(err),
      );
    };
  }

  return {
    check,
    middleware,
    policy: () => policies.current(),
    flush: () => reporter?.flush() ?? Promise.resolve(),
    close: () => reporter?.close() ?? Promise.resolve(),
  };
}

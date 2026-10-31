/**
 * Agent passports: the types shared by the verifier, its policy and its reports.
 *
 * The wire formats (passport claims, receiver policy, check result) are a
 * contract with the Shield360 app (issuer: /api/agent-passports/*, receiver:
 * /api/inbound-agents/*) and with the Python verifier.
 *
 * Must stay in sync with: sdk/python/src/shield360/agents/_types.py
 */

/** The HTTP header a calling agent sends its passport in. */
export const AGENT_HEADER = 'Shield360-Agent';

/** The JWS `typ` every passport carries. */
export const PASSPORT_TYP = 'shield360-agent+jwt';

/** Issuers trusted when none are configured. */
export const DEFAULT_ISSUERS = ['https://app.shield360.ai'];

/** The Shield360 app the policy and reports go to when no base URL is given. */
export const DEFAULT_BASE_URL = 'https://app.shield360.ai';

/** The longest lifetime (exp - iat) a passport may have, in seconds. */
export const MAX_LIFETIME_SECONDS = 300;

/** How strongly a passport shows the agent acts for a person, strongest first. */
export type Assurance = 'delegated' | 'named' | 'unverified';
export const ASSURANCE_LEVELS: readonly Assurance[] = ['delegated', 'named', 'unverified'];
/** The weakest assurance a receiver accepts; "none" has no requirement. */
export type MinAssurance = 'none' | Assurance;

/** Rank of an assurance: higher is stronger; "none" (or no act) is 0. */
export function assuranceRank(a: MinAssurance | undefined): number {
  return a === 'delegated' ? 3 : a === 'named' ? 2 : a === 'unverified' ? 1 : 0;
}

/** The receiver's policy: what to do with the agents that call it. */
export type AgentPolicy = {
  /** observe: never block, report what enforce would do. */
  mode: 'observe' | 'enforce';
  /** A call without a passport is denied (reason "absent"). */
  requireAgent: boolean;
  /** Allowed operator ids or domains; empty means any verified operator. */
  operators: string[];
  /** The passport must say the agent acts for a person (the `act` claim). */
  requireOnBehalfOf: boolean;
  /** Always ask the issuer whether the passport is still good. */
  online: boolean;
  /**
   * The weakest on-behalf-of assurance accepted. "none" (default): no
   * requirement; otherwise a passport without act, or with weaker assurance,
   * is denied with "assurance_too_low".
   */
  minAssurance: MinAssurance;
};

export const DEFAULT_POLICY: Readonly<AgentPolicy> = Object.freeze({
  mode: 'observe',
  requireAgent: false,
  operators: [],
  requireOnBehalfOf: false,
  online: false,
  minAssurance: 'none',
});

/** Why a check did not verify, or why the policy denied it. */
export type AgentCheckReason =
  | 'malformed'
  | 'unsupported_alg'
  | 'untrusted_issuer'
  | 'unknown_key'
  | 'bad_signature'
  | 'expired'
  | 'not_yet_valid'
  | 'lifetime_too_long'
  | 'wrong_audience'
  | 'replayed'
  | 'replay_check_failed'
  | 'revoked'
  | 'unknown_passport'
  | 'issuer_unreachable'
  | 'absent'
  | 'operator_not_allowed'
  | 'on_behalf_of_required'
  | 'assurance_too_low';

export type AgentIdentity = {
  id: string;
  name: string;
  purpose?: string;
  status?: 'enrolled' | 'not_enrolled';
  environment?: string | null;
  risk?: string | null;
  owner?: { domain: string | null };
  /** ISO 8601. */
  reviewedAt?: string | null;
  /** ISO 8601. */
  enrolledAt?: string | null;
};
export type AgentOperator = { id: string; name: string; domain: string | null };
export type AgentMandate = { id: string; expiresAt: string };
export type AgentOnBehalfOf = {
  id: string;
  domain: string | null;
  /** "named" when the passport's act carries none. Lowered when the issuer says so online. */
  assurance: Assurance;
  mandate?: AgentMandate;
};

/** The result of one check. Never contains the passport itself. */
export type AgentCheck = {
  status: 'verified' | 'absent' | 'invalid';
  /** What the policy says. */
  decision: 'allow' | 'deny';
  /** decision === "deny" && mode === "enforce". */
  blocked: boolean;
  reason?: AgentCheckReason | string;
  agent?: AgentIdentity;
  operator?: AgentOperator;
  /** id is the pairwise person id (act.sub): stable per receiver, never the person's id or email. */
  onBehalfOf?: AgentOnBehalfOf;
  scopes: string[];
  issuer?: string;
  /** The passport's jti. */
  passportId?: string;
  /** ISO 8601. */
  expiresAt?: string;
};

/** Remembers passport ids so each is accepted once. */
export interface ReplayStore {
  /**
   * Records `jti` until `expiresAtMs` (epoch milliseconds) and returns whether
   * it had already been seen. Must be atomic for clustered receivers (e.g.
   * Redis `SET key 1 NX PXAT expiresAtMs`, seen = the SET did not happen).
   */
  seen(jti: string, expiresAtMs: number): Promise<boolean>;
}

export type Shield360Connection = { apiKey: string; baseUrl?: string };

export type AgentVerifierOptions = {
  /** The receiver: a host name (`api.servflo.ai`) or an https origin, or several. */
  audience: string | string[];
  /** Trusted issuers' base URLs. Default ["https://app.shield360.ai"]. */
  issuers?: string[];
  /** Local policy, merged over the defaults and over the console policy. */
  policy?: Partial<AgentPolicy>;
  /** Follow the console policy of the receiver's Shield360 project (cached 60 s). */
  policyFrom?: Shield360Connection;
  /** Send results to the project's inbound decision log (batched, never blocks). */
  report?: Shield360Connection;
  /** Where passport ids are remembered. Default: in memory, per process. */
  replay?: ReplayStore;
  /** Allowed clock difference with the issuer, seconds. Default 60. */
  clockSkewSeconds?: number;
  /**
   * What a failed online check (issuer unreachable) means. Default "allow":
   * the passport was already verified offline.
   */
  onlineFailure?: 'allow' | 'deny';
  fetch?: typeof fetch;
  /** Milliseconds since the epoch; for tests. */
  clock?: () => number;
};

export type AgentCheckOptions = {
  /** Ask the issuer too (also on when the policy says online). */
  online?: boolean;
  /** Recorded with the report; never sent anywhere else. */
  route?: string;
  method?: string;
};

/** Anything a passport can be read from. */
export type AgentCheckInput =
  | string
  | Request
  | Headers
  | { headers: unknown }
  | { get(name: string): unknown }
  | Record<string, string | string[] | undefined>
  | null
  | undefined;

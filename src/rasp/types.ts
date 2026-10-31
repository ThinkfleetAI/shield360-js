/**
 * Shield360 RASP shared types. sdk/rasp/README.md is the contract.
 */

export type AttackType =
  | 'sql_injection'
  | 'nosql_injection'
  | 'command_injection'
  | 'shell_spawn'
  | 'path_traversal'
  | 'file_write'
  | 'ssrf'
  | 'outbound'
  | 'deserialization'
  | 'code_injection'
  | 'xxe'
  | 'xss'
  | 'virtual_patch'
  | 'baseline'
  | 'custom_rule'
  | 'deception';

export const ATTACK_TYPES: readonly AttackType[] = [
  'sql_injection',
  'nosql_injection',
  'command_injection',
  'shell_spawn',
  'path_traversal',
  'file_write',
  'ssrf',
  'outbound',
  'deserialization',
  'code_injection',
  'xxe',
  'xss',
  'virtual_patch',
  'baseline',
  'custom_rule',
  'deception',
];

/** Attack types that only ever report: `block` is treated as `monitor` (README "Attack types and modes"). */
export const MONITOR_ONLY: ReadonlySet<AttackType> = new Set<AttackType>(['xss', 'baseline']);

export type RaspMode = 'off' | 'monitor' | 'block';
export type InputSource = 'request' | 'model_output';

/** One piece of untrusted input. `key` is a location name; the value never leaves the process. */
export type RaspInput = { value: string; key: string; source: InputSource };

/** What a detector found. */
export type Finding = {
  attack: AttackType;
  rule: string;
  input?: RaspInput;
  cve?: string;
  /** Virtual patches: the most the rule does. */
  action?: RaspMode;
  /** Allow-list rules: the destination the rule compared, raw (README "Allow-list targets"); masked before it is sent. */
  target?: string;
  /** SQL findings: the dialect the lexer used. */
  dialect?: string;
};

export type RaspAllow = { commands: string[]; outboundHosts: string[]; fileRoots: string[] };

/** A public key for the signed config: a JWK, a JWKS, or one of them as JSON text. */
export type Jwk = { kty: string; crv: string; x: string; kid?: string; [k: string]: unknown };
export type Jwks = { keys: Jwk[] };
export type ConfigPublicKey = string | Jwk | Jwks;

/** `init({ rasp })` options (README "Enabling"). */
export type RaspOptions = {
  /** Turns RASP on. `SHIELD360_RASP=monitor|block` turns it on too; `off` always wins. */
  enabled?: boolean;
  /** Default mode for every attack type without its own. Default `monitor`. */
  mode?: RaspMode;
  /** Mode per attack type. */
  attacks?: Partial<Record<AttackType, RaspMode>>;
  allow?: Partial<RaspAllow>;
  /** Treat model output seen by the SDK's LLM instrumentation as untrusted input. Default true. */
  modelOutput?: boolean;
  /** Poll the signed config when a Shield360 URL and API key are set. Default true. */
  remote?: boolean;
  /**
   * Required to use the signed config: the environment's public key, as a
   * JWK, a JWKS (`{"keys":[…]}`, so a rotation can list the old and new key)
   * or the bare base64url `x`. Also `SHIELD360_CONFIG_PUBLIC_KEY`. Copy it
   * from the app's Runtime protection settings in Shield360. Without it the
   * signed config is not fetched and RASP runs its built-in defaults in
   * monitor mode.
   */
  configPublicKey?: ConfigPublicKey;
  /**
   * Development only: trust on first use (pin the first `kid` the server
   * sends). Also `SHIELD360_CONFIG_TOFU=dev`. Ignored when
   * `NODE_ENV`/`ENVIRONMENT` is `production`.
   */
  allowUnpinnedConfig?: boolean;
  /** Where the last verified config is cached. Default OS temp dir + `/shield360-rasp`. */
  cacheDir?: string;
  /** Report the app's packages and versions at start and every 24 h. Default true. */
  components?: boolean;
  /**
   * Passive IAST: report vulnerabilities (request input reaching a sink
   * unparameterized) seen during normal traffic. Off by default; also
   * `SHIELD360_IAST=on` or the signed config's `iast: "on"`. Never blocks.
   * `sampleRate` (0 to 1) defaults to 1.0, or 0.1 in production.
   */
  iast?: boolean | { enabled?: boolean; sampleRate?: number };
};

export const BLOCK_MESSAGE = 'Request blocked by Shield360 runtime protection';

/**
 * Thrown by a blocking check; framework middleware maps it to a 403. The
 * contract calls it `Shield360RaspBlocked` in TypeScript (exported under
 * that name too).
 */
export class RaspBlockedError extends Error {
  readonly attack: AttackType;
  readonly rule: string;
  readonly eventId: string;
  /** For framework error handlers that read the status from the error (Express, Fastify, Koa). */
  readonly status = 403;
  readonly statusCode = 403;
  constructor(attack: AttackType, rule: string, eventId: string) {
    super(`${BLOCK_MESSAGE} (${attack}, ${rule})`);
    this.name = 'RaspBlockedError';
    this.attack = attack;
    this.rule = rule;
    this.eventId = eventId;
  }
}

/** The JSON body of the 403 (README "The block response"). */
export function blockBody(e: RaspBlockedError): { error: string; attack: AttackType; rule: string; event: string } {
  return { error: BLOCK_MESSAGE, attack: e.attack, rule: e.rule, event: e.eventId };
}

/**
 * shield360/agents: verify the agents that call your API or MCP server.
 *
 *   import { agentVerifier, AGENT_HEADER } from 'shield360/agents';
 *   const verifier = agentVerifier({ audience: 'api.example.com' });
 *   const result = await verifier.check(request);
 *
 * Kept apart from tracing: importing this subpath loads no OpenTelemetry code.
 */

export { agentVerifier, readPassport } from './verifier';
export type { AgentVerifier } from './verifier';
export { MemoryReplayStore } from './replay';
export type { MemoryReplayStoreOptions } from './replay';
export { AGENT_HEADER, ASSURANCE_LEVELS, DEFAULT_ISSUERS, DEFAULT_POLICY, PASSPORT_TYP, assuranceRank } from './types';
export type {
  AgentCheck,
  AgentCheckInput,
  AgentCheckOptions,
  AgentCheckReason,
  AgentIdentity,
  AgentMandate,
  AgentOnBehalfOf,
  AgentOperator,
  AgentPolicy,
  AgentVerifierOptions,
  Assurance,
  MinAssurance,
  ReplayStore,
  Shield360Connection,
} from './types';

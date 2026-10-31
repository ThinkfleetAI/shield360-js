/**
 * What the AI security checks know about the request in progress: the
 * signed-in end user's roles and attributes (for tool permissions), and the
 * identifiers of other tenants that reached the model's context (for the
 * cross-tenant output check).
 *
 * The end customer itself (tenant and user ids) is the one set with
 * Shield360.withCustomer() / setCustomer(); this adds what tool rules need.
 * Scoped with AsyncLocalStorage, so concurrent requests never see each
 * other's state. Bounded: at most MAX_IDENTIFIERS identifiers per request.
 *
 * Must stay in sync with: sdk/python/src/shield360/ai_security/_context.py
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { getCustomer, withCustomer, type CustomerInput } from '../customer';

export type EndUser = {
  roles: string[];
  attributes: Record<string, string>;
};

export type RequestState = {
  user: EndUser | null;
  /** Lower-cased identifier -> the tenant it belongs to. */
  foreign: Map<string, string>;
};

const MAX_IDENTIFIERS = 2000;
const MIN_IDENTIFIER = 4;
const MAX_IDENTIFIER = 200;

const store = new AsyncLocalStorage<RequestState>();
let fallback: RequestState = { user: null, foreign: new Map() };

function state(): RequestState {
  return store.getStore() || fallback;
}

export type EndUserInput = CustomerInput & { roles?: string[]; attributes?: Record<string, unknown> };

function cleanUser(input: EndUserInput | null | undefined): EndUser | null {
  if (!input) return null;
  const roles = Array.isArray(input.roles)
    ? input.roles.filter((r): r is string => typeof r === 'string' && r.length > 0 && r.length <= 128).slice(0, 100)
    : [];
  const attributes: Record<string, string> = {};
  if (input.attributes && typeof input.attributes === 'object') {
    for (const [k, v] of Object.entries(input.attributes).slice(0, 100)) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') attributes[k] = String(v).slice(0, 256);
    }
  }
  return { roles, attributes };
}

/**
 * Runs fn as one request for this end user: the customer (tenant, user) for
 * attribution, and roles and attributes for tool permissions. Identifiers
 * of other tenants seen during fn are forgotten when it returns.
 */
export function withEndUser<T>(user: EndUserInput | null, fn: () => T): T {
  const next: RequestState = { user: cleanUser(user), foreign: new Map() };
  const run = () => store.run(next, fn);
  return user && user.tenantId !== undefined ? withCustomer({ tenantId: user.tenantId, userId: user.userId }, run) : run();
}

/** Sets the process-wide end user (scripts, single-user workers). Prefer withEndUser in servers. */
export function setEndUser(user: EndUserInput | null): void {
  fallback = { user: cleanUser(user), foreign: new Map() };
}

export function getEndUser(): EndUser | null {
  return state().user;
}

/** The tenant of the request in progress, from the end customer. */
export function currentTenant(): string | null {
  return getCustomer()?.tenantId ?? null;
}

/** Remembers identifiers that belong to another tenant and reached this request's context. */
export function rememberForeignIdentifiers(tenantId: string, identifiers: Iterable<string>): void {
  const s = state();
  for (const raw of identifiers) {
    if (s.foreign.size >= MAX_IDENTIFIERS) return;
    const id = String(raw).trim().toLowerCase();
    if (id.length >= MIN_IDENTIFIER && id.length <= MAX_IDENTIFIER) s.foreign.set(id, tenantId);
  }
}

export function foreignIdentifiers(): ReadonlyMap<string, string> {
  return state().foreign;
}

/** Clears the process-wide state; for tests. */
export function resetRequestState(): void {
  fallback = { user: null, foreign: new Map() };
}

const ID_PATTERNS: RegExp[] = [
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, // e-mail
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, // UUID
  /\b[A-Z]{2,6}-?[0-9]{4,}\b/g, // ACCT-00421, INV2024001
  /(?<![0-9])[0-9]{6,}(?![0-9])/g, // long numbers: account, order, phone
];

/** Distinctive identifiers in a text: e-mail addresses, UUIDs, record ids and long numbers. Bounded. */
export function identifiersIn(text: string, limit = 200): string[] {
  const out = new Set<string>();
  if (!text) return [];
  const sample = text.length > 100_000 ? text.slice(0, 100_000) : text;
  for (const re of ID_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(sample)) && out.size < limit) out.add(m[0]);
  }
  return Array.from(out);
}

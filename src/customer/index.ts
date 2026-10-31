/**
 * Cost per end customer: SaaS builders tag each AI call with their own
 * customer (tenant) and, optionally, the end user inside that tenant, so
 * Shield360 can show cost and margin per end customer.
 *
 * Shield360.setCustomer() sets a process-wide default; Shield360.withCustomer()
 * scopes a customer to one call tree through AsyncLocalStorage and wins over
 * the default. CustomerSpanProcessor stamps every span started while a
 * customer is in effect, so one processor covers every instrumentation.
 *
 * The SDK never hashes. Ids are sent as given: Shield360 stores user ids only
 * as a keyed hash on its side, and keeps tenant ids as given unless the
 * organisation opts to hash them.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import type { Context } from '@opentelemetry/api';
import type { ReadableSpan, Span, SpanProcessor } from '@opentelemetry/sdk-trace-base';
import SemanticConvention from '../semantic-convention';

export const ATTR_CUSTOMER_TENANT_ID = SemanticConvention.SHIELD360_CUSTOMER_TENANT_ID;
export const ATTR_CUSTOMER_USER_ID = SemanticConvention.SHIELD360_CUSTOMER_USER_ID;

/** The customer a call is attributed to. userId is only ever set with a tenantId. */
export type Customer = { tenantId: string; userId?: string };

/** What callers pass: ids may be strings or numbers; anything invalid is dropped. */
export type CustomerInput = { tenantId?: string | number | null; userId?: string | number | null };

const MAX_ID_LENGTH = 256;

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/**
 * A valid id, or undefined. Strings and finite numbers are accepted, trimmed,
 * 1–256 characters, with no control characters. Never throws, never logs.
 */
export function normaliseCustomerId(value: unknown): string | undefined {
  let text: string;
  if (typeof value === 'string') text = value;
  else if (typeof value === 'number' && Number.isFinite(value)) text = String(value);
  else if (typeof value === 'bigint') text = value.toString();
  else return undefined;
  text = text.trim();
  if (text.length < 1 || text.length > MAX_ID_LENGTH || hasControlCharacter(text)) return undefined;
  return text;
}

/**
 * A validated customer, or null. A user is only attributable inside a tenant,
 * so a userId without a valid tenantId is dropped with it.
 */
export function normaliseCustomer(input: CustomerInput | null | undefined): Customer | null {
  try {
    if (!input || typeof input !== 'object') return null;
    const tenantId = normaliseCustomerId(input.tenantId);
    if (!tenantId) return null;
    const userId = normaliseCustomerId(input.userId);
    return userId ? { tenantId, userId } : { tenantId };
  } catch {
    return null;
  }
}

// The scoped customer. A store of { customer: null } means "no customer here",
// so an invalid or null scoped customer never falls back to the default.
const _scoped = new AsyncLocalStorage<{ customer: Customer | null }>();
let _default: Customer | null = null;

/**
 * Set the process-wide default customer; null clears it. An invalid tenantId
 * also clears it, so calls are never attributed to the wrong customer.
 */
export function setCustomer(customer: CustomerInput | null): void {
  _default = normaliseCustomer(customer);
}

/**
 * Run fn (sync or async) with this customer in effect for every span it
 * starts. Nested calls override; the scoped customer wins over the default.
 * Passing null (or an invalid tenantId) runs fn with no customer.
 */
export function withCustomer<T>(customer: CustomerInput | null, fn: () => T): T {
  return _scoped.run({ customer: normaliseCustomer(customer) }, fn);
}

/** The customer in effect here (scoped, else the default), or null. */
export function getCustomer(): Customer | null {
  const store = _scoped.getStore();
  const customer = store ? store.customer : _default;
  return customer ? { ...customer } : null;
}

/**
 * Stamps shield360.customer.tenant_id / user_id on every span started while a
 * customer is in effect. A span that already carries a tenant id (set by the
 * caller) is left alone, so explicit attributes are never mixed with ours.
 */
export class CustomerSpanProcessor implements SpanProcessor {
  onStart(span: Span, _parentContext: Context): void {
    try {
      const store = _scoped.getStore();
      const customer = store ? store.customer : _default;
      if (!customer) return;
      if (span.attributes[ATTR_CUSTOMER_TENANT_ID] !== undefined) return;
      span.setAttribute(ATTR_CUSTOMER_TENANT_ID, customer.tenantId);
      if (customer.userId) span.setAttribute(ATTR_CUSTOMER_USER_ID, customer.userId);
    } catch {
      // Never break span creation.
    }
  }

  onEnd(_span: ReadableSpan): void {}

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

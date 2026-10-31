import { InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import Shield360 from '../../index';
import Tracing from '../../otel/tracing';
import {
  ATTR_CUSTOMER_TENANT_ID,
  ATTR_CUSTOMER_USER_ID,
  CustomerSpanProcessor,
  getCustomer,
  normaliseCustomer,
  normaliseCustomerId,
  setCustomer,
  withCustomer,
} from '../index';

const tick = () => new Promise((r) => setTimeout(r, 1));

afterEach(() => setCustomer(null));

describe('customer context', () => {
  it('has no customer by default', () => {
    expect(getCustomer()).toBeNull();
  });

  it('sets and clears a process-wide default', () => {
    setCustomer({ tenantId: 'acme', userId: 'u1' });
    expect(getCustomer()).toEqual({ tenantId: 'acme', userId: 'u1' });
    setCustomer(null);
    expect(getCustomer()).toBeNull();
  });

  it('withCustomer wins over the default, nests, and restores after', () => {
    setCustomer({ tenantId: 'default-co' });
    const seen = withCustomer({ tenantId: 'acme', userId: 'u1' }, () => {
      const outer = getCustomer();
      const inner = withCustomer({ tenantId: 'globex' }, () => getCustomer());
      return { outer, inner, after: getCustomer() };
    });
    expect(seen.outer).toEqual({ tenantId: 'acme', userId: 'u1' });
    expect(seen.inner).toEqual({ tenantId: 'globex' });
    expect(seen.after).toEqual({ tenantId: 'acme', userId: 'u1' });
    expect(getCustomer()).toEqual({ tenantId: 'default-co' });
  });

  it('propagates across awaits and keeps concurrent calls apart', async () => {
    const run = (tenantId: string) =>
      withCustomer({ tenantId }, async () => {
        await tick();
        await Promise.resolve();
        return getCustomer()?.tenantId;
      });
    const results = await Promise.all([run('a'), run('b'), run('c')]);
    expect(results).toEqual(['a', 'b', 'c']);
    expect(getCustomer()).toBeNull();
  });

  it('a null or invalid scoped customer means no customer, not the default', () => {
    setCustomer({ tenantId: 'default-co' });
    expect(withCustomer(null, () => getCustomer())).toBeNull();
    expect(withCustomer({ tenantId: '   ' }, () => getCustomer())).toBeNull();
  });

  it('is exposed on the default export', () => {
    expect(Shield360.setCustomer).toBe(setCustomer);
    expect(Shield360.withCustomer).toBe(withCustomer);
    expect(Shield360.getCustomer).toBe(getCustomer);
  });

  it('returns a copy, so callers cannot change the customer in effect', () => {
    setCustomer({ tenantId: 'acme' });
    getCustomer()!.tenantId = 'mutated';
    expect(getCustomer()).toEqual({ tenantId: 'acme' });
  });
});

describe('validation', () => {
  it('trims strings and converts finite numbers', () => {
    expect(normaliseCustomerId('  acme ')).toBe('acme');
    expect(normaliseCustomerId(42)).toBe('42');
    expect(normaliseCustomerId('x'.repeat(256))).toBe('x'.repeat(256));
  });

  it.each([
    ['empty', ''],
    ['whitespace', '  \t '],
    ['too long', 'x'.repeat(257)],
    ['newline', 'ac\nme'],
    ['NUL', 'ac\u0000me'],
    ['DEL', 'ac\u007fme'],
    ['C1 control', 'ac\u0085me'],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['object', { id: 'acme' }],
    ['boolean', true],
    ['null', null],
    ['undefined', undefined],
  ])('drops %s', (_name, value) => {
    expect(normaliseCustomerId(value)).toBeUndefined();
  });

  it('drops a userId without a valid tenantId', () => {
    expect(normaliseCustomer({ userId: 'u1' })).toBeNull();
    expect(normaliseCustomer({ tenantId: '', userId: 'u1' })).toBeNull();
  });

  it('keeps the tenant when only the userId is invalid', () => {
    expect(normaliseCustomer({ tenantId: 'acme', userId: 'bad\nid' })).toEqual({ tenantId: 'acme' });
  });

  it('never throws on odd input', () => {
    expect(() => setCustomer('acme' as any)).not.toThrow();
    expect(getCustomer()).toBeNull();
    const hostile = { get tenantId() { throw new Error('boom'); } };
    expect(() => setCustomer(hostile as any)).not.toThrow();
    expect(getCustomer()).toBeNull();
  });

  it('an invalid default clears the previous one', () => {
    setCustomer({ tenantId: 'acme' });
    setCustomer({ tenantId: '' });
    expect(getCustomer()).toBeNull();
  });
});

describe('CustomerSpanProcessor', () => {
  let exporter: InMemorySpanExporter;
  let provider: NodeTracerProvider;

  beforeEach(() => {
    exporter = new InMemorySpanExporter();
    provider = new NodeTracerProvider({
      spanProcessors: [new CustomerSpanProcessor(), new SimpleSpanProcessor(exporter)],
    });
  });

  afterEach(async () => {
    await provider.shutdown();
  });

  const startAndEnd = (name = 'chat gpt-4o', attributes?: Record<string, string>) =>
    provider.getTracer('test').startSpan(name, { attributes }).end();
  const lastAttrs = () => {
    const spans = exporter.getFinishedSpans();
    return spans[spans.length - 1].attributes;
  };

  it('leaves spans alone when no customer is in effect', () => {
    startAndEnd();
    expect(lastAttrs()[ATTR_CUSTOMER_TENANT_ID]).toBeUndefined();
    expect(lastAttrs()[ATTR_CUSTOMER_USER_ID]).toBeUndefined();
  });

  it('stamps the default customer on every span, GenAI or not', () => {
    setCustomer({ tenantId: 'acme', userId: 'u1' });
    startAndEnd('GET /orders', { 'http.method': 'GET' });
    expect(lastAttrs()[ATTR_CUSTOMER_TENANT_ID]).toBe('acme');
    expect(lastAttrs()[ATTR_CUSTOMER_USER_ID]).toBe('u1');
  });

  it('stamps the scoped customer, across awaits, over the default', async () => {
    setCustomer({ tenantId: 'default-co' });
    await withCustomer({ tenantId: 'acme', userId: 7 }, async () => {
      await tick();
      startAndEnd();
    });
    expect(lastAttrs()[ATTR_CUSTOMER_TENANT_ID]).toBe('acme');
    expect(lastAttrs()[ATTR_CUSTOMER_USER_ID]).toBe('7');
    startAndEnd();
    expect(lastAttrs()[ATTR_CUSTOMER_TENANT_ID]).toBe('default-co');
    expect(lastAttrs()[ATTR_CUSTOMER_USER_ID]).toBeUndefined();
  });

  it('never overwrites a tenant id the caller set on the span', () => {
    setCustomer({ tenantId: 'acme', userId: 'u1' });
    startAndEnd('chat', { [ATTR_CUSTOMER_TENANT_ID]: 'given' });
    expect(lastAttrs()[ATTR_CUSTOMER_TENANT_ID]).toBe('given');
    expect(lastAttrs()[ATTR_CUSTOMER_USER_ID]).toBeUndefined();
  });

  it('is registered first in the processors the SDK builds', () => {
    const processors = (Tracing as any).buildSpanProcessors({ disableBatch: true });
    expect(processors[0]).toBeInstanceOf(CustomerSpanProcessor);
  });
});

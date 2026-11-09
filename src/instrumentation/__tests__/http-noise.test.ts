import { communityOptions, isHealthProbe, isOwnCall, maskKafkaKey, shield360Host } from '../http-noise';

describe('request tracing noise', () => {
  it('treats probes and health paths as health checks', () => {
    expect(isHealthProbe('/anything', 'kube-probe/1.31')).toBe(true);
    expect(isHealthProbe('/', 'ELB-HealthChecker/2.0')).toBe(true);
    expect(isHealthProbe('/healthz', 'curl/8')).toBe(true);
    expect(isHealthProbe('/api/health?deep=1', undefined)).toBe(true);
    expect(isHealthProbe('/readyz/', undefined)).toBe(true);
  });

  it('keeps the app\'s own requests', () => {
    expect(isHealthProbe('/api/orders', 'Mozilla/5.0')).toBe(false);
    expect(isHealthProbe('/healthy-recipes', undefined)).toBe(false);
    expect(isHealthProbe(undefined, undefined)).toBe(false);
  });

  it('knows the Shield360 host from SHIELD360_URL', () => {
    expect(shield360Host({ SHIELD360_URL: 'https://app.shield360.ai/' })).toBe('app.shield360.ai');
    expect(shield360Host({ SHIELD360_URL: 'not a url' })).toBe('');
    expect(shield360Host({})).toBe('');
    expect(isOwnCall('APP.shield360.ai', 'app.shield360.ai')).toBe(true);
    expect(isOwnCall('api.example.com', 'app.shield360.ai')).toBe(false);
    expect(isOwnCall('app.shield360.ai', '')).toBe(false);
  });

  it('wires the hooks into http and undici only', () => {
    const before = process.env.SHIELD360_URL;
    process.env.SHIELD360_URL = 'https://app.shield360.ai';
    try {
      const http = communityOptions('http') as any;
      expect(http.ignoreIncomingRequestHook({ url: '/healthz', headers: {} })).toBe(true);
      expect(http.ignoreIncomingRequestHook({ url: '/api/orders', headers: { 'user-agent': 'Mozilla/5.0' } })).toBe(false);
      expect(http.ignoreOutgoingRequestHook({ hostname: 'app.shield360.ai' })).toBe(true);
      expect(http.ignoreOutgoingRequestHook({ hostname: 'api.anthropic.com', port: 443 })).toBe(false);
      const undici = communityOptions('undici') as any;
      expect(undici.ignoreRequestHook({ origin: 'https://app.shield360.ai' })).toBe(true);
      expect(undici.ignoreRequestHook({ origin: 'https://api.anthropic.com' })).toBe(false);
      expect(communityOptions('koa')).toBeUndefined();
    } finally {
      if (before === undefined) delete process.env.SHIELD360_URL;
      else process.env.SHIELD360_URL = before;
    }
  });
});

describe('data store options', () => {
  it('records cache commands by name only', () => {
    const redis = communityOptions('redis') as any;
    expect(redis.dbStatementSerializer('get', ['session:ada@example.com'])).toBe('GET');
    expect((communityOptions('ioredis') as any).dbStatementSerializer('set', ['k', 'secret'])).toBe('SET');
  });

  it('keeps GraphQL values and Mongo values out', () => {
    expect(communityOptions('graphql')).toMatchObject({ allowValues: false, ignoreTrivialResolveSpans: true });
    expect(communityOptions('mongodb')).toEqual({ enhancedDatabaseReporting: false });
    expect(communityOptions('aws-sdk')).toEqual({ suppressInternalInstrumentation: true });
    expect(communityOptions('express')).toEqual({ ignoreLayersType: ['middleware'] });
  });

  it('masks values out of mysql statements', () => {
    expect(communityOptions('mysql2')).toEqual({ maskStatement: true });
    expect(communityOptions('mysql')).toEqual({ enhancedDatabaseReporting: false });
    // The instrumentation's own statement builder, with the option set: values never reach the text.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getQueryText } = require('@opentelemetry/instrumentation-mysql2/build/src/utils');
    const format = (sql: string, values: unknown[]) => sql.replace(/\?/g, () => `'${values.shift()}'`);
    expect(getQueryText('SELECT * FROM users WHERE email = ?', format, ['ada@example.com'], true))
      .toBe('SELECT * FROM users WHERE email = ?');
    expect(getQueryText("UPDATE t SET n = 42 WHERE name = 'Ada'", format, undefined, true))
      .toBe('UPDATE t SET n = ? WHERE name = ?');
    expect(getQueryText('SELECT * FROM users WHERE email = ?', format, ['ada@example.com'], false))
      .toContain('ada@example.com');
  });

  it('records a Kafka message key as ? and never the payload', () => {
    const kafka = communityOptions('kafkajs') as any;
    expect(kafka.producerHook).toBe(maskKafkaKey);
    expect(kafka.consumerHook).toBe(maskKafkaKey);
    const set: Record<string, string> = {};
    const span = { setAttribute: (k: string, v: string) => { set[k] = v; } };
    maskKafkaKey(span, { topic: 'orders', message: { key: 'ada@example.com', value: 'secret' } } as any);
    expect(set).toEqual({ 'messaging.kafka.message.key': '?' });
    const none: Record<string, string> = {};
    maskKafkaKey({ setAttribute: (k: string, v: string) => { none[k] = v; } }, { message: { value: 'x' } } as any);
    expect(none).toEqual({});
  });
});

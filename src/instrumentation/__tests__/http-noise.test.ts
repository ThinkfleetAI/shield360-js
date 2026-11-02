import { communityOptions, isHealthProbe, isOwnCall, shield360Host } from '../http-noise';

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
});

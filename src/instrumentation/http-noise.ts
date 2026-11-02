/**
 * SHIELD: request tracing without the noise.
 *
 * HTTP and undici tracing are on by default so an app's requests are traces
 * and its database calls and log lines sit inside them. Two kinds of request
 * are left out, because they would bury the app's own traffic:
 *   - health probes (Kubernetes, load balancers, uptime checks), which arrive
 *     every few seconds and say nothing about the app;
 *   - the SDK's own calls to Shield360 (guard reports, heartbeats, config),
 *     which are not the app's work.
 */

const HEALTH_PATHS = new Set(['/health', '/healthz', '/healthcheck', '/ready', '/readyz', '/live', '/livez', '/ping', '/status', '/metrics', '/api/health']);
const PROBE_AGENTS = /^(kube-probe|ELB-HealthChecker|GoogleHC|Consul Health Check|Amazon-Route53-Health-Check-Service|UptimeRobot)/i;

/** Whether an incoming request is a health probe: a probe's user agent, or a well-known health path. */
export function isHealthProbe(url: string | undefined, userAgent: string | string[] | undefined): boolean {
  const agent = Array.isArray(userAgent) ? userAgent[0] : userAgent;
  if (agent && PROBE_AGENTS.test(agent)) return true;
  const path = (url || '').split('?')[0].replace(/\/+$/, '') || '/';
  return HEALTH_PATHS.has(path.toLowerCase());
}

/** The Shield360 host the SDK reports to, from SHIELD360_URL, or ''. */
export function shield360Host(env: NodeJS.ProcessEnv = process.env): string {
  try {
    return env.SHIELD360_URL ? new URL(env.SHIELD360_URL).host.toLowerCase() : '';
  } catch {
    return '';
  }
}

/** Whether an outgoing request goes to Shield360 itself. */
export function isOwnCall(host: string | undefined, own: string = shield360Host()): boolean {
  return !!own && !!host && host.toLowerCase() === own;
}

/** The options each default community instrumentation is created with (health probes and own calls left out, values kept out of statements). */
export function communityOptions(name: string): Record<string, unknown> | undefined {
  if (name === 'http') {
    return {
      ignoreIncomingRequestHook: (req: { url?: string; headers?: Record<string, string | string[] | undefined> }) => {
        try {
          return isHealthProbe(req.url, req.headers?.['user-agent']);
        } catch {
          return false;
        }
      },
      ignoreOutgoingRequestHook: (options: { host?: string | null; hostname?: string | null; port?: string | number | null }) => {
        try {
          const name = options.hostname || options.host || '';
          const host = options.port && !String(name).includes(':') ? `${name}:${options.port}` : String(name);
          return isOwnCall(host) || isOwnCall(String(name));
        } catch {
          return false;
        }
      },
    };
  }
  if (name === 'undici') {
    return {
      ignoreRequestHook: (request: { origin?: string }) => {
        try {
          return !!request.origin && isOwnCall(new URL(request.origin).host);
        } catch {
          return false;
        }
      },
    };
  }
  // SHIELD: data minimisation — a cache command is recorded by name only: its
  // keys and values can hold personal data or secrets.
  if (name === 'redis' || name === 'ioredis') {
    return { dbStatementSerializer: (command: string) => String(command || '').toUpperCase() };
  }
  // Express: the route and its handler, not one span per middleware (expressInit, query, json…).
  if (name === 'express') return { ignoreLayersType: ['middleware'] };
  // One span per resolver is noise; field values are never recorded.
  if (name === 'graphql') return { ignoreTrivialResolveSpans: true, mergeItems: true, allowValues: false };
  // Query shapes only, values replaced (the instrumentation's default, kept explicit).
  if (name === 'mongodb') return { enhancedDatabaseReporting: false };
  // The SDK call is the span; the HTTP request under it would repeat it.
  if (name === 'aws-sdk') return { suppressInternalInstrumentation: true };
  return undefined;
}

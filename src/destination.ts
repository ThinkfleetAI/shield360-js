/**
 * Where telemetry goes when nobody said.
 *
 * The SDK has always exported over OTLP to `OTEL_EXPORTER_OTLP_ENDPOINT`, with
 * `OTEL_EXPORTER_OTLP_HEADERS` for whatever authorises it. That is the right
 * shape for a collector of your own. It is the wrong first experience for a
 * Shield360 customer, who already holds a URL and an API key for the platform
 * and reasonably expects them to be enough.
 *
 * They are, now: with no OTLP endpoint given, a Shield360 URL and API key
 * resolve to the platform's authenticated ingest route, with the key as the
 * bearer token. An explicit endpoint always wins, and an explicit
 * Authorization header is never overwritten.
 */

export const INGEST_PATH = '/api/ingest/otlp';

export interface DestinationInput {
  /** From the option or OTEL_EXPORTER_OTLP_ENDPOINT. */
  otlpEndpoint?: string;
  /** From the option or OTEL_EXPORTER_OTLP_HEADERS, already parsed. */
  otlpHeaders?: Record<string, unknown>;
  shield360Url?: string;
  shield360ApiKey?: string;
}

export interface Destination {
  otlpEndpoint?: string;
  otlpHeaders: Record<string, unknown>;
}

/**
 * `OTEL_EXPORTER_OTLP_HEADERS`, as OTel spells it: comma-separated
 * `name=value` pairs.
 *
 * Split on the first `=` only. A Shield360 API key ends in `=`, and splitting
 * on every one sent the key without its last character — every span refused
 * as an invalid key, and nothing to say why.
 */
export function parseOtlpHeaders(raw: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const pair of (raw ?? '').split(',')) {
    const at = pair.indexOf('=');
    if (at <= 0) continue;
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (name && value) headers[name] = value;
  }
  return headers;
}

function hasHeader(headers: Record<string, unknown>, name: string): boolean {
  const wanted = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === wanted);
}

export function resolveDestination(input: DestinationInput): Destination {
  const headers: Record<string, unknown> = { ...(input.otlpHeaders ?? {}) };

  const explicit = input.otlpEndpoint?.trim();
  if (explicit) {
    // `/v1/traces` is the most common thing to paste; the exporters add the
    // signal path themselves.
    return { otlpEndpoint: explicit.replace(/\/v1\/traces$/, ''), otlpHeaders: headers };
  }

  const url = input.shield360Url?.trim().replace(/\/+$/, '');
  const apiKey = input.shield360ApiKey?.trim();
  if (!url || !apiKey) {
    return { otlpEndpoint: undefined, otlpHeaders: headers };
  }

  if (!hasHeader(headers, 'Authorization')) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  return { otlpEndpoint: `${url}${INGEST_PATH}`, otlpHeaders: headers };
}

/**
 * Whether telemetry with nowhere to go may be printed to the console instead
 * (OpenTelemetry's development default). Not when a Shield360 URL or key was
 * given, since that means "send it to Shield360": without both, nothing is
 * sent and init() says why once. And not when stdout and stderr are captured
 * as application logs, because every printed record would come back as a new
 * log record (a loop seen in production, 2026-10-31).
 */
export function consoleFallbackAllowed(input: {
  otlpEndpoint?: string;
  shield360Url?: string;
  shield360ApiKey?: string;
  captureStdio?: boolean;
}): boolean {
  if (input.otlpEndpoint) return false;
  if (input.shield360Url?.trim() || input.shield360ApiKey?.trim()) return false;
  return !input.captureStdio;
}

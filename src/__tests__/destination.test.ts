import { INGEST_PATH, parseOtlpHeaders, resolveDestination } from '../destination';

/**
 * A Shield360 URL and API key are enough to send telemetry.
 *
 * Before this, they configured prompt management, the vault and evaluations,
 * and telemetry silently went to the console unless somebody also set the
 * OTLP variables — which every customer has to discover by finding nothing
 * in their dashboard.
 */
describe('resolveDestination', () => {
  it('points at the platform ingest route with the key as bearer', () => {
    const d = resolveDestination({
      shield360Url: 'https://app.shield360.ai',
      shield360ApiKey: 'k-1',
    });
    expect(d.otlpEndpoint).toBe(`https://app.shield360.ai${INGEST_PATH}`);
    expect(d.otlpHeaders).toEqual({ Authorization: 'Bearer k-1' });
  });

  it('tolerates a trailing slash on the URL', () => {
    const d = resolveDestination({ shield360Url: 'https://app.shield360.ai/', shield360ApiKey: 'k' });
    expect(d.otlpEndpoint).toBe(`https://app.shield360.ai${INGEST_PATH}`);
  });

  it('lets an explicit OTLP endpoint win, untouched', () => {
    const d = resolveDestination({
      otlpEndpoint: 'http://collector:4318',
      otlpHeaders: { 'X-Team': 'ai' },
      shield360Url: 'https://app.shield360.ai',
      shield360ApiKey: 'k',
    });
    expect(d.otlpEndpoint).toBe('http://collector:4318');
    // No bearer is added to somebody else's collector.
    expect(d.otlpHeaders).toEqual({ 'X-Team': 'ai' });
  });

  it('strips a pasted /v1/traces from an explicit endpoint, as before', () => {
    const d = resolveDestination({ otlpEndpoint: 'http://collector:4318/v1/traces' });
    expect(d.otlpEndpoint).toBe('http://collector:4318');
  });

  it('never overwrites an Authorization header the caller set', () => {
    const d = resolveDestination({
      otlpHeaders: { authorization: 'Basic abc' },
      shield360Url: 'https://app.shield360.ai',
      shield360ApiKey: 'k',
    });
    expect(d.otlpHeaders).toEqual({ authorization: 'Basic abc' });
  });

  it('resolves to nowhere with only one of the two, so the console fallback stays', () => {
    expect(resolveDestination({ shield360Url: 'https://app.shield360.ai' }).otlpEndpoint).toBeUndefined();
    expect(resolveDestination({ shield360ApiKey: 'k' }).otlpEndpoint).toBeUndefined();
    expect(resolveDestination({}).otlpEndpoint).toBeUndefined();
  });
});

/**
 * A Shield360 key ends in `=`. The old reader split each pair on every `=`
 * and sent the key one character short — every span refused as invalid, and
 * nothing in the SDK to say why.
 */
describe('parseOtlpHeaders', () => {
  it('keeps a value that itself contains "="', () => {
    expect(parseOtlpHeaders('Authorization=Bearer shield360-abc/DEF==')).toEqual({
      Authorization: 'Bearer shield360-abc/DEF==',
    });
  });

  it('reads several pairs and trims the spaces around them', () => {
    expect(parseOtlpHeaders(' Authorization=Bearer k= , x-team = ai ')).toEqual({
      Authorization: 'Bearer k=',
      'x-team': 'ai',
    });
  });

  it('ignores what is not a pair', () => {
    expect(parseOtlpHeaders('=nothing,justaname,,')).toEqual({});
    expect(parseOtlpHeaders(undefined)).toEqual({});
  });
});

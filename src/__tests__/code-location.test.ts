import { dirname, relative, resolve } from 'path';
import { existsSync } from 'fs';
import { pathToFileURL } from 'url';
import { InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import {
  ATTR_CODE_FILE_PATH,
  ATTR_CODE_FUNCTION_NAME,
  ATTR_CODE_LINE_NUMBER,
  CodeLocationSpanProcessor,
  PathNormaliser,
  anonymiseAbsolutePath,
  resolveCaptureCodeLocation,
} from '../otel/code-location';

const GEN_AI = { 'gen_ai.operation.name': 'chat' };
/** This file as the processor reports it: relative to the repository root, which is the monorepo here and the SDK's own root in its public mirror. */
function gitRoot(from: string): string {
  let dir = from;
  while (!existsSync(resolve(dir, '.git'))) {
    const parent = dirname(dir);
    if (parent === dir) return from;
    dir = parent;
  }
  return dir;
}
const THIS_FILE = relative(gitRoot(__dirname), __filename).split('\\').join('/');

/** Line number of the caller's line, read the same way V8 reports it. */
function callerLine(): number {
  const frame = new Error().stack!.split('\n')[2];
  return Number(/:(\d+):\d+\)?$/.exec(frame)![1]);
}

describe('CodeLocationSpanProcessor', () => {
  let exporter: InMemorySpanExporter;
  let processor: CodeLocationSpanProcessor;
  let provider: NodeTracerProvider;

  beforeEach(() => {
    exporter = new InMemorySpanExporter();
    processor = new CodeLocationSpanProcessor();
    provider = new NodeTracerProvider({
      spanProcessors: [processor, new SimpleSpanProcessor(exporter)],
    });
  });

  afterEach(async () => {
    await provider.shutdown();
  });

  function startChat(attributes: Record<string, string | number> = GEN_AI) {
    const [span, line] = [provider.getTracer('test').startSpan('chat', { attributes }), callerLine()];
    span.end();
    return { attrs: exporter.getFinishedSpans()[0].attributes, line };
  }

  it('adds the application call site to GenAI spans', () => {
    const { attrs, line } = startChat();
    expect(attrs[ATTR_CODE_FUNCTION_NAME]).toBe('startChat');
    expect(attrs[ATTR_CODE_FILE_PATH]).toBe(THIS_FILE);
    expect(attrs[ATTR_CODE_LINE_NUMBER]).toBe(line);
  });

  it('leaves non-GenAI spans alone', () => {
    const { attrs } = startChat({ 'db.system': 'postgresql' });
    expect(attrs[ATTR_CODE_FILE_PATH]).toBeUndefined();
    expect(attrs[ATTR_CODE_FUNCTION_NAME]).toBeUndefined();
    expect(attrs[ATTR_CODE_LINE_NUMBER]).toBeUndefined();
  });

  it('recognises instrumentations that set the operation after creation', () => {
    provider.getTracer('@shield360/instrumentation-langchain').startSpan('chain').end();
    const attrs = exporter.getFinishedSpans()[0].attributes;
    expect(attrs[ATTR_CODE_FILE_PATH]).toBe(THIS_FILE);
  });

  it('never overwrites an existing code.* attribute', () => {
    const { attrs } = startChat({ ...GEN_AI, [ATTR_CODE_FILE_PATH]: 'given.ts' });
    expect(attrs[ATTR_CODE_FILE_PATH]).toBe('given.ts');
    expect(attrs[ATTR_CODE_LINE_NUMBER]).toBeUndefined();
  });

  it('reuses cached frames for a repeated call site', () => {
    const lines: number[] = [];
    for (let i = 0; i < 3; i++) lines.push(startChat().attrs[ATTR_CODE_LINE_NUMBER] as number);
    const size = processor.cacheSize;
    startChat();
    expect(processor.cacheSize).toBe(size);
    expect(new Set(lines).size).toBe(1);
  });

  it('restores Error.stackTraceLimit', () => {
    const before = Error.stackTraceLimit;
    startChat();
    expect(Error.stackTraceLimit).toBe(before);
  });

  it('skips SDK, node_modules and node internal frames', () => {
    const sdkFile = resolve(__dirname, '../instrumentation/openai/wrapper.ts');
    const appFile = resolve(process.cwd(), 'app/billing.ts');
    const stack = [
      'Error',
      `    at CodeLocationSpanProcessor.onStart (${resolve(__dirname, '../otel/code-location.ts')}:1:1)`,
      `    at Span (${process.cwd()}/node_modules/@opentelemetry/sdk-trace/build/src/Span.js:75:29)`,
      `    at Completions.create [as create] (${sdkFile}:84:20)`,
      '    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)',
      `    at async Billing.summarise (${appFile}:42:7)`,
    ].join('\n');
    expect(processor.findApplicationFrame(stack)).toEqual({
      functionName: 'Billing.summarise',
      filePath: relative(gitRoot(process.cwd()), appFile).split('\\').join('/'),
      lineNumber: 42,
    });
  });

  it('omits the function name for anonymous frames', () => {
    const file = resolve(process.cwd(), 'app/main.ts');
    const frame = processor.findApplicationFrame(`Error\n    at Object.<anonymous> (${file}:3:9)`);
    expect(frame?.functionName).toBeUndefined();
    expect(frame?.lineNumber).toBe(3);
  });
});

describe('PathNormaliser', () => {
  it('strips an explicit code root first', () => {
    const n = new PathNormaliser({ codeRoot: '/srv/app', cwd: '/elsewhere', home: '/home/bob' });
    expect(n.normalise('/srv/app/src/x.ts')).toBe('src/x.ts');
  });

  it('strips the git root', () => {
    const n = new PathNormaliser({ cwd: '/elsewhere', home: '/nobody' });
    expect(n.normalise(__filename)).toBe(THIS_FILE);
  });

  it('strips the working directory when there is no git root', () => {
    const n = new PathNormaliser({ cwd: '/app', home: '/home/bob' });
    expect(n.normalise('/app/src/server.js')).toBe('src/server.js');
  });

  it('never emits the home directory', () => {
    const n = new PathNormaliser({ cwd: '/srv', home: '/home/bob' });
    expect(n.normalise('/home/bob/proj/x.ts')).toBe('proj/x.ts');
    expect(n.normalise('/opt/lib/y.ts')).toBe('/opt/lib/y.ts');
  });

  it.each([
    ['/home/runner/work/api/api/src/x.ts', 'src/x.ts'],
    ['/github/workspace/src/x.ts', 'src/x.ts'],
    ['/builds/acme/api/src/x.ts', 'src/x.ts'],
    ['/Users/alice/dev/api/x.ts', 'dev/api/x.ts'],
    ['/home/alice/dev/api/x.ts', 'dev/api/x.ts'],
    ['C:/Users/alice/dev/api/x.ts', 'dev/api/x.ts'],
    ['/root/api/x.ts', 'api/x.ts'],
    ['/srv/app/x.ts', '/srv/app/x.ts'],
  ])('drops a home or CI workspace prefix from %s', (input, expected) => {
    expect(anonymiseAbsolutePath(input)).toBe(expected);
    const n = new PathNormaliser({ cwd: '/elsewhere', home: '/home/app' });
    expect(n.normalise(input)).toBe(expected);
  });

  it('converts file:// URLs and drops query and hash', () => {
    const n = new PathNormaliser({ cwd: '/app', home: '/home/bob' });
    expect(n.normalise('file:///app/src/esm.mjs?v=2#top')).toBe('src/esm.mjs');
    expect(n.normalise(pathToFileURL(__filename).href)).toBe(THIS_FILE);
  });

  it('reads SHIELD360_CODE_ROOT', () => {
    const saved = process.env.SHIELD360_CODE_ROOT;
    process.env.SHIELD360_CODE_ROOT = '/srv/app';
    try {
      expect(new PathNormaliser({ cwd: '/x', home: '/y' }).normalise('/srv/app/a.ts')).toBe('a.ts');
    } finally {
      if (saved === undefined) delete process.env.SHIELD360_CODE_ROOT;
      else process.env.SHIELD360_CODE_ROOT = saved;
    }
  });
});

describe('resolveCaptureCodeLocation', () => {
  const saved = process.env.SHIELD360_CAPTURE_CODE_LOCATION;
  afterEach(() => {
    if (saved === undefined) delete process.env.SHIELD360_CAPTURE_CODE_LOCATION;
    else process.env.SHIELD360_CAPTURE_CODE_LOCATION = saved;
  });

  it('is on by default', () => {
    delete process.env.SHIELD360_CAPTURE_CODE_LOCATION;
    expect(resolveCaptureCodeLocation()).toBe(true);
  });

  it.each(['false', '0', 'NO', ' Off '])('is turned off by env %p', (value) => {
    process.env.SHIELD360_CAPTURE_CODE_LOCATION = value;
    expect(resolveCaptureCodeLocation()).toBe(false);
  });

  it('lets the init option win over env', () => {
    process.env.SHIELD360_CAPTURE_CODE_LOCATION = 'false';
    expect(resolveCaptureCodeLocation(true)).toBe(true);
    process.env.SHIELD360_CAPTURE_CODE_LOCATION = 'true';
    expect(resolveCaptureCodeLocation(false)).toBe(false);
  });
});

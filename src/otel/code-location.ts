/**
 * Code location on GenAI spans: code.function.name, code.file.path and
 * code.line.number of the application call site that started the span.
 *
 * A SpanProcessor's onStart runs synchronously inside tracer.startSpan, so
 * the caller's stack is still live there and one processor covers every
 * instrumentation. Only names, repo-relative paths and line numbers are
 * captured: never argument values, locals or source text.
 */
import { existsSync } from 'fs';
import { homedir } from 'os';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import type { Context } from '@opentelemetry/api';
import type { ReadableSpan, Span, SpanProcessor } from '@opentelemetry/sdk-trace-node';
import { INSTRUMENTATION_PREFIX } from '../constant';

export const ATTR_CODE_FUNCTION_NAME = 'code.function.name';
export const ATTR_CODE_FILE_PATH = 'code.file.path';
export const ATTR_CODE_LINE_NUMBER = 'code.line.number';
const GEN_AI_OPERATION = 'gen_ai.operation.name';

// These instrumentations set gen_ai.operation.name after span creation, so
// their spans are recognised by instrumentation scope instead.
const LATE_OPERATION_SCOPES = new Set(
  ['langchain', 'mcp', 'browser-use'].map((n) => `${INSTRUMENTATION_PREFIX}/instrumentation-${n}`)
);

const MAX_CACHE_ENTRIES = 4096;
const STACK_LIMIT = 64;
const FALSY = new Set(['false', '0', 'no', 'off']);

// The SDK's own compiled or source directory (dist/ or src/). Its tests are
// application code for this purpose.
const SDK_DIR = toPosix(resolve(__dirname, '..'));

export interface CodeLocationOptions {
  codeRoot?: string;
  cwd?: string;
  home?: string;
}

interface Frame {
  functionName?: string;
  filePath: string;
  lineNumber: number;
}

/** captureCodeLocation option wins; otherwise SHIELD360_CAPTURE_CODE_LOCATION; default on. */
export function resolveCaptureCodeLocation(option?: boolean): boolean {
  if (option !== undefined) return option;
  const env = process.env.SHIELD360_CAPTURE_CODE_LOCATION;
  return !(env && FALSY.has(env.trim().toLowerCase()));
}

function toPosix(p: string): string {
  return p.replace(/\\/g, '/');
}

function stripPrefix(path: string, root: string | undefined): string | undefined {
  if (!root) return undefined;
  const r = toPosix(root).replace(/\/+$/, '');
  if (r && path.startsWith(r + '/')) return path.slice(r.length + 1);
  return undefined;
}

/** CI workspace and home directory prefixes, CI first (a runner's workspace sits under its home). */
const BUILD_HOST_PREFIXES: RegExp[] = [
  /^\/home\/runner\/work\/[^/]+\/[^/]+\//, // GitHub Actions
  /^\/github\/workspace\//, // GitHub container actions
  /^\/home\/vsts\/work\/[^/]+\/s\//, // Azure Pipelines
  /^\/builds\/[^/]+\/[^/]+\//, // GitLab CI
  /^\/var\/lib\/buildkite-agent\/builds\/[^/]+\/[^/]+\/[^/]+\//, // Buildkite
  /^\/(?:var\/lib\/jenkins|var\/jenkins_home)\/workspace\/[^/]+\//, // Jenkins
  /^\/opt\/atlassian\/pipelines\/agent\/build\//, // Bitbucket Pipelines
  /^\/codebuild\/output\/src[^/]*\/src\//, // AWS CodeBuild
  /^\/home\/[^/]+\//,
  /^\/Users\/[^/]+\//,
  /^[A-Za-z]:\/Users\/[^/]+\//,
  /^\/root\//,
];

/**
 * Drops the first home directory or CI workspace prefix of an absolute path:
 * the last resort for a path under no code root, repository, working directory
 * or the current user's home. Other absolute paths (/srv/app/...) are kept.
 */
export function anonymiseAbsolutePath(path: string): string {
  for (const re of BUILD_HOST_PREFIXES) {
    const m = re.exec(path);
    if (m) return path.slice(m[0].length);
  }
  return path;
}

export class PathNormaliser {
  private readonly codeRoot?: string;
  private readonly cwd: string;
  private readonly home: string;
  private readonly gitDirs = new Map<string, boolean>();

  constructor(options: CodeLocationOptions = {}) {
    const codeRoot = options.codeRoot ?? process.env.SHIELD360_CODE_ROOT;
    this.codeRoot = codeRoot ? toPosix(resolve(codeRoot)) : undefined;
    this.cwd = toPosix(options.cwd ?? process.cwd());
    this.home = toPosix(options.home ?? homedir());
  }

  /** Repo-relative path for a stack-frame file (path or file:// URL). */
  normalise(file: string): string {
    let path = file;
    if (path.startsWith('file://')) {
      path = fileURLToPath(path.replace(/[?#].*$/, ''));
    }
    path = toPosix(path);
    const relative =
      stripPrefix(path, this.codeRoot) ??
      stripPrefix(path, this.gitRoot(path)) ??
      stripPrefix(path, this.cwd) ??
      stripPrefix(path, this.home) ??
      anonymiseAbsolutePath(path);
    return relative.replace(/^\.\//, '');
  }

  /** Nearest ancestor containing .git; each directory is probed at most once. */
  private gitRoot(path: string): string | undefined {
    let dir = dirname(path);
    for (;;) {
      let hasGit = this.gitDirs.get(dir);
      if (hasGit === undefined) {
        hasGit = existsSync(join(dir, '.git'));
        if (this.gitDirs.size < MAX_CACHE_ENTRIES) this.gitDirs.set(dir, hasGit);
      }
      if (hasGit) return toPosix(dir);
      const parent = dirname(dir);
      if (parent === dir) return undefined;
      dir = parent;
    }
  }
}

const FRAME_RE = /^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/;

function isApplicationFile(file: string): boolean {
  if (file.startsWith('node:') || file.startsWith('internal/') || file.startsWith('<')) return false;
  if (!(file.startsWith('/') || file.startsWith('file://') || /^[A-Za-z]:[\\/]/.test(file))) {
    return false;
  }
  const posix = toPosix(file);
  if (posix.includes('/node_modules/')) return false;
  if (posix.startsWith(SDK_DIR + '/') && !posix.includes('/__tests__/')) return false;
  return true;
}

function cleanFunctionName(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const name = raw
    .replace(/^async /, '')
    .replace(/^new /, '')
    .replace(/ \[as [^\]]+\]$/, '')
    .trim();
  if (!name || name.includes('<anonymous>')) return undefined;
  return name;
}

export class CodeLocationSpanProcessor implements SpanProcessor {
  private readonly normaliser: PathNormaliser;
  // Raw frame line -> parsed application frame, or null when not one.
  private readonly cache = new Map<string, Frame | null>();

  constructor(options: CodeLocationOptions = {}) {
    this.normaliser = new PathNormaliser(options);
  }

  onStart(span: Span, _parentContext: Context): void {
    try {
      if (!isGenAISpan(span)) return;
      const attrs = span.attributes;
      if (
        attrs[ATTR_CODE_FUNCTION_NAME] !== undefined ||
        attrs[ATTR_CODE_FILE_PATH] !== undefined ||
        attrs[ATTR_CODE_LINE_NUMBER] !== undefined
      ) {
        return;
      }
      const frame = this.findApplicationFrame(captureStack());
      if (!frame) return;
      if (frame.functionName) span.setAttribute(ATTR_CODE_FUNCTION_NAME, frame.functionName);
      span.setAttribute(ATTR_CODE_FILE_PATH, frame.filePath);
      span.setAttribute(ATTR_CODE_LINE_NUMBER, frame.lineNumber);
    } catch {
      // Never break span creation.
    }
  }

  /** Visible for tests: number of cached frame lines. */
  get cacheSize(): number {
    return this.cache.size;
  }

  /** First application frame in a V8 stack string. */
  findApplicationFrame(stack: string | undefined): Frame | undefined {
    if (!stack) return undefined;
    const lines = stack.split('\n');
    for (let i = 1; i < lines.length; i++) {
      const frame = this.parseLine(lines[i]);
      if (frame) return frame;
    }
    return undefined;
  }

  private parseLine(line: string): Frame | null {
    const cached = this.cache.get(line);
    if (cached !== undefined) return cached;
    let frame: Frame | null = null;
    const m = FRAME_RE.exec(line);
    if (m && !m[2].includes('(') && isApplicationFile(m[2])) {
      frame = {
        functionName: cleanFunctionName(m[1]),
        filePath: this.normaliser.normalise(m[2]),
        lineNumber: Number(m[3]),
      };
    }
    if (this.cache.size < MAX_CACHE_ENTRIES) this.cache.set(line, frame);
    return frame;
  }

  onEnd(_span: ReadableSpan): void {}

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

function isGenAISpan(span: Span): boolean {
  if (span.attributes[GEN_AI_OPERATION] !== undefined) return true;
  const scope = span.instrumentationScope?.name;
  return scope !== undefined && LATE_OPERATION_SCOPES.has(scope);
}

function captureStack(): string | undefined {
  const previous = Error.stackTraceLimit;
  try {
    Error.stackTraceLimit = STACK_LIMIT;
    return new Error().stack;
  } finally {
    Error.stackTraceLimit = previous;
  }
}

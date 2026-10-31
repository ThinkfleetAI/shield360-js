/**
 * Build and VCS resource attributes (service.version, vcs.*), resolved once
 * at init. Per attribute, the first valid value wins from: explicit config
 * (init option, SHIELD360_* env — SHIELD360_SERVICE_VERSION, then its alias
 * SHIELD360_RELEASE, for service.version), OTel env (OTEL_SERVICE_VERSION,
 * OTEL_RESOURCE_ATTRIBUTES), then CI/platform env. CI values come from a
 * single provider and are never mixed across providers.
 * Values are never logged.
 */

export const ATTR_SERVICE_VERSION = 'service.version';
export const ATTR_VCS_REVISION = 'vcs.ref.head.revision';
export const ATTR_VCS_REPOSITORY_URL = 'vcs.repository.url.full';
export const ATTR_VCS_REF_NAME = 'vcs.ref.head.name';

type Env = Record<string, string | undefined>;
type Sanitiser = (value: string | undefined) => string | undefined;

interface Candidates {
  version?: string;
  revision?: string;
  repo?: string;
  ref?: string;
}

const MAX_TEXT = 256;
const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

export function sanitiseRevision(value: string | undefined): string | undefined {
  const v = value?.trim();
  return v && /^[0-9a-fA-F]{7,64}$/.test(v) ? v.toLowerCase() : undefined;
}

export function sanitiseText(value: string | undefined): string | undefined {
  // eslint-disable-next-line no-control-regex
  const v = value?.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').trim().slice(0, MAX_TEXT);
  return v || undefined;
}

/** Normalise to https://host/owner/repo (http stays http), with credentials removed. */
export function sanitiseRepositoryUrl(value: string | undefined): string | undefined {
  const v = value?.trim();
  if (!v) return undefined;
  let scheme = 'https';
  let hostname: string;
  let port = '';
  let path: string;
  const scp = /^[^@/\s]+@([^:/\s]+):(?!\/)([^?#]+)/.exec(v);
  if (scp) {
    [, hostname, path] = scp;
  } else {
    let url: URL;
    try {
      url = new URL(v);
    } catch {
      return undefined;
    }
    const protocol = url.protocol.slice(0, -1);
    if (!['https', 'http', 'ssh', 'git'].includes(protocol)) return undefined;
    if (protocol === 'http') scheme = 'http';
    // The port is kept for web URLs and dropped for ssh/git transports.
    if (protocol === 'https' || protocol === 'http') port = url.port;
    hostname = url.hostname;
    path = url.pathname;
  }
  if (!HOST_RE.test(hostname)) return undefined;
  path = path.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '').replace(/\/+$/, '');
  if (!path) return undefined;
  return `${scheme}://${hostname.toLowerCase()}${port ? `:${port}` : ''}/${path}`;
}

function strip(prefix: string, value: string | undefined): string | undefined {
  return value?.startsWith(prefix) ? value.slice(prefix.length) : value;
}

const VERCEL_HOSTS: Record<string, string> = {
  github: 'github.com',
  gitlab: 'gitlab.com',
  bitbucket: 'bitbucket.org',
};

/** CI providers in priority order; repo and ref come only from the chosen one. */
const CI_PROVIDERS: Array<(env: Env) => Candidates> = [
  (e) => ({
    revision: e.GITHUB_SHA,
    repo: e.GITHUB_REPOSITORY
      ? `${e.GITHUB_SERVER_URL || 'https://github.com'}/${e.GITHUB_REPOSITORY}`
      : undefined,
    ref: e.GITHUB_HEAD_REF || e.GITHUB_REF_NAME,
  }),
  (e) => ({ revision: e.CI_COMMIT_SHA, repo: e.CI_PROJECT_URL, ref: e.CI_COMMIT_REF_NAME }),
  (e) => {
    const host = VERCEL_HOSTS[(e.VERCEL_GIT_PROVIDER || '').toLowerCase()];
    const owner = e.VERCEL_GIT_REPO_OWNER;
    const slug = e.VERCEL_GIT_REPO_SLUG;
    return {
      revision: e.VERCEL_GIT_COMMIT_SHA,
      repo: host && owner && slug ? `https://${host}/${owner}/${slug}` : undefined,
      ref: e.VERCEL_GIT_COMMIT_REF,
    };
  },
  (e) => ({ revision: e.COMMIT_REF, repo: e.REPOSITORY_URL, ref: e.BRANCH }),
  (e) => ({ revision: e.RENDER_GIT_COMMIT, ref: e.RENDER_GIT_BRANCH }),
  (e) => ({
    revision: e.RAILWAY_GIT_COMMIT_SHA,
    repo:
      e.RAILWAY_GIT_REPO_OWNER && e.RAILWAY_GIT_REPO_NAME
        ? `https://github.com/${e.RAILWAY_GIT_REPO_OWNER}/${e.RAILWAY_GIT_REPO_NAME}`
        : undefined,
    ref: e.RAILWAY_GIT_BRANCH,
  }),
  (e) => ({ revision: e.HEROKU_SLUG_COMMIT || e.SOURCE_VERSION }),
  (e) => ({
    revision: e.CODEBUILD_RESOLVED_SOURCE_VERSION,
    repo: e.CODEBUILD_SOURCE_REPO_URL,
    ref: strip('refs/heads/', e.CODEBUILD_WEBHOOK_HEAD_REF),
  }),
  (e) => ({ revision: e.BUILDKITE_COMMIT, repo: e.BUILDKITE_REPO, ref: e.BUILDKITE_BRANCH }),
  (e) => ({ revision: e.CIRCLE_SHA1, repo: e.CIRCLE_REPOSITORY_URL, ref: e.CIRCLE_BRANCH }),
  (e) => ({
    revision: e.BITBUCKET_COMMIT,
    repo: e.BITBUCKET_GIT_HTTP_ORIGIN,
    ref: e.BITBUCKET_BRANCH,
  }),
  (e) => ({
    revision: e.BUILD_SOURCEVERSION,
    repo: e.BUILD_REPOSITORY_URI,
    ref: e.BUILD_SOURCEBRANCHNAME,
  }),
  (e) => ({ revision: e.GIT_COMMIT, repo: e.GIT_URL, ref: strip('origin/', e.GIT_BRANCH) }),
];

function ciCandidates(env: Env): Candidates {
  for (const provider of CI_PROVIDERS) {
    const c = provider(env);
    if (c.revision) return c;
  }
  return {};
}

export function parseOtelResourceAttributes(value: string | undefined): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const item of (value || '').split(',')) {
    const eq = item.indexOf('=');
    if (eq <= 0) continue;
    try {
      attrs[item.slice(0, eq).trim()] = decodeURIComponent(item.slice(eq + 1).trim());
    } catch {
      // Skip values that are not valid percent-encoding.
    }
  }
  return attrs;
}

function firstValid(sanitise: Sanitiser, ...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    const v = sanitise(value);
    if (v) return v;
  }
  return undefined;
}

export function resolveBuildAttributes(
  options: { serviceVersion?: string } = {},
  env: Env = process.env
): Record<string, string> {
  const ci = ciCandidates(env);
  const otel = parseOtelResourceAttributes(env.OTEL_RESOURCE_ATTRIBUTES);
  const resolved: Record<string, string | undefined> = {
    [ATTR_SERVICE_VERSION]: firstValid(
      sanitiseText,
      options.serviceVersion,
      env.SHIELD360_SERVICE_VERSION,
      env.SHIELD360_RELEASE,
      env.OTEL_SERVICE_VERSION,
      otel[ATTR_SERVICE_VERSION]
    ),
    [ATTR_VCS_REVISION]: firstValid(
      sanitiseRevision,
      env.SHIELD360_GIT_COMMIT,
      otel[ATTR_VCS_REVISION],
      ci.revision
    ),
    [ATTR_VCS_REPOSITORY_URL]: firstValid(
      sanitiseRepositoryUrl,
      env.SHIELD360_GIT_REPOSITORY_URL,
      otel[ATTR_VCS_REPOSITORY_URL],
      ci.repo
    ),
    [ATTR_VCS_REF_NAME]: firstValid(
      sanitiseText,
      env.SHIELD360_GIT_BRANCH,
      otel[ATTR_VCS_REF_NAME],
      ci.ref
    ),
  };
  const attrs: Record<string, string> = {};
  for (const [key, value] of Object.entries(resolved)) {
    if (value) attrs[key] = value;
  }
  return attrs;
}

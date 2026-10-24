import {
  ATTR_SERVICE_VERSION,
  ATTR_VCS_REF_NAME,
  ATTR_VCS_REPOSITORY_URL,
  ATTR_VCS_REVISION,
  parseOtelResourceAttributes,
  resolveBuildAttributes,
  sanitiseRepositoryUrl,
  sanitiseRevision,
  sanitiseText,
} from '../otel/build-info';

const SHA = 'ABCDEF1234567890abcdef1234567890abcdef12';
const sha = SHA.toLowerCase();

describe('resolveBuildAttributes', () => {
  it('returns nothing when nothing is configured', () => {
    expect(resolveBuildAttributes({}, {})).toEqual({});
  });

  it('prefers the init option, then SHIELD360_* env', () => {
    const env = {
      SHIELD360_SERVICE_VERSION: '2.0.0',
      SHIELD360_GIT_COMMIT: SHA,
      SHIELD360_GIT_REPOSITORY_URL: 'git@github.com:acme/api.git',
      SHIELD360_GIT_BRANCH: 'release',
      GITHUB_SHA: '1111111111111111111111111111111111111111',
      GITHUB_REPOSITORY: 'other/repo',
      GITHUB_REF_NAME: 'main',
      OTEL_SERVICE_VERSION: '9.9.9',
    };
    expect(resolveBuildAttributes({ serviceVersion: '3.1.0' }, env)).toEqual({
      [ATTR_SERVICE_VERSION]: '3.1.0',
      [ATTR_VCS_REVISION]: sha,
      [ATTR_VCS_REPOSITORY_URL]: 'https://github.com/acme/api',
      [ATTR_VCS_REF_NAME]: 'release',
    });
    expect(resolveBuildAttributes({}, env)[ATTR_SERVICE_VERSION]).toBe('2.0.0');
  });

  it('reads CI provider env and never takes service.version from CI', () => {
    expect(
      resolveBuildAttributes(
        {},
        {
          GITHUB_SHA: SHA,
          GITHUB_REPOSITORY: 'acme/api',
          GITHUB_HEAD_REF: 'feature/x',
          GITHUB_REF_NAME: '12/merge',
        }
      )
    ).toEqual({
      [ATTR_VCS_REVISION]: sha,
      [ATTR_VCS_REPOSITORY_URL]: 'https://github.com/acme/api',
      [ATTR_VCS_REF_NAME]: 'feature/x',
    });
  });

  it('never mixes providers', () => {
    const attrs = resolveBuildAttributes(
      {},
      {
        RENDER_GIT_COMMIT: SHA,
        RENDER_GIT_BRANCH: 'main',
        // Lower-priority provider with a repo URL must not leak in.
        GIT_COMMIT: '2222222',
        GIT_URL: 'https://github.com/acme/jenkins',
        GIT_BRANCH: 'origin/dev',
        // Higher-priority provider without a revision is skipped entirely.
        CI_PROJECT_URL: 'https://gitlab.com/acme/gitlab',
      }
    );
    expect(attrs).toEqual({ [ATTR_VCS_REVISION]: sha, [ATTR_VCS_REF_NAME]: 'main' });
  });

  it.each([
    [
      'Vercel',
      {
        VERCEL_GIT_COMMIT_SHA: SHA,
        VERCEL_GIT_PROVIDER: 'gitlab',
        VERCEL_GIT_REPO_OWNER: 'acme',
        VERCEL_GIT_REPO_SLUG: 'api',
        VERCEL_GIT_COMMIT_REF: 'main',
      },
      'https://gitlab.com/acme/api',
      'main',
    ],
    [
      'CodeBuild',
      {
        CODEBUILD_RESOLVED_SOURCE_VERSION: SHA,
        CODEBUILD_SOURCE_REPO_URL: 'https://github.com/acme/api.git',
        CODEBUILD_WEBHOOK_HEAD_REF: 'refs/heads/main',
      },
      'https://github.com/acme/api',
      'main',
    ],
    [
      'Jenkins',
      { GIT_COMMIT: SHA, GIT_URL: 'ssh://git@github.com:22/acme/api.git', GIT_BRANCH: 'origin/dev' },
      'https://github.com/acme/api',
      'dev',
    ],
  ])('maps %s variables', (_name, env, repo, ref) => {
    const attrs = resolveBuildAttributes({}, env as Record<string, string>);
    expect(attrs[ATTR_VCS_REVISION]).toBe(sha);
    expect(attrs[ATTR_VCS_REPOSITORY_URL]).toBe(repo);
    expect(attrs[ATTR_VCS_REF_NAME]).toBe(ref);
  });

  it('uses Heroku SOURCE_VERSION when HEROKU_SLUG_COMMIT is unset', () => {
    expect(resolveBuildAttributes({}, { SOURCE_VERSION: SHA })).toEqual({
      [ATTR_VCS_REVISION]: sha,
    });
  });

  it('lets explicit OTel env beat CI auto-detection, per attribute', () => {
    const env = {
      GITHUB_SHA: '1111111111111111111111111111111111111111',
      GITHUB_REPOSITORY: 'acme/ci',
      GITHUB_REF_NAME: 'ci-branch',
      OTEL_RESOURCE_ATTRIBUTES: `vcs.ref.head.revision=${SHA},vcs.ref.head.name=otel-branch`,
    };
    expect(resolveBuildAttributes({}, env)).toEqual({
      [ATTR_VCS_REVISION]: sha,
      [ATTR_VCS_REF_NAME]: 'otel-branch',
      // OTel set no repository, so the CI provider fills it.
      [ATTR_VCS_REPOSITORY_URL]: 'https://github.com/acme/ci',
    });
    // An invalid OTel revision falls through to CI.
    expect(
      resolveBuildAttributes({}, { GITHUB_SHA: SHA, OTEL_RESOURCE_ATTRIBUTES: 'vcs.ref.head.revision=HEAD' })[
        ATTR_VCS_REVISION
      ]
    ).toBe(sha);
  });

  it('uses OTel env when nothing explicit is set', () => {
    const env = {
      OTEL_SERVICE_VERSION: '1.2.3',
      OTEL_RESOURCE_ATTRIBUTES:
        'service.version=0.0.1,vcs.ref.head.revision=' +
        SHA +
        ',vcs.repository.url.full=https%3A%2F%2Fgithub.com%2Facme%2Fapi,vcs.ref.head.name=feat%2Fa',
    };
    expect(resolveBuildAttributes({}, env)).toEqual({
      [ATTR_SERVICE_VERSION]: '1.2.3',
      [ATTR_VCS_REVISION]: sha,
      [ATTR_VCS_REPOSITORY_URL]: 'https://github.com/acme/api',
      [ATTR_VCS_REF_NAME]: 'feat/a',
    });
    expect(resolveBuildAttributes({ serviceVersion: '5' }, env)[ATTR_SERVICE_VERSION]).toBe('5');
  });

  it('drops an invalid revision and falls through to the next source', () => {
    expect(
      resolveBuildAttributes({}, { SHIELD360_GIT_COMMIT: 'not-a-sha', CIRCLE_SHA1: SHA })[
        ATTR_VCS_REVISION
      ]
    ).toBe(sha);
    expect(resolveBuildAttributes({}, { SHIELD360_GIT_COMMIT: 'abc' })).toEqual({});
  });
});

describe('sanitisers', () => {
  it.each([
    ['https://x-access-token:ghp_abc@github.com/acme/api.git', 'https://github.com/acme/api'],
    ['git@github.com:acme/api.git', 'https://github.com/acme/api'],
    ['ssh://git@gitlab.example.com:2222/group/sub/repo.git/', 'https://gitlab.example.com/group/sub/repo'],
    ['git://github.com/acme/api', 'https://github.com/acme/api'],
    ['http://git.local:8080/acme/api/?q=1#x', 'http://git.local:8080/acme/api'],
    ['HTTPS://GitHub.com/acme/api/', 'https://github.com/acme/api'],
  ])('normalises repository URL %p', (input, expected) => {
    expect(sanitiseRepositoryUrl(input)).toBe(expected);
  });

  it.each(['/home/bob/repo', 'file:///repo', 'ftp://host/repo', 'not a url', 'https://github.com/', ''])(
    'drops repository URL %p',
    (input) => {
      expect(sanitiseRepositoryUrl(input)).toBeUndefined();
    }
  );

  it('validates revisions', () => {
    expect(sanitiseRevision(`  ${SHA} `)).toBe(sha);
    expect(sanitiseRevision('abc123')).toBeUndefined();
    expect(sanitiseRevision('zzzzzzzz')).toBeUndefined();
  });

  it('cleans text values', () => {
    expect(sanitiseText(' main\u0000\n ')).toBe('main');
    expect(sanitiseText('x'.repeat(300))).toHaveLength(256);
    expect(sanitiseText(' \t ')).toBeUndefined();
  });

  it('parses OTEL_RESOURCE_ATTRIBUTES', () => {
    expect(parseOtelResourceAttributes('a=1, b = x%2Cy ,bad,c=%E0%A4%A')).toEqual({ a: '1', b: 'x,y' });
  });
});

describe('Shield360.init resource', () => {
  const savedEnv = process.env;

  afterEach(() => {
    process.env = savedEnv;
    jest.resetModules();
  });

  it('carries the resolved build attributes', () => {
    process.env = {
      ...savedEnv,
      OTEL_TRACES_EXPORTER: 'none',
      SHIELD360_GIT_COMMIT: SHA,
      GITHUB_SHA: '',
      OTEL_RESOURCE_ATTRIBUTES: 'vcs.ref.head.name=main',
    };
    jest.isolateModules(() => {
      const Shield360 = require('../index').default;
      Shield360.init({
        serviceVersion: '4.0.0',
        captureCodeLocation: false,
        disableMetrics: true,
        disableEvents: true,
      });
      expect(Shield360.options.captureCodeLocation).toBe(false);
      expect(Shield360.resource.attributes).toMatchObject({
        [ATTR_SERVICE_VERSION]: '4.0.0',
        [ATTR_VCS_REVISION]: sha,
        [ATTR_VCS_REF_NAME]: 'main',
      });
    });
  });
});

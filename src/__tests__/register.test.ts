describe('shield360/register', () => {
  const originalEnv = process.env;
  const originalVersion = process.versions.node;
  let initMock: jest.Mock;

  beforeEach(() => {
    jest.resetModules();
    initMock = jest.fn();
    jest.doMock('../index', () => ({
      __esModule: true,
      default: { init: initMock },
    }));
    process.env = {
      ...originalEnv,
      OTEL_SERVICE_NAME: 'node-ai-app',
      OTEL_DEPLOYMENT_ENVIRONMENT: 'prod',
      OTEL_RESOURCE_ATTRIBUTES: 'service.workload.key=k8s:demo,team=ai',
      SHIELD360_DISABLED_INSTRUMENTORS: 'openai,anthropic',
      SHIELD360_ESM_HOOK: 'off',
    };
    delete (globalThis as any).__shield360_register_initialized__;
    delete (globalThis as any).__shield360_zero_code_started__;
    delete (globalThis as any).__shield360_zero_code_init_warned__;
  });

  afterEach(() => {
    process.env = originalEnv;
    Object.defineProperty(process.versions, 'node', {
      value: originalVersion,
      configurable: true,
    });
    delete (globalThis as any).__shield360_register_initialized__;
    delete (globalThis as any).__shield360_zero_code_started__;
    delete (globalThis as any).__shield360_zero_code_init_warned__;
    jest.dontMock('../index');
  });

  it('initializes once with controller environment values', async () => {
    await import('../register');
    await import('../register');

    expect(initMock).toHaveBeenCalledTimes(1);
    expect(initMock).toHaveBeenCalledWith({
      applicationName: 'node-ai-app',
      environment: 'prod',
      disabledInstrumentors: ['openai', 'anthropic'],
      customSpanAttributes: {
        'service.workload.key': 'k8s:demo',
        team: 'ai',
      },
    });
  });

  it('skips unsupported Node.js versions', async () => {
    Object.defineProperty(process.versions, 'node', {
      value: '16.20.2',
      configurable: true,
    });
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    await import('../register');

    expect(initMock).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('requires Node.js 18 or newer')
    );
    errorSpy.mockRestore();
  });

  it("does nothing in Node's module-hooks thread, where a --require preload runs again", async () => {
    const registerMock = jest.fn();
    jest.doMock('worker_threads', () => ({ ...jest.requireActual('worker_threads'), isInternalThread: true, isMainThread: false }));
    jest.doMock('module', () => ({ ...jest.requireActual('module'), register: registerMock }));
    process.env.SHIELD360_ESM_HOOK = 'on';
    try {
      await import('../register');
      expect(initMock).not.toHaveBeenCalled();
      expect(registerMock).not.toHaveBeenCalled();
    } finally {
      jest.dontMock('worker_threads');
      jest.dontMock('module');
    }
  });

  it('registers the ESM loader hook from the main thread only', async () => {
    const registerMock = jest.fn();
    jest.doMock('module', () => ({ ...jest.requireActual('module'), register: registerMock }));
    process.env.SHIELD360_ESM_HOOK = 'on';
    try {
      jest.doMock('worker_threads', () => ({ ...jest.requireActual('worker_threads'), isInternalThread: false, isMainThread: false }));
      await import('../register');
      expect(initMock).toHaveBeenCalledTimes(1);
      expect(registerMock).not.toHaveBeenCalled();

      jest.resetModules();
      delete (globalThis as any).__shield360_register_initialized__;
      jest.doMock('../index', () => ({ __esModule: true, default: { init: initMock } }));
      jest.doMock('module', () => ({ ...jest.requireActual('module'), register: registerMock }));
      jest.doMock('worker_threads', () => ({ ...jest.requireActual('worker_threads'), isInternalThread: false, isMainThread: true }));
      await import('../register');
      expect(registerMock).toHaveBeenCalledTimes(1);
      expect(registerMock).toHaveBeenCalledWith('@opentelemetry/instrumentation/hook.mjs', expect.stringMatching(/^file:/));
    } finally {
      jest.dontMock('worker_threads');
      jest.dontMock('module');
    }
  });

  it('marks the process started so a later init() in app code is a no-op', async () => {
    await import('../register');
    const { zeroCodeStarted } = await import('../zero-code');
    expect(zeroCodeStarted()).toBe(true);
  });

  it('fails open: an init failure prints one warning and does not throw', async () => {
    initMock.mockImplementation(() => {
      throw new Error('boom');
    });
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    await expect(import('../register')).resolves.toBeDefined();

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('the app runs without Shield360'));
    const { zeroCodeStarted } = await import('../zero-code');
    expect(zeroCodeStarted()).toBe(false);
    warnSpy.mockRestore();
  });
});

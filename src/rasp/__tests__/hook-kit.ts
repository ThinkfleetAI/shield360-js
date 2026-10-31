/**
 * The checks every RASP sink hook must pass, whoever wrote it. The hooks'
 * own tests cover what each sink detects; this kit covers how a hook sits
 * in the process: install once, restore exactly, keep the replaced
 * functions' shape, check a call once, fail open, stay quiet when RASP is
 * off, and live alongside another wrapper (OpenTelemetry tracing wraps the
 * same functions) in either order.
 *
 * Each hook supplies a harmless trigger: a call its detector flags under
 * the given inputs, safe to run when RASP only reports.
 */
import { runWithInputs, type RaspContext } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { RaspBlockedError, type AttackType, type RaspInput, type RaspMode } from '../types';

export type Target = { owner: object; key: string };

export type HookSpec = {
  name: string;
  install: () => boolean;
  uninstall: () => void;
  /** Properties the hook replaces. */
  replaced: Target[];
  /** Properties the hook adds (absent before install, removed by uninstall). */
  added?: Target[];
  /** The property the "wrapper on top" check wraps after install (default: the first replaced). */
  outer?: Target;
  /** A harmless call the hook flags under `inputs`. May return, throw or return a promise. */
  trigger: () => unknown;
  inputs: RaspInput[];
  context?: Partial<RaspContext>;
  /** The detector the trigger goes through, to make it fail. */
  detector: { module: object; name: string };
  attack: AttackType;
  /** Per-test setup and teardown the trigger needs (temp files, a server). */
  beforeEach?: () => unknown;
  afterEach?: () => unknown;
};

type Outcome = { blocked: boolean; error?: unknown };

export function describeHookContract(spec: HookSpec): void {
  describe(`${spec.name}: hook contract`, () => {
    const events: { attrs: Record<string, string> }[] = [];
    const setMode = (mode: RaspMode | 'disabled') => {
      if (mode === 'disabled') configureEngine({ enabled: false, applicationName: 'kit', env: {} });
      else configureEngine({ enabled: true, applicationName: 'kit', mode, env: {} });
      setEventSink({ add: (e) => events.push(e) });
    };
    const ours = () => events.filter((e) => e.attrs['shield360.rasp.attack'] === spec.attack);

    async function fire(): Promise<Outcome> {
      try {
        await runWithInputs(spec.inputs, spec.trigger, { inRequest: true, ...spec.context });
        return { blocked: false };
      } catch (error) {
        return { blocked: error instanceof RaspBlockedError, error };
      }
    }

    const snapshot = (targets: Target[]) => targets.map((t) => ({ ...t, descriptor: Object.getOwnPropertyDescriptor(t.owner, t.key) }));

    beforeEach(async () => {
      events.length = 0;
      setMode('block');
      await spec.beforeEach?.();
    });
    afterEach(async () => {
      spec.uninstall();
      jest.restoreAllMocks();
      setEventSink(undefined);
      configureEngine({ enabled: false, applicationName: 'default', env: {} });
      await spec.afterEach?.();
    });

    it('installs, and installing again changes nothing', () => {
      expect(spec.install()).toBe(true);
      const first = spec.replaced.map((t) => Reflect.get(t.owner, t.key));
      expect(spec.install()).toBe(true);
      expect(spec.replaced.map((t) => Reflect.get(t.owner, t.key))).toEqual(first);
    });

    it('keeps the name and length of what it replaces', () => {
      const before = snapshot(spec.replaced);
      spec.install();
      for (const { owner, key, descriptor } of before) {
        const now = Reflect.get(owner, key) as { name: string; length: number };
        expect(now).not.toBe(descriptor?.value);
        expect(now.name).toBe(descriptor?.value.name);
        expect(now.length).toBe(descriptor?.value.length);
      }
    });

    it('uninstall restores exactly, and twice is harmless', () => {
      const before = snapshot(spec.replaced);
      for (const t of spec.added ?? []) expect(Object.prototype.hasOwnProperty.call(t.owner, t.key)).toBe(false);
      spec.install();
      for (const t of spec.added ?? []) expect(Object.prototype.hasOwnProperty.call(t.owner, t.key)).toBe(true);
      spec.uninstall();
      spec.uninstall();
      for (const { owner, key, descriptor } of before) expect(Object.getOwnPropertyDescriptor(owner, key)).toEqual(descriptor);
      for (const t of spec.added ?? []) expect(Object.prototype.hasOwnProperty.call(t.owner, t.key)).toBe(false);
    });

    it('block: the trigger is refused and reported once', async () => {
      spec.install();
      const out = await fire();
      expect(out.blocked).toBe(true);
      expect(ours()).toHaveLength(1);
      expect(ours()[0].attrs['shield360.rasp.decision']).toBe('blocked');
    });

    it('monitor: the trigger goes through and is reported exactly once', async () => {
      setMode('monitor');
      spec.install();
      const out = await fire();
      expect(out.blocked).toBe(false);
      expect(ours()).toHaveLength(1);
      expect(ours()[0].attrs['shield360.rasp.decision']).toBe('monitored');
    });

    it('RASP off: nothing is checked or reported', async () => {
      setMode('disabled');
      const detector = jest.spyOn(spec.detector.module as Record<string, (...a: unknown[]) => unknown>, spec.detector.name);
      spec.install();
      const out = await fire();
      expect(out.blocked).toBe(false);
      expect(detector).not.toHaveBeenCalled();
      expect(events).toHaveLength(0);
    });

    it('fails open when the detector fails', async () => {
      jest.spyOn(spec.detector.module as Record<string, (...a: unknown[]) => unknown>, spec.detector.name).mockImplementation(() => {
        throw new Error('detector unavailable');
      });
      spec.install();
      const out = await fire();
      expect(out.blocked).toBe(false);
      expect(events).toHaveLength(0);
    });

    it('lives alongside a wrapper put on top of it', async () => {
      const target = spec.outer ?? spec.replaced[0];
      spec.install();
      const inner = Reflect.get(target.owner, target.key) as (...a: unknown[]) => unknown;
      const descriptor = Object.getOwnPropertyDescriptor(target.owner, target.key)!;
      // Shaped like a tracing wrapper: a plain function calling what it found.
      const outer = function (this: unknown, ...values: unknown[]) {
        return Reflect.apply(inner, this, values);
      };
      Object.defineProperty(target.owner, target.key, { ...descriptor, value: outer });
      try {
        expect((await fire()).blocked).toBe(true);
        spec.uninstall();
        // Uninstall must not tear the outer wrapper off, and what is left must not check.
        expect(Reflect.get(target.owner, target.key)).toBe(outer);
        events.length = 0;
        expect((await fire()).blocked).toBe(false);
        expect(events).toHaveLength(0);
      } finally {
        Object.defineProperty(target.owner, target.key, descriptor);
      }
    });
  });
}

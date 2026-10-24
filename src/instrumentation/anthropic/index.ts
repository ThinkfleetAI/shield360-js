import {
  InstrumentationBase,
  InstrumentationModuleDefinition,
  InstrumentationNodeModuleDefinition,
  isWrapped,
} from '@opentelemetry/instrumentation';
import { InstrumentationConfig } from '@opentelemetry/instrumentation';
import { INSTRUMENTATION_PREFIX } from '../../constant';
import AnthropicWrapper from './wrapper';

export interface AnthropicInstrumentationConfig extends InstrumentationConfig {}

/**
 * The two Messages resources the Anthropic SDK ships, and where each lives.
 *
 * `client.messages` is the stable API. `client.beta.messages` is a separate
 * class with its own prototype — not a subclass — and it is the one the SDK's
 * own tool runner (`client.beta.messages.toolRunner`) and every beta feature
 * call. Patching only the stable class meant an agent built on the tool
 * runner produced no spans and no cost at all, while looking instrumented.
 */
const MESSAGE_RESOURCES: { path: string[]; endpoint: string }[] = [
  { path: ['Messages'], endpoint: 'anthropic.resources.messages' },
  { path: ['Beta', 'Messages'], endpoint: 'anthropic.resources.beta.messages' },
];

export default class Shield360AnthropicInstrumentation extends InstrumentationBase {
  constructor(config: AnthropicInstrumentationConfig = {}) {
    super(`${INSTRUMENTATION_PREFIX}/instrumentation-anthropic`, '1.0.0', config);
  }

  protected init(): void | InstrumentationModuleDefinition | InstrumentationModuleDefinition[] {
    const module = new InstrumentationNodeModuleDefinition(
      '@anthropic-ai/sdk',
      ['>= 0.21.0'],
      (moduleExports) => {
        this._patch(moduleExports);
        return moduleExports;
      },
      (moduleExports) => {
        if (moduleExports !== undefined) {
          this._unpatch(moduleExports);
        }
      }
    );
    return [module];
  }

  public manualPatch(anthropic: any): void {
    this._patch(anthropic);
  }

  /**
   * The prototype carrying `create` for one resource, or undefined when this
   * SDK version does not have it. `Beta` arrived after the minimum supported
   * version, so its absence is not an error.
   */
  private static _resourcePrototype(AnthropicClass: any, path: string[]): any {
    let target = AnthropicClass;
    for (const key of path) {
      target = target?.[key];
      if (!target) return undefined;
    }
    return typeof target.prototype?.create === 'function' ? target.prototype : undefined;
  }

  protected _patch(moduleExports: any) {
    try {
      const AnthropicClass = (moduleExports as any).Anthropic ?? moduleExports;
      for (const { path, endpoint } of MESSAGE_RESOURCES) {
        const proto = Shield360AnthropicInstrumentation._resourcePrototype(AnthropicClass, path);
        if (!proto) continue;
        if (isWrapped(proto.create)) {
          this._unwrap(proto, 'create');
        }
        this._wrap(proto, 'create', AnthropicWrapper._patchMessageCreate(this.tracer, endpoint));
      }
    } catch (e) {
      console.error('Error in _patch method:', e);
    }
  }

  protected _unpatch(moduleExports: any) {
    const AnthropicClass = (moduleExports as any).Anthropic ?? moduleExports;
    for (const { path } of MESSAGE_RESOURCES) {
      const proto = Shield360AnthropicInstrumentation._resourcePrototype(AnthropicClass, path);
      if (proto && isWrapped(proto.create)) {
        this._unwrap(proto, 'create');
      }
    }
  }
}

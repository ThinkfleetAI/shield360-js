import Shield360Helper from '../helpers';
import pricing from '../pricing.json';

/**
 * The bundled price table knows the current Claude models.
 *
 * `getChatModelCost` returns 0 for a model it has no entry for, and 0 is
 * indistinguishable from "this call was free". When the table fell behind the
 * model line-up, every request to the newest — and dearest — models was
 * reported as costing nothing, which is the one direction a cost tracker must
 * never be wrong in. These pin the entries and the arithmetic against the
 * published per-million prices.
 */

const MILLION = 1_000_000;

/** Cost of a million input and a million output tokens, in dollars. */
function perMillion(model: string): { input: number; output: number } {
  return {
    input: Shield360Helper.getChatModelCost(model, pricing, MILLION, 0),
    output: Shield360Helper.getChatModelCost(model, pricing, 0, MILLION),
  };
}

describe('pricing for the Claude 5 family', () => {
  it.each([
    ['claude-opus-5', 5, 25],
    ['claude-opus-5-5', 4, 20],
    ['claude-opus-4-8', 5, 25],
    ['claude-sonnet-5', 2, 10],
    ['claude-sonnet-5-5', 2, 10],
    ['gpt-5.6-sol', 4, 20],
    ['gpt-5.6-terra', 2, 12],
    ['claude-fable-5', 10, 50],
    ['claude-fable-5-1', 10, 50],
    ['claude-haiku-4-5-20251001', 1, 5],
  ])('%s costs $%d in and $%d out per million tokens', (model, input, output) => {
    expect(perMillion(model)).toEqual({ input, output });
  });

  it('prices a cache read at a tenth of input, and a quarter of that on Fable 5.1', () => {
    const opusRead = Shield360Helper.getChatModelCost('claude-opus-5', pricing, 0, 0, MILLION);
    expect(opusRead).toBeCloseTo(0.5, 6);

    const fableRead = Shield360Helper.getChatModelCost('claude-fable-5-1', pricing, 0, 0, MILLION);
    expect(fableRead).toBeCloseTo(0.25, 6);
  });

  it('prices a cache write at one and a quarter times input', () => {
    const write = Shield360Helper.getChatModelCost('claude-sonnet-5', pricing, 0, 0, 0, MILLION);
    expect(write).toBeCloseTo(2.5, 6);
  });

  it('is not silently free for a model the table does know', () => {
    // The failure mode this file exists for: an unknown model costs 0.
    expect(Shield360Helper.getChatModelCost('claude-opus-5', pricing, 1000, 1000)).toBeGreaterThan(0);
  });
});

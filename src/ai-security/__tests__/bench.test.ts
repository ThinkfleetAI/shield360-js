/**
 * Overhead of the AI security checks, in process. Printed, not asserted
 * tightly: CI machines vary. The bound only catches a pathological change
 * (an order of magnitude).
 */
import { performance } from 'perf_hooks';
import { resetAiSecurity, scanContext, scanOutput, checkPrompt, streamScanner, checkRetrieval } from '../index';
import { scanToolDescription } from '../mcp';

function time(label: string, n: number, fn: () => void): number {
  for (let i = 0; i < Math.min(20, n); i++) fn();
  const samples: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    fn();
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  const p50 = samples[Math.floor(n * 0.5)];
  const p95 = samples[Math.floor(n * 0.95)];
  console.log(`${label}: p50 ${p50.toFixed(3)} ms, p95 ${p95.toFixed(3)} ms (n=${n})`);
  return p95;
}

const para = 'Our refund policy allows returns within 30 days of delivery when the item is unused and in its original packaging. ';

describe('overhead', () => {
  beforeAll(() => resetAiSecurity());

  it('stays within budget', () => {
    const k2 = para.repeat(18); // ~2 KB
    const k20 = para.repeat(180); // ~20 KB
    const results = [
      time('scanContext 2 KB tool result', 300, () => scanContext(k2, { source: 'tool_result' })),
      time('scanContext 20 KB document', 100, () => scanContext(k20, { source: 'document' })),
      time('checkPrompt 4 turns', 300, () => checkPrompt(['hi', 'what is the refund policy?', 'and for sale items?', 'thanks, one more question about shipping'])),
      time('scanOutput 2 KB answer (with system prompt)', 300, () => scanOutput(k2, { systemPrompt: para.repeat(5) })),
      time('stream 2 KB in 40-char chunks', 200, () => {
        const s = streamScanner();
        for (let i = 0; i < k2.length; i += 40) s.push(k2.slice(i, i + 40));
        s.end();
      }),
      time('checkRetrieval 8 chunks', 300, () => checkRetrieval(Array.from({ length: 8 }, (_v, i) => ({ text: para.repeat(4), id: `c${i}`, metadata: {} })), { query: 'refund' })),
      time('scanToolDescription', 300, () => scanToolDescription('Search the knowledge base for articles matching a query. Returns titles and links.')),
    ];
    for (const p95 of results) expect(p95).toBeLessThan(250);
  });
});

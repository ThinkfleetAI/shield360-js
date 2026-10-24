/**
 * Guard Pipeline -- composes multiple guards into an ordered evaluation chain.
 *
 * Must stay in sync with: sdk/python/src/shield360/guard/_pipeline.py
 */

import { SpanStatusCode, trace } from '@opentelemetry/api';
import {
  Guard,
  GuardAction,
  GuardPhase,
  GuardResult,
  PipelineResult,
  ACTION_SEVERITY,
  GuardConfigError,
  makeGuardResult,
} from './base';
import { reportGuardDecision } from './report';

export interface PipelineOptions {
  guards?: Guard[];
  failOpen?: boolean;
}

export class Pipeline {
  private readonly _guards: Guard[];
  private readonly _failOpen: boolean;

  constructor(opts: PipelineOptions = {}) {
    this._guards = [...(opts.guards || [])];
    this._failOpen = opts.failOpen ?? true;
  }

  get guards(): Guard[] {
    return [...this._guards];
  }

  /** Whether any guard runs in `phase`. */
  hasPhase(phase: GuardPhase): boolean {
    return this._guards.some((g) => g.supportsPhase(phase));
  }

  /**
   * The most characters every guard in the pipeline reads: the smallest
   * positive maxScanLength, or 0 when every guard reads everything. Text
   * past it is scanned in part by at least one guard; Shield Protect's
   * enforced mode refuses such text instead.
   */
  scanBound(): number {
    const bounds = this._guards.map((g) => g.maxScanLength).filter((n) => n > 0);
    return bounds.length ? Math.min(...bounds) : 0;
  }

  evaluate(text: string, phase: string = 'preflight'): PipelineResult {
    const validPhases = Object.values(GuardPhase) as string[];
    if (!validPhases.includes(phase)) {
      throw new GuardConfigError(
        `Invalid phase '${phase}'. Must be one of: ${validPhases.join(', ')}`,
      );
    }
    const guardPhase = phase as GuardPhase;
    const results: GuardResult[] = [];
    let currentText = text;
    let worstAction = GuardAction.ALLOW;

    for (const guard of this._guards) {
      if (!guard.supportsPhase(guardPhase)) {
        continue;
      }

      let result: GuardResult;
      try {
        result = guard.run(currentText, guardPhase);
      } catch (e) {
        if (this._failOpen) {
          console.warn(
            `Guard '${guard.name}' raised during ${phase} evaluation; fail-open -> allow`,
            e,
          );
          result = makeGuardResult({ guardName: guard.name });
        } else {
          throw e;
        }
      }

      results.push(result);
      Pipeline._emitOtel(result, phase);

      if (ACTION_SEVERITY[result.action] > ACTION_SEVERITY[worstAction]) {
        worstAction = result.action;
      }

      if (result.action === GuardAction.REDACT && result.transformedText !== null) {
        currentText = result.transformedText;
      }

      if (result.action === GuardAction.DENY) {
        break;
      }
    }

    const transformed = currentText !== text ? currentText : null;
    return new PipelineResult(worstAction, results, transformed);
  }

  /**
   * Apply every redacting guard to `text` and return the result.
   *
   * Used after `evaluate` has already decided a call is redacted, to rewrite
   * each message on its own. Emits nothing: the decision, and its telemetry,
   * came from `evaluate`.
   */
  redact(text: string, phase: string = 'preflight'): string {
    const guardPhase = phase as GuardPhase;
    let current = text;
    for (const guard of this._guards) {
      if (!guard.supportsPhase(guardPhase)) continue;
      let result: GuardResult;
      try {
        result = guard.run(current, guardPhase);
      } catch (e) {
        if (this._failOpen) continue;
        throw e;
      }
      if (result.action === GuardAction.REDACT && result.transformedText !== null) {
        current = result.transformedText;
      }
    }
    return current;
  }

  private static _emitOtel(result: GuardResult, phase: string): void {
    reportGuardDecision(result.guardName, result.action, result.classification, phase, result.findings);

    try {
      const Metrics = require('../otel/metrics').default;
      if (Metrics?.guardRequests) {
        Metrics.guardRequests.add(1, {
          'guard.name': result.guardName,
          'guard.action': result.action,
          'guard.score': result.score,
          'guard.classification': result.classification,
          'guard.phase': phase,
        });
      }
    } catch {
      // metrics not initialized yet
    }

    try {
      const attributes = {
        'guard.name': result.guardName,
        'guard.phase': phase,
        'guard.action': result.action,
        'guard.score': result.score,
        'guard.classification': result.classification,
        'guard.explanation': result.explanation,
        'guard.latency_ms': result.latencyMs,
      };
      const span = trace.getActiveSpan();
      if (span && span.isRecording()) {
        span.addEvent('guard.evaluation', attributes);
      } else if (result.action !== GuardAction.ALLOW) {
        // Guards run before the LLM call's span starts, and a denied call
        // never starts one. Record what the guard did on a span of its own so
        // a block or redaction is never invisible. Only the kind of data found
        // is recorded, never the text.
        const own = trace.getTracer('shield360.guard').startSpan('shield360.guard', { attributes });
        own.addEvent('guard.evaluation', attributes);
        if (result.action === GuardAction.DENY) {
          own.setStatus({ code: SpanStatusCode.ERROR, message: 'denied by guard' });
        }
        own.end();
      }
    } catch {
      // tracing not initialized
    }
  }
}

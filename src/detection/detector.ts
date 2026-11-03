/**
 * Detector: runs the active rules against one inspection target. Never throws.
 */
import type { CreateDetector, DetectionRule, Finding, InspectionContext, InspectionTarget, RuleContext } from '../contracts.js';
import { clamp, oneLine, toolNameOf } from './helpers/text.js';
import { BUILTIN_RULES } from './rules/index.js';

export const RULE_ERROR_ID = 'toolguard.rule-error';

export const createDetector: CreateDetector = (opts) => {
  const disabled = new Set(opts.disabledRules ?? []);
  const rules: readonly DetectionRule[] = Object.freeze(
    [...BUILTIN_RULES, ...(opts.extraRules ?? [])].filter((r) => !disabled.has(r.id)),
  );

  const inspect = (target: InspectionTarget, ctx: InspectionContext): Finding[] => {
    let toolName: string | undefined;
    try {
      toolName = toolNameOf(target);
    } catch {
      toolName = undefined;
    }
    const ruleCtx: RuleContext = { ...ctx, pins: opts.pins };
    const out: Finding[] = [];
    for (const rule of rules) {
      try {
        if (!rule.appliesTo.includes(target.kind)) continue;
        const found = rule.detect(target, ruleCtx);
        if (!Array.isArray(found)) continue;
        for (const f of found) {
          if (!f || typeof f !== 'object') continue;
          const finding: Finding = { ...f };
          if (finding.evidence !== undefined) finding.evidence = clamp(String(finding.evidence));
          if (toolName !== undefined) finding.toolName = toolName;
          out.push(finding);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const finding: Finding = {
          ruleId: RULE_ERROR_ID,
          severity: 'low',
          message: clamp(`Detection rule "${rule.id}" failed: ${oneLine(msg)}`),
        };
        if (toolName !== undefined) finding.toolName = toolName;
        out.push(finding);
      }
    }
    return out;
  };

  return { rules, inspect };
};

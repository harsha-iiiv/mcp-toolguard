import {
  ACTION_ORDER,
  PROXY_RULE_IDS,
  SEVERITY_ORDER,
  type Action,
  type Decision,
  type Finding,
  type ToolguardPolicy,
  type InspectionTarget,
  type PolicyEngine,
  type Severity,
} from '../contracts.js';
import { compileGlobs, globToRegExp, matchesAny } from './glob.js';

interface CompiledArgRule {
  tool: RegExp;
  path: string;
  segments: string[];
  deny: RegExp[];
  allow: RegExp[];
  action: Action;
  reason?: string;
}

interface Contribution {
  action: Action;
  reason: string;
  /** Finding severity, or -1 for policy (non-finding) contributions. Used as a tie-breaker. */
  severity: number;
}

const actionRank = (a: Action): number => ACTION_ORDER.indexOf(a);
const severityRank = (s: Severity): number => SEVERITY_ORDER.indexOf(s);

function maxAction(a: Action, b: Action): Action {
  return actionRank(b) > actionRank(a) ? b : a;
}

function stringify(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (value === undefined) return undefined;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function resolvePath(args: Record<string, unknown>, segments: readonly string[]): { found: boolean; value: unknown } {
  let cur: unknown = args;
  for (const seg of segments) {
    if (typeof cur !== 'object' || cur === null || !Object.prototype.hasOwnProperty.call(cur, seg)) {
      return { found: false, value: undefined };
    }
    cur = (cur as Record<string, unknown>)[seg];
  }
  return { found: true, value: cur };
}

function toolNameOf(target: InspectionTarget): string {
  return target.kind === 'tool_definition' ? target.tool.name : target.toolName;
}

export function createPolicyEngine(policy: ToolguardPolicy): PolicyEngine {
  const allowGlobs = compileGlobs(policy.tools.allow);
  const denyGlobs = compileGlobs(policy.tools.deny);
  const disabled = new Set(
    Object.entries(policy.rules)
      .filter(([, o]) => o.enabled === false)
      .map(([id]) => id),
  );
  const argRules: CompiledArgRule[] = policy.arguments.map((r) => ({
    tool: globToRegExp(r.tool),
    path: r.path,
    segments: r.path.split('.'),
    deny: (r.deny ?? []).map((s) => new RegExp(s, 'i')),
    allow: (r.allow ?? []).map((s) => new RegExp(s, 'i')),
    action: r.action ?? 'block',
    reason: r.reason,
  }));

  function evaluate(target: InspectionTarget, findings: Finding[], extra?: { knownTool?: boolean }): Decision {
    const toolName = toolNameOf(target);
    const contributions: Contribution[] = [];

    // 1-2. Findings, after rule overrides.
    const effective: Finding[] = [];
    for (const f of findings) {
      if (disabled.has(f.ruleId)) continue;
      const override = policy.rules[f.ruleId];
      const finding: Finding = override?.severity ? { ...f, severity: override.severity } : { ...f };
      effective.push(finding);
      const fallback =
        finding.ruleId === PROXY_RULE_IDS.UNKNOWN_TOOL_CALL
          ? policy.tools.unknown
          : policy.severityActions[finding.severity];
      contributions.push({
        action: override?.action ?? fallback,
        reason: `${finding.ruleId}: ${finding.message}`,
        severity: severityRank(finding.severity),
      });
    }

    // 3. Tool allow/deny lists (not for tool_result).
    if (target.kind !== 'tool_result') {
      if (matchesAny(toolName, denyGlobs)) {
        contributions.push({ action: 'block', reason: `tool '${toolName}' is denied by policy`, severity: -1 });
      } else if (allowGlobs.length > 0 && !matchesAny(toolName, allowGlobs)) {
        contributions.push({
          action: policy.tools.unlisted,
          reason: `tool '${toolName}' is not in the policy allow list`,
          severity: -1,
        });
      }
    }

    if (target.kind === 'tool_call') {
      // 4a. Unknown tool. The proxy normally also emits an UNKNOWN_TOOL_CALL finding (handled above);
      // only add a reason of our own when that finding is absent. Disabling that rule silences both.
      if (extra?.knownTool === false && !disabled.has(PROXY_RULE_IDS.UNKNOWN_TOOL_CALL)) {
        const hasFinding = effective.some((f) => f.ruleId === PROXY_RULE_IDS.UNKNOWN_TOOL_CALL);
        if (!hasFinding) {
          contributions.push({
            action: policy.tools.unknown,
            reason: `tool '${toolName}' was never listed by the server`,
            severity: -1,
          });
        }
      }

      // 4b. Argument rules.
      const args = target.arguments ?? {};
      for (const rule of argRules) {
        if (!rule.tool.test(toolName)) continue;
        const values: Array<{ name: string; value: string }> = [];
        if (rule.path === '*') {
          for (const [k, v] of Object.entries(args)) if (typeof v === 'string') values.push({ name: k, value: v });
        } else {
          const r = resolvePath(args, rule.segments);
          const s = r.found ? stringify(r.value) : undefined;
          if (s !== undefined) values.push({ name: rule.path, value: s });
        }
        for (const { name, value } of values) {
          const denied = rule.deny.some((re) => re.test(value));
          const notAllowed = rule.allow.length > 0 && !rule.allow.some((re) => re.test(value));
          if (denied || notAllowed) {
            contributions.push({
              action: rule.action,
              reason: rule.reason ?? `argument '${name}' violates policy`,
              severity: -1,
            });
          }
        }
      }
    }

    // 5. Combine.
    let action: Action = 'allow';
    for (const c of contributions) action = maxAction(action, c.action);

    const ordered = contributions
      .map((c, i) => ({ c, i }))
      .sort(
        (a, b) =>
          actionRank(b.c.action) - actionRank(a.c.action) || b.c.severity - a.c.severity || a.i - b.i,
      );
    const reasons: string[] = [];
    for (const { c } of ordered) if (!reasons.includes(c.reason)) reasons.push(c.reason);

    let wouldBlock = false;
    if (policy.mode === 'monitor' && action === 'block') {
      action = 'warn';
      wouldBlock = true;
    }
    return { action, wouldBlock, reasons, findings: effective };
  }

  return {
    policy,
    disabledRules: () => [...disabled],
    evaluate,
  };
}

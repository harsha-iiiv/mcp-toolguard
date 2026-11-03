import {
  ACTION_ORDER,
  PolicyError,
  SEVERITY_ORDER,
  type Action,
  type ArgumentRule,
  type ToolguardPolicy,
  type RuleOverride,
  type Severity,
} from '../contracts.js';
import { defaultPolicy } from './defaults.js';
import { expandHome } from './paths.js';

const TOP_KEYS = ['version', 'mode', 'tools', 'severityActions', 'rules', 'arguments', 'pins', 'audit', 'spend', 'approval', 'learning', 'plugins'] as const;
const SPEND_KEYS = ['maxSpendPerTaskUsd', 'costs', 'defaultCostUsd'] as const;
const APPROVAL_KEYS = ['tools', 'file'] as const;
const LEARNING_KEYS = ['enabled', 'file', 'minSamples'] as const;
const PLUGIN_KEYS = ['enabled', 'dir'] as const;
const TOOLS_KEYS = ['allow', 'deny', 'unlisted', 'unknown'] as const;
const RULE_KEYS = ['enabled', 'action', 'severity'] as const;
const ARG_KEYS = ['tool', 'path', 'deny', 'allow', 'action', 'reason'] as const;
const PINS_KEYS = ['file'] as const;
const AUDIT_KEYS = ['file', 'redact', 'logAllowed'] as const;
const MODES = ['enforce', 'monitor'] as const;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

function quoteList(values: readonly string[]): string {
  return values.map((v) => `'${v}'`).join(' | ');
}

class Issues {
  readonly list: string[] = [];
  add(path: string, msg: string): void {
    this.list.push(`${path}: ${msg}`);
  }
}

/** Reports unknown keys. Returns the object if it is an object, undefined otherwise (with an issue). */
function checkObject(value: unknown, path: string, keys: readonly string[], issues: Issues): Obj | undefined {
  if (!isObj(value)) {
    issues.add(path, `expected object, got ${describe(value)}`);
    return undefined;
  }
  for (const k of Object.keys(value)) {
    if (!keys.includes(k)) issues.add(path === '' ? k : `${path}.${k}`, `unknown key (allowed: ${keys.join(', ')})`);
  }
  return value;
}

function checkEnum<T extends string>(value: unknown, path: string, values: readonly T[], issues: Issues): T | undefined {
  if (typeof value === 'string' && (values as readonly string[]).includes(value)) return value as T;
  issues.add(path, `expected one of ${quoteList(values)}, got ${JSON.stringify(value) ?? describe(value)}`);
  return undefined;
}

function checkString(value: unknown, path: string, issues: Issues, nonEmpty = false): string | undefined {
  if (typeof value !== 'string') {
    issues.add(path, `expected string, got ${describe(value)}`);
    return undefined;
  }
  if (nonEmpty && value.length === 0) {
    issues.add(path, 'expected non-empty string');
    return undefined;
  }
  return value;
}

function checkBoolean(value: unknown, path: string, issues: Issues): boolean | undefined {
  if (typeof value === 'boolean') return value;
  issues.add(path, `expected boolean, got ${describe(value)}`);
  return undefined;
}

function checkStringArray(value: unknown, path: string, issues: Issues): string[] | undefined {
  if (!Array.isArray(value)) {
    issues.add(path, `expected array of strings, got ${describe(value)}`);
    return undefined;
  }
  const out: string[] = [];
  value.forEach((v, i) => {
    const s = checkString(v, `${path}[${i}]`, issues);
    if (s !== undefined) out.push(s);
  });
  return out;
}

function checkRegexArray(value: unknown, path: string, issues: Issues): string[] | undefined {
  const arr = checkStringArray(value, path, issues);
  if (!arr) return undefined;
  arr.forEach((src, i) => {
    try {
      new RegExp(src, 'i');
    } catch (err) {
      issues.add(`${path}[${i}]`, `invalid regex: ${(err as Error).message}`);
    }
  });
  return arr;
}

/** Section values of null are treated as "not given" (YAML `tools:` with everything commented out). */
function present(v: unknown): boolean {
  return v !== undefined && v !== null;
}

function validateArgumentRule(value: unknown, path: string, issues: Issues): ArgumentRule | undefined {
  const o = checkObject(value, path, ARG_KEYS, issues);
  if (!o) return undefined;
  const tool = checkString(o.tool, `${path}.tool`, issues, true);
  const p = checkString(o.path, `${path}.path`, issues, true);
  const rule: ArgumentRule = { tool: tool ?? '', path: p ?? '' };
  if (o.deny !== undefined) rule.deny = checkRegexArray(o.deny, `${path}.deny`, issues);
  if (o.allow !== undefined) rule.allow = checkRegexArray(o.allow, `${path}.allow`, issues);
  if (o.action !== undefined) rule.action = checkEnum(o.action, `${path}.action`, ACTION_ORDER, issues);
  if (o.reason !== undefined) rule.reason = checkString(o.reason, `${path}.reason`, issues);
  if (rule.deny === undefined && rule.allow === undefined) {
    issues.add(path, "expected at least one of 'deny' or 'allow'");
  }
  return rule;
}

function validateRuleOverride(value: unknown, path: string, issues: Issues): RuleOverride | undefined {
  const o = checkObject(value, path, RULE_KEYS, issues);
  if (!o) return undefined;
  const r: RuleOverride = {};
  if (o.enabled !== undefined) r.enabled = checkBoolean(o.enabled, `${path}.enabled`, issues);
  if (o.action !== undefined) r.action = checkEnum(o.action, `${path}.action`, ACTION_ORDER, issues);
  if (o.severity !== undefined) r.severity = checkEnum(o.severity, `${path}.severity`, SEVERITY_ORDER, issues);
  return r;
}

/**
 * Validate a (partial) raw policy and deep-merge it over defaultPolicy().
 * Arrays replace the default arrays; objects merge key by key. '~' in file paths is expanded.
 * Throws PolicyError('Invalid policy', issues) listing every problem found.
 */
export function validatePolicy(raw: unknown): ToolguardPolicy {
  const policy = defaultPolicy();
  const issues = new Issues();

  if (present(raw)) {
    if (!isObj(raw)) {
      issues.add('policy', `expected object, got ${describe(raw)}`);
    } else {
      mergeRoot(checkObject(raw, '', TOP_KEYS, issues)!, policy, issues);
    }
  }

  if (issues.list.length > 0) throw new PolicyError('Invalid policy', issues.list);

  policy.pins.file = expandHome(policy.pins.file);
  policy.audit.file = expandHome(policy.audit.file);
  policy.approval.file = expandHome(policy.approval.file);
  policy.learning.file = expandHome(policy.learning.file);
  return policy;
}

function mergeRoot(root: Obj, policy: ToolguardPolicy, issues: Issues): void {
  if (root.version !== undefined && root.version !== 1) {
    issues.add('version', `expected 1, got ${JSON.stringify(root.version) ?? describe(root.version)}`);
  }

  if (root.mode !== undefined) {
    const m = checkEnum(root.mode, 'mode', MODES, issues);
    if (m) policy.mode = m;
  }

  if (present(root.tools)) {
    const t = checkObject(root.tools, 'tools', TOOLS_KEYS, issues);
    if (t) {
      if (present(t.allow)) policy.tools.allow = checkStringArray(t.allow, 'tools.allow', issues) ?? [];
      if (present(t.deny)) policy.tools.deny = checkStringArray(t.deny, 'tools.deny', issues) ?? [];
      if (t.unlisted !== undefined) {
        const a = checkEnum(t.unlisted, 'tools.unlisted', ACTION_ORDER, issues);
        if (a) policy.tools.unlisted = a;
      }
      if (t.unknown !== undefined) {
        const a = checkEnum(t.unknown, 'tools.unknown', ACTION_ORDER, issues);
        if (a) policy.tools.unknown = a;
      }
    }
  }

  if (present(root.severityActions)) {
    const s = checkObject(root.severityActions, 'severityActions', SEVERITY_ORDER, issues);
    if (s) {
      for (const sev of SEVERITY_ORDER) {
        if (s[sev] === undefined) continue;
        const a = checkEnum<Action>(s[sev], `severityActions.${sev}`, ACTION_ORDER, issues);
        if (a) policy.severityActions[sev as Severity] = a;
      }
    }
  }

  if (present(root.rules)) {
    if (!isObj(root.rules)) {
      issues.add('rules', `expected object, got ${describe(root.rules)}`);
    } else {
      for (const [id, v] of Object.entries(root.rules)) {
        const r = validateRuleOverride(v, `rules.${id}`, issues);
        if (r) policy.rules[id] = { ...policy.rules[id], ...r };
      }
    }
  }

  if (present(root.arguments)) {
    if (!Array.isArray(root.arguments)) {
      issues.add('arguments', `expected array, got ${describe(root.arguments)}`);
    } else {
      const out: ArgumentRule[] = [];
      root.arguments.forEach((v, i) => {
        const r = validateArgumentRule(v, `arguments[${i}]`, issues);
        if (r) out.push(r);
      });
      policy.arguments = out;
    }
  }

  if (present(root.pins)) {
    const p = checkObject(root.pins, 'pins', PINS_KEYS, issues);
    if (p && p.file !== undefined) {
      const f = checkString(p.file, 'pins.file', issues, true);
      if (f !== undefined) policy.pins.file = f;
    }
  }

  if (present(root.audit)) {
    const a = checkObject(root.audit, 'audit', AUDIT_KEYS, issues);
    if (a) {
      if (a.file !== undefined) {
        const f = checkString(a.file, 'audit.file', issues, true);
        if (f !== undefined) policy.audit.file = f;
      }
      if (a.redact !== undefined) {
        const b = checkBoolean(a.redact, 'audit.redact', issues);
        if (b !== undefined) policy.audit.redact = b;
      }
      if (a.logAllowed !== undefined) {
        const b = checkBoolean(a.logAllowed, 'audit.logAllowed', issues);
        if (b !== undefined) policy.audit.logAllowed = b;
      }
    }
  }

  mergeV2(root, policy, issues);
}

function checkNonNegative(v: unknown, path: string, issues: Issues): number | undefined {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
    issues.add(path, `expected a non-negative number, got ${JSON.stringify(v) ?? describe(v)}`);
    return undefined;
  }
  return v;
}

/** v0.2 sections: spend, approval, learning, plugins. */
function mergeV2(root: Obj, policy: ToolguardPolicy, issues: Issues): void {
  if (present(root.spend)) {
    const s = checkObject(root.spend, 'spend', SPEND_KEYS, issues);
    if (s) {
      if (s.maxSpendPerTaskUsd === null) policy.spend.maxSpendPerTaskUsd = null;
      else if (s.maxSpendPerTaskUsd !== undefined) {
        const n = checkNonNegative(s.maxSpendPerTaskUsd, 'spend.maxSpendPerTaskUsd', issues);
        if (n !== undefined) policy.spend.maxSpendPerTaskUsd = n;
      }
      if (s.defaultCostUsd !== undefined) {
        const n = checkNonNegative(s.defaultCostUsd, 'spend.defaultCostUsd', issues);
        if (n !== undefined) policy.spend.defaultCostUsd = n;
      }
      if (present(s.costs)) {
        if (!isObj(s.costs)) issues.add('spend.costs', `expected object, got ${describe(s.costs)}`);
        else {
          const costs: Record<string, number> = {};
          for (const [k, v] of Object.entries(s.costs)) {
            const n = checkNonNegative(v, `spend.costs.${k}`, issues);
            if (n !== undefined) costs[k] = n;
          }
          policy.spend.costs = costs;
        }
      }
    }
  }
  if (present(root.approval)) {
    const a = checkObject(root.approval, 'approval', APPROVAL_KEYS, issues);
    if (a) {
      if (present(a.tools)) policy.approval.tools = checkStringArray(a.tools, 'approval.tools', issues) ?? [];
      if (a.file !== undefined) {
        const f = checkString(a.file, 'approval.file', issues, true);
        if (f !== undefined) policy.approval.file = f;
      }
    }
  }
  if (present(root.learning)) {
    const l = checkObject(root.learning, 'learning', LEARNING_KEYS, issues);
    if (l) {
      if (l.enabled !== undefined) {
        const b = checkBoolean(l.enabled, 'learning.enabled', issues);
        if (b !== undefined) policy.learning.enabled = b;
      }
      if (l.file !== undefined) {
        const f = checkString(l.file, 'learning.file', issues, true);
        if (f !== undefined) policy.learning.file = f;
      }
      if (l.minSamples !== undefined) {
        const n = checkNonNegative(l.minSamples, 'learning.minSamples', issues);
        if (n !== undefined) policy.learning.minSamples = Math.floor(n);
      }
    }
  }
  if (present(root.plugins)) {
    const p = checkObject(root.plugins, 'plugins', PLUGIN_KEYS, issues);
    if (p) {
      if (p.enabled !== undefined) {
        const b = checkBoolean(p.enabled, 'plugins.enabled', issues);
        if (b !== undefined) policy.plugins.enabled = b;
      }
      if (p.dir !== undefined) {
        const d = checkString(p.dir, 'plugins.dir', issues, true);
        if (d !== undefined) policy.plugins.dir = d;
      }
    }
  }
}

// The public API is frozen. Renaming or removing any of these names must fail CI.
import { describe, expect, it } from 'vitest';
import * as api from '../../../src/index.js';

/** Frozen from v1.0. Never remove or rename an entry; additions only. */
const FROZEN_V1 = [
  'startProxy',
  'loadPolicy',
  'createPolicyEngine',
  'createDetector',
  'createPinStore',
  'createAuditLogger',
  'verifyAuditLog',
  'loadPlugin',
] as const;

/** Existing exports kept for compatibility (also functions/classes). */
const KEPT = [
  'defaultPolicy',
  'validatePolicy',
  'builtinRules',
  'hashTool',
  'redactSecrets',
  'canonicalJson',
  'runCli',
  'UsageError',
  'PolicyError',
  'loadPlugins',
  'definePlugin',
  'PluginError',
] as const;

const CONSTANTS = [
  'TOOLGUARD_VERSION',
  'SEVERITY_ORDER',
  'ACTION_ORDER',
  'RULE_IDS',
  'PROXY_RULE_IDS',
  'BLOCK_MARKER',
  'VERDICT_ORDER',
  'APPROVAL_MARKER',
] as const;

describe('public API (src/index.ts)', () => {
  it.each(FROZEN_V1)('frozen v1 export %s is a function', (name) => {
    expect(typeof (api as Record<string, unknown>)[name]).toBe('function');
  });

  it.each(KEPT)('compat export %s is a function', (name) => {
    expect(typeof (api as Record<string, unknown>)[name]).toBe('function');
  });

  it.each(CONSTANTS)('contract constant %s is exported', (name) => {
    expect((api as Record<string, unknown>)[name]).toBeDefined();
  });

  it('contract types are exported (compile-time check)', () => {
    // These lines fail `npm run typecheck` if a type export disappears.
    const verdict: api.Verdict = { action: 'block', reason: 'r', ruleId: 'x' };
    const plugin: api.RulePlugin = { id: 'x', check: (_c: api.ToolCall, _r: api.ToolResult | undefined, _p: api.Policy) => verdict };
    const opts: Partial<api.ProxyOptions> = { plugins: [plugin] };
    const _types: [api.ToolguardPolicy?, api.ProxyHandle?, api.Detector?, api.PolicyEngine?, api.AuditLogger?, api.ToolPinStore?] = [];
    expect(opts.plugins).toHaveLength(1);
    expect(_types).toEqual([]);
  });
});

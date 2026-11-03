import { describe, expect, it } from 'vitest';
import type {
  Finding,
  ToolguardPolicy,
  InspectionTarget,
  ToolCallTarget,
  ToolDefinitionTarget,
  ToolResultTarget,
} from '../../../src/contracts.js';
import { PROXY_RULE_IDS } from '../../../src/contracts.js';
import { createPolicyEngine, validatePolicy } from '../../../src/policy/index.js';
import { globToRegExp } from '../../../src/policy/glob.js';

const call = (toolName: string, args: Record<string, unknown> = {}): ToolCallTarget => ({
  kind: 'tool_call',
  requestId: 1,
  toolName,
  arguments: args,
});
const def = (name: string): ToolDefinitionTarget => ({ kind: 'tool_definition', tool: { name, description: 'd' } });
const result = (toolName: string): ToolResultTarget => ({
  kind: 'tool_result',
  requestId: 1,
  toolName,
  result: { content: [] },
});
const finding = (ruleId: string, severity: Finding['severity'], message = 'msg'): Finding => ({
  ruleId,
  severity,
  message,
});

function engine(raw: unknown = {}) {
  return createPolicyEngine(validatePolicy(raw));
}
function evaluate(raw: unknown, target: InspectionTarget, findings: Finding[] = [], extra?: { knownTool?: boolean }) {
  return engine(raw).evaluate(target, findings, extra);
}

describe('glob', () => {
  it('supports * and ? anchored', () => {
    const re = globToRegExp('read_*');
    expect(re.test('read_file')).toBe(true);
    expect(re.test('read_')).toBe(true);
    expect(re.test('xread_file')).toBe(false);
    const q = globToRegExp('a?c');
    expect(q.test('abc')).toBe(true);
    expect(q.test('ac')).toBe(false);
    expect(q.test('abbc')).toBe(false);
    expect(globToRegExp('*').test('')).toBe(true);
  });

  it('escapes other regex characters', () => {
    expect(globToRegExp('a.b').test('a.b')).toBe(true);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
    expect(globToRegExp('fs+(x)[1]|$^\\{2}').test('fs+(x)[1]|$^\\{2}')).toBe(true);
    expect(globToRegExp('a+').test('aa')).toBe(false);
  });

  it('is case-sensitive and exact', () => {
    expect(globToRegExp('exec').test('Exec')).toBe(false);
    expect(globToRegExp('exec').test('exec2')).toBe(false);
  });
});

describe('policy engine basics', () => {
  it('clean allow', () => {
    expect(evaluate({}, call('anything'))).toEqual({ action: 'allow', wouldBlock: false, reasons: [], findings: [] });
  });

  it('exposes policy and disabledRules', () => {
    const e = engine({ rules: { a: { enabled: false }, b: { enabled: true }, c: { action: 'warn' } } });
    expect(e.disabledRules()).toEqual(['a']);
    expect(e.policy.rules.c).toEqual({ action: 'warn' });
  });

  it('does not mutate input findings', () => {
    const f = finding('r', 'low');
    const d = evaluate({ rules: { r: { severity: 'critical' } } }, call('t'), [f]);
    expect(f.severity).toBe('low');
    expect(d.findings[0]!.severity).toBe('critical');
  });
});

describe('findings and severity actions', () => {
  it('maps severity via severityActions', () => {
    expect(evaluate({}, call('t'), [finding('r', 'low')]).action).toBe('allow');
    expect(evaluate({}, call('t'), [finding('r', 'medium')]).action).toBe('warn');
    expect(evaluate({}, call('t'), [finding('r', 'high')]).action).toBe('block');
    expect(evaluate({}, call('t'), [finding('r', 'critical')]).action).toBe('block');
    expect(evaluate({ severityActions: { critical: 'warn' } }, call('t'), [finding('r', 'critical')]).action).toBe(
      'warn',
    );
  });

  it('reason format is ruleId: message', () => {
    const d = evaluate({}, call('t'), [finding('secret-exfiltration', 'critical', 'AWS key in arguments.x')]);
    expect(d.reasons).toEqual(['secret-exfiltration: AWS key in arguments.x']);
  });

  it('takes the max action and sorts reasons most severe first', () => {
    const d = evaluate({}, call('t'), [
      finding('a', 'low', 'l'),
      finding('b', 'medium', 'm'),
      finding('c', 'critical', 'c'),
      finding('d', 'high', 'h'),
    ]);
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual(['c: c', 'd: h', 'b: m', 'a: l']);
    expect(d.findings.map((f) => f.ruleId)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('dedupes identical reasons', () => {
    const d = evaluate({}, call('t'), [finding('a', 'high', 'x'), finding('a', 'high', 'x')]);
    expect(d.reasons).toEqual(['a: x']);
    expect(d.findings).toHaveLength(2);
  });
});

describe('rule overrides', () => {
  it('disable removes findings', () => {
    const d = evaluate({ rules: { 'tool-poisoning': { enabled: false } } }, def('t'), [
      finding('tool-poisoning', 'critical'),
      finding('hidden-unicode', 'medium'),
    ]);
    expect(d.findings.map((f) => f.ruleId)).toEqual(['hidden-unicode']);
    expect(d.action).toBe('warn');
  });

  it('action override beats severityActions', () => {
    expect(evaluate({ rules: { r: { action: 'warn' } } }, call('t'), [finding('r', 'critical')]).action).toBe('warn');
    expect(evaluate({ rules: { r: { action: 'block' } } }, call('t'), [finding('r', 'low')]).action).toBe('block');
  });

  it('severity override re-labels and then uses severityActions', () => {
    const d = evaluate({ rules: { r: { severity: 'low' } } }, call('t'), [finding('r', 'critical')]);
    expect(d.action).toBe('allow');
    expect(d.findings[0]!.severity).toBe('low');
  });

  it('action override wins over severity override', () => {
    const d = evaluate({ rules: { r: { severity: 'critical', action: 'warn' } } }, call('t'), [finding('r', 'low')]);
    expect(d.action).toBe('warn');
    expect(d.findings[0]!.severity).toBe('critical');
  });
});

describe('tool lists', () => {
  it('deny blocks tool_call and tool_definition', () => {
    const p = { tools: { deny: ['exec_*', 'rm'] } };
    for (const t of [call('exec_shell'), def('exec_shell'), call('rm')]) {
      const d = evaluate(p, t);
      expect(d.action).toBe('block');
      expect(d.reasons[0]).toMatch(/^tool '(exec_shell|rm)' is denied by policy$/);
    }
    expect(evaluate(p, call('rmdir')).action).toBe('allow');
  });

  it('deny wins over allow', () => {
    const d = evaluate({ tools: { allow: ['*'], deny: ['danger'], unlisted: 'warn' } }, call('danger'));
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual(["tool 'danger' is denied by policy"]);
  });

  it('unlisted applies only when allow is non-empty', () => {
    expect(evaluate({ tools: { allow: [] } }, call('x')).action).toBe('allow');
    const p = { tools: { allow: ['read_*', 'list_?'] } };
    expect(evaluate(p, call('read_file')).action).toBe('allow');
    expect(evaluate(p, call('list_a')).action).toBe('allow');
    expect(evaluate(p, call('list_ab')).action).toBe('block');
    expect(evaluate(p, def('write_file')).action).toBe('block');
    expect(evaluate({ tools: { allow: ['read_*'], unlisted: 'warn' } }, call('write_file')).action).toBe('warn');
    expect(evaluate({ tools: { allow: ['read_*'], unlisted: 'allow' } }, call('write_file')).action).toBe('allow');
  });

  it('tool_result is exempt from tool lists', () => {
    const p = { tools: { allow: ['read_*'], deny: ['exec'] } };
    expect(evaluate(p, result('exec'))).toEqual({ action: 'allow', wouldBlock: false, reasons: [], findings: [] });
    expect(evaluate(p, result('write_file')).action).toBe('allow');
    expect(evaluate(p, result('exec'), [finding('result-injection', 'high')]).action).toBe('block');
  });
});

describe('unknown tools', () => {
  it('knownTool false contributes tools.unknown', () => {
    const d = evaluate({}, call('ghost'), [], { knownTool: false });
    expect(d.action).toBe('warn');
    expect(d.reasons).toHaveLength(1);
    expect(evaluate({ tools: { unknown: 'block' } }, call('ghost'), [], { knownTool: false }).action).toBe('block');
    expect(evaluate({ tools: { unknown: 'allow' } }, call('ghost'), [], { knownTool: false }).action).toBe('allow');
  });

  it('knownTool true / undefined contributes nothing', () => {
    expect(evaluate({ tools: { unknown: 'block' } }, call('t'), [], { knownTool: true }).action).toBe('allow');
    expect(evaluate({ tools: { unknown: 'block' } }, call('t')).action).toBe('allow');
  });

  it('only for tool_call', () => {
    expect(evaluate({ tools: { unknown: 'block' } }, def('t'), [], { knownTool: false }).action).toBe('allow');
    expect(evaluate({ tools: { unknown: 'block' } }, result('t'), [], { knownTool: false }).action).toBe('allow');
  });

  it('does not double-count with the proxy finding; finding follows tools.unknown', () => {
    const f = finding(PROXY_RULE_IDS.UNKNOWN_TOOL_CALL, 'medium', "tool 'ghost' was never listed");
    const d = evaluate({ tools: { unknown: 'block' } }, call('ghost'), [f], { knownTool: false });
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual([`${PROXY_RULE_IDS.UNKNOWN_TOOL_CALL}: tool 'ghost' was never listed`]);
    expect(evaluate({ tools: { unknown: 'allow' } }, call('ghost'), [f], { knownTool: false }).action).toBe('allow');
  });

  it('a rule override on the proxy rule id still wins', () => {
    const f = finding(PROXY_RULE_IDS.UNKNOWN_TOOL_CALL, 'medium');
    const p = { rules: { [PROXY_RULE_IDS.UNKNOWN_TOOL_CALL]: { action: 'block' } } };
    expect(evaluate(p, call('ghost'), [f], { knownTool: false }).action).toBe('block');
    const off = { tools: { unknown: 'block' }, rules: { [PROXY_RULE_IDS.UNKNOWN_TOOL_CALL]: { enabled: false } } };
    expect(evaluate(off, call('ghost'), [f], { knownTool: false })).toMatchObject({ action: 'allow', reasons: [] });
  });
});

describe('argument rules', () => {
  it('deny regex blocks, case-insensitive, default reason', () => {
    const p = { arguments: [{ tool: 'fetch', path: 'url', deny: ['^file:'] }] };
    const d = evaluate(p, call('fetch', { url: 'FILE:///etc/passwd' }));
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual(["argument 'url' violates policy"]);
    expect(evaluate(p, call('fetch', { url: 'https://x' })).action).toBe('allow');
  });

  it('allow list: no match violates, match passes', () => {
    const p = { arguments: [{ tool: 'fetch', path: 'url', allow: ['^https://example\\.com/'] }] };
    expect(evaluate(p, call('fetch', { url: 'https://evil.com/' })).action).toBe('block');
    expect(evaluate(p, call('fetch', { url: 'https://EXAMPLE.com/a' })).action).toBe('allow');
  });

  it('custom action and reason', () => {
    const p = { arguments: [{ tool: '*', path: 'q', deny: ['drop table'], action: 'warn', reason: 'no SQL DDL' }] };
    const d = evaluate(p, call('sql', { q: 'DROP TABLE users' }));
    expect(d).toMatchObject({ action: 'warn', reasons: ['no SQL DDL'] });
  });

  it('tool glob must match', () => {
    const p = { arguments: [{ tool: 'fs_*', path: 'path', deny: ['\\.ssh'] }] };
    expect(evaluate(p, call('fs_read', { path: '~/.ssh/id_rsa' })).action).toBe('block');
    expect(evaluate(p, call('net_get', { path: '~/.ssh/id_rsa' })).action).toBe('allow');
  });

  it('dot paths into nested objects', () => {
    const p = { arguments: [{ tool: '*', path: 'options.url', deny: ['localhost'] }] };
    expect(evaluate(p, call('t', { options: { url: 'http://localhost:8080' } })).action).toBe('block');
    expect(evaluate(p, call('t', { options: { url: 'http://ok' } })).action).toBe('allow');
    expect(evaluate(p, call('t', { options: 'localhost' })).action).toBe('allow');
    expect(evaluate(p, call('t', {})).action).toBe('allow');
  });

  it('missing path does not trigger allow-list violation', () => {
    const p = { arguments: [{ tool: '*', path: 'url', allow: ['^https:'] }] };
    expect(evaluate(p, call('t', { other: 'x' })).action).toBe('allow');
  });

  it('non-string values are JSON-stringified', () => {
    const p = { arguments: [{ tool: '*', path: 'opts', deny: ['"force":true'] }] };
    expect(evaluate(p, call('t', { opts: { force: true } })).action).toBe('block');
    const n = { arguments: [{ tool: '*', path: 'count', allow: ['^\\d{1,2}$'] }] };
    expect(evaluate(n, call('t', { count: 5 })).action).toBe('allow');
    expect(evaluate(n, call('t', { count: 500 })).action).toBe('block');
    const nul = { arguments: [{ tool: '*', path: 'v', deny: ['^null$'] }] };
    expect(evaluate(nul, call('t', { v: null })).action).toBe('block');
  });

  it("'*' checks every top-level string arg and names the offending one", () => {
    const p = { arguments: [{ tool: '*', path: '*', deny: ['rm -rf'] }] };
    const d = evaluate(p, call('t', { a: 'ls', b: 'rm -rf /', c: { x: 'rm -rf /' } }));
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual(["argument 'b' violates policy"]);
    expect(evaluate(p, call('t', { c: { x: 'rm -rf /' }, n: 1 })).action).toBe('allow');
  });

  it("'*' with allow list checks each string arg", () => {
    const p = { arguments: [{ tool: '*', path: '*', allow: ['^[a-z]+$'] }] };
    expect(evaluate(p, call('t', { a: 'ok', b: 'fine' })).action).toBe('allow');
    expect(evaluate(p, call('t', { a: 'ok', b: 'NOT ok!' })).reasons).toEqual(["argument 'b' violates policy"]);
  });

  it('argument rules apply only to tool_call', () => {
    const p = { arguments: [{ tool: '*', path: '*', deny: ['.*'] }] };
    expect(evaluate(p, def('t')).action).toBe('allow');
    expect(evaluate(p, result('t')).action).toBe('allow');
  });

  it('regexes are not stateful across evaluations', () => {
    const e = engine({ arguments: [{ tool: '*', path: 'a', deny: ['x'] }] });
    for (let i = 0; i < 3; i++) expect(e.evaluate(call('t', { a: 'x' }), []).action).toBe('block');
  });
});

describe('combining and monitor mode', () => {
  it('max over findings, tool lists and arguments; policy reasons ordered by action', () => {
    const p = {
      tools: { allow: ['read_*'], unlisted: 'warn' },
      arguments: [{ tool: '*', path: 'p', deny: ['secret'] }],
    };
    const d = evaluate(p, call('write', { p: 'secret' }), [finding('a', 'low', 'l')]);
    expect(d.action).toBe('block');
    expect(d.reasons).toEqual(["argument 'p' violates policy", "tool 'write' is not in the policy allow list", 'a: l']);
  });

  it('monitor mode downgrades block to warn with wouldBlock', () => {
    const d = evaluate({ mode: 'monitor' }, call('t'), [finding('r', 'critical')]);
    expect(d).toMatchObject({ action: 'warn', wouldBlock: true, reasons: ['r: msg'] });
    const deny = evaluate({ mode: 'monitor', tools: { deny: ['t'] } }, def('t'));
    expect(deny).toMatchObject({ action: 'warn', wouldBlock: true });
  });

  it('monitor mode leaves warn/allow alone', () => {
    expect(evaluate({ mode: 'monitor' }, call('t'), [finding('r', 'medium')])).toMatchObject({
      action: 'warn',
      wouldBlock: false,
    });
    expect(evaluate({ mode: 'monitor' }, call('t'))).toMatchObject({ action: 'allow', wouldBlock: false });
  });

  it('enforce mode never sets wouldBlock', () => {
    expect(evaluate({}, call('t'), [finding('r', 'critical')])).toMatchObject({ action: 'block', wouldBlock: false });
  });

  it('works on a policy object built by hand', () => {
    const policy: ToolguardPolicy = validatePolicy({});
    policy.tools.deny = ['x'];
    expect(createPolicyEngine(policy).evaluate(call('x'), []).action).toBe('block');
  });
});

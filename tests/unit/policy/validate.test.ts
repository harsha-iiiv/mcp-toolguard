import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PolicyError, defaultPolicy, validatePolicy } from '../../../src/policy/index.js';
import { PolicyError as ContractPolicyError } from '../../../src/contracts.js';

function issuesOf(raw: unknown): string[] {
  try {
    validatePolicy(raw);
  } catch (err) {
    expect(err).toBeInstanceOf(PolicyError);
    expect((err as PolicyError).message).toBe('Invalid policy');
    return (err as PolicyError).issues;
  }
  throw new Error('expected validatePolicy to throw');
}

describe('defaultPolicy', () => {
  let saved: string | undefined;
  beforeEach(() => {
    saved = process.env.MCP_TOOLGUARD_HOME;
    delete process.env.MCP_TOOLGUARD_HOME;
  });
  afterEach(() => {
    if (saved === undefined) delete process.env.MCP_TOOLGUARD_HOME;
    else process.env.MCP_TOOLGUARD_HOME = saved;
  });

  it('matches the spec', () => {
    expect(defaultPolicy()).toEqual({
      version: 1,
      mode: 'enforce',
      tools: { allow: [], deny: [], unlisted: 'block', unknown: 'warn' },
      severityActions: { low: 'allow', medium: 'warn', high: 'block', critical: 'block' },
      rules: {},
      arguments: [],
      pins: { file: '~/.mcp-toolguard/pins.json' },
      spend: { maxSpendPerTaskUsd: null, costs: {}, defaultCostUsd: 0 },
      approval: { tools: [], file: '~/.mcp-toolguard/approvals.json' },
      learning: { enabled: false, file: '~/.mcp-toolguard/baseline.json', minSamples: 50 },
      plugins: { enabled: false, dir: './toolguard-plugins' },
      audit: { file: '~/.mcp-toolguard/audit.jsonl', redact: true, logAllowed: true },
    });
  });

  it('validates the v0.2 sections', () => {
    const p = validatePolicy({
      spend: { maxSpendPerTaskUsd: 1.5, costs: { 'brave_*': 0.005 } },
      approval: { tools: ['write_*', 'edit_file'] },
      learning: { enabled: true, minSamples: 10 },
      plugins: { enabled: true, dir: './p' },
    });
    expect(p.spend).toEqual({ maxSpendPerTaskUsd: 1.5, costs: { 'brave_*': 0.005 }, defaultCostUsd: 0 });
    expect(p.approval.tools).toEqual(['write_*', 'edit_file']);
    expect(p.learning.enabled).toBe(true);
    expect(p.plugins).toEqual({ enabled: true, dir: './p' });
    expect(() => validatePolicy({ spend: { maxSpendPerTaskUsd: -1 } })).toThrow(PolicyError);
    expect(() => validatePolicy({ approval: { tools: 'x' } })).toThrow(PolicyError);
    expect(() => validatePolicy({ plugins: { autoload: true } })).toThrow(PolicyError);
  });

  it('returns a fresh object each call', () => {
    const a = defaultPolicy();
    a.tools.deny.push('x');
    a.rules.foo = { enabled: false };
    expect(defaultPolicy().tools.deny).toEqual([]);
    expect(defaultPolicy().rules).toEqual({});
    expect(defaultPolicy()).not.toBe(defaultPolicy());
  });

  it('honours MCP_TOOLGUARD_HOME', () => {
    process.env.MCP_TOOLGUARD_HOME = '/tmp/gh';
    const p = defaultPolicy();
    expect(p.pins.file).toBe('/tmp/gh/pins.json');
    expect(p.audit.file).toBe('/tmp/gh/audit.jsonl');
  });

  it('PolicyError is the contract class', () => {
    expect(PolicyError).toBe(ContractPolicyError);
  });
});

describe('validatePolicy: defaults and merge', () => {
  let saved: string | undefined;
  beforeEach(() => {
    saved = process.env.MCP_TOOLGUARD_HOME;
    delete process.env.MCP_TOOLGUARD_HOME;
  });
  afterEach(() => {
    if (saved === undefined) delete process.env.MCP_TOOLGUARD_HOME;
    else process.env.MCP_TOOLGUARD_HOME = saved;
  });

  it('undefined / null / {} give defaults with expanded paths', () => {
    for (const raw of [undefined, null, {}]) {
      const p = validatePolicy(raw);
      expect(p.mode).toBe('enforce');
      expect(p.pins.file).toBe(path.join(os.homedir(), '.mcp-toolguard/pins.json'));
      expect(p.audit.file).toBe(path.join(os.homedir(), '.mcp-toolguard/audit.jsonl'));
    }
  });

  it('expands ~ in MCP_TOOLGUARD_HOME-free custom paths and leaves absolute paths alone', () => {
    const p = validatePolicy({ pins: { file: '~/x/pins.json' }, audit: { file: '/var/log/a.jsonl' } });
    expect(p.pins.file).toBe(path.join(os.homedir(), 'x/pins.json'));
    expect(p.audit.file).toBe('/var/log/a.jsonl');
    expect(validatePolicy({ pins: { file: '~notme/p.json' } }).pins.file).toBe('~notme/p.json');
  });

  it('uses MCP_TOOLGUARD_HOME in defaults', () => {
    process.env.MCP_TOOLGUARD_HOME = '/opt/toolguard';
    expect(validatePolicy(undefined).audit.file).toBe('/opt/toolguard/audit.jsonl');
  });

  it('deep-merges partial objects', () => {
    const p = validatePolicy({
      mode: 'monitor',
      tools: { deny: ['rm_*'] },
      severityActions: { low: 'warn' },
      audit: { redact: false },
      rules: { 'tool-poisoning': { action: 'warn' } },
      arguments: [{ tool: '*', path: 'url', deny: ['^file:'] }],
    });
    expect(p.mode).toBe('monitor');
    expect(p.tools).toEqual({ allow: [], deny: ['rm_*'], unlisted: 'block', unknown: 'warn' });
    expect(p.severityActions).toEqual({ low: 'warn', medium: 'warn', high: 'block', critical: 'block' });
    expect(p.audit.redact).toBe(false);
    expect(p.audit.logAllowed).toBe(true);
    expect(p.audit.file).toBe(path.join(os.homedir(), '.mcp-toolguard/audit.jsonl'));
    expect(p.rules).toEqual({ 'tool-poisoning': { action: 'warn' } });
    expect(p.arguments).toEqual([{ tool: '*', path: 'url', deny: ['^file:'] }]);
    expect(p.version).toBe(1);
  });

  it('treats null sections as not given', () => {
    const p = validatePolicy({ tools: null, rules: null, arguments: null, audit: null, pins: null });
    expect(p.tools.unlisted).toBe('block');
  });

  it('accepts version: 1 explicitly', () => {
    expect(validatePolicy({ version: 1 }).version).toBe(1);
  });
});

describe('validatePolicy: errors', () => {
  it('rejects non-object root', () => {
    expect(issuesOf('hello')).toEqual(['policy: expected object, got string']);
    expect(issuesOf([1])).toEqual(['policy: expected object, got array']);
  });

  it('rejects unknown top-level keys', () => {
    expect(issuesOf({ modes: 'enforce' })[0]).toMatch(/^modes: unknown key/);
  });

  it('rejects unknown nested keys', () => {
    expect(issuesOf({ tools: { block: [] } })[0]).toMatch(/^tools\.block: unknown key/);
    expect(issuesOf({ audit: { path: 'x' } })[0]).toMatch(/^audit\.path: unknown key/);
    expect(issuesOf({ pins: { dir: 'x' } })[0]).toMatch(/^pins\.dir: unknown key/);
    expect(issuesOf({ severityActions: { extreme: 'block' } })[0]).toMatch(/^severityActions\.extreme: unknown key/);
    expect(issuesOf({ rules: { x: { disable: true } } })[0]).toMatch(/^rules\.x\.disable: unknown key/);
    expect(issuesOf({ arguments: [{ tool: '*', path: 'a', deny: ['x'], extra: 1 }] })[0]).toMatch(
      /^arguments\[0\]\.extra: unknown key/,
    );
  });

  it('rejects bad version', () => {
    expect(issuesOf({ version: 2 })).toEqual(['version: expected 1, got 2']);
    expect(issuesOf({ version: '1' })).toEqual(['version: expected 1, got "1"']);
  });

  it('rejects bad enums', () => {
    expect(issuesOf({ mode: 'audit' })[0]).toMatch(/^mode: expected one of 'enforce' \| 'monitor'/);
    expect(issuesOf({ tools: { unlisted: 'deny' } })[0]).toMatch(/^tools\.unlisted: expected one of/);
    expect(issuesOf({ tools: { unknown: 1 } })[0]).toMatch(/^tools\.unknown: expected one of/);
    expect(issuesOf({ severityActions: { high: 'stop' } })[0]).toMatch(/^severityActions\.high: expected one of/);
    expect(issuesOf({ rules: { r: { action: 'nope' } } })[0]).toMatch(/^rules\.r\.action: expected one of/);
    expect(issuesOf({ rules: { r: { severity: 'huge' } } })[0]).toMatch(/^rules\.r\.severity: expected one of/);
    expect(issuesOf({ arguments: [{ tool: '*', path: 'a', deny: ['x'], action: 'x' }] })[0]).toMatch(
      /^arguments\[0\]\.action: expected one of/,
    );
  });

  it('rejects wrong types with readable paths', () => {
    expect(issuesOf({ tools: { deny: ['ok', 3] } })).toEqual(['tools.deny[1]: expected string, got number']);
    expect(issuesOf({ tools: { allow: 'x' } })).toEqual(['tools.allow: expected array of strings, got string']);
    expect(issuesOf({ tools: [] })).toEqual(['tools: expected object, got array']);
    expect(issuesOf({ rules: [] })).toEqual(['rules: expected object, got array']);
    expect(issuesOf({ rules: { r: true } })).toEqual(['rules.r: expected object, got boolean']);
    expect(issuesOf({ rules: { r: { enabled: 'no' } } })).toEqual(['rules.r.enabled: expected boolean, got string']);
    expect(issuesOf({ arguments: {} })).toEqual(['arguments: expected array, got object']);
    expect(issuesOf({ arguments: ['x'] })).toEqual(['arguments[0]: expected object, got string']);
    expect(issuesOf({ pins: { file: 3 } })).toEqual(['pins.file: expected string, got number']);
    expect(issuesOf({ pins: { file: '' } })).toEqual(['pins.file: expected non-empty string']);
    expect(issuesOf({ audit: { file: false } })).toEqual(['audit.file: expected string, got boolean']);
    expect(issuesOf({ audit: { redact: 'yes' } })).toEqual(['audit.redact: expected boolean, got string']);
    expect(issuesOf({ audit: { logAllowed: 1 } })).toEqual(['audit.logAllowed: expected boolean, got number']);
    expect(issuesOf({ mode: null })[0]).toMatch(/^mode: expected one of/);
  });

  it('validates argument rules', () => {
    expect(issuesOf({ arguments: [{ path: 'a', deny: ['x'] }] })).toEqual([
      'arguments[0].tool: expected string, got undefined',
    ]);
    expect(issuesOf({ arguments: [{ tool: '*', path: '', deny: ['x'] }] })).toEqual([
      'arguments[0].path: expected non-empty string',
    ]);
    expect(issuesOf({ arguments: [{ tool: '*', path: 'a' }] })).toEqual([
      "arguments[0]: expected at least one of 'deny' or 'allow'",
    ]);
    expect(issuesOf({ arguments: [{ tool: '*', path: 'a', deny: [1] }] })).toEqual([
      'arguments[0].deny[0]: expected string, got number',
    ]);
    expect(issuesOf({ arguments: [{ tool: '*', path: 'a', deny: ['x'], reason: 5 }] })).toEqual([
      'arguments[0].reason: expected string, got number',
    ]);
  });

  it('rejects invalid regex sources', () => {
    const deny = issuesOf({ arguments: [{ tool: '*', path: 'a', deny: ['ok', '(unclosed'] }] });
    expect(deny).toHaveLength(1);
    expect(deny[0]).toMatch(/^arguments\[0\]\.deny\[1\]: invalid regex: /);
    const allow = issuesOf({ arguments: [{ tool: '*', path: 'a', allow: ['[z-a]'] }] });
    expect(allow[0]).toMatch(/^arguments\[0\]\.allow\[0\]: invalid regex: /);
  });

  it('reports every problem at once', () => {
    const issues = issuesOf({ version: 3, mode: 'x', bogus: 1, tools: { deny: [1] } });
    expect(issues).toHaveLength(4);
  });
});

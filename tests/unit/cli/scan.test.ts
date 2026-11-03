import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Finding, ToolguardPolicy, InspectionTarget } from '../../../src/contracts.js';
import { makeIo } from './helpers.js';

const m = vi.hoisted(() => ({
  loadPolicy: vi.fn(),
  createPinStore: vi.fn(),
  mode: 'enforce' as 'enforce' | 'monitor',
}));

vi.mock('../../../src/policy/index.js', () => ({
  loadPolicy: m.loadPolicy,
  createPolicyEngine: (policy: ToolguardPolicy) => ({
    policy,
    disabledRules: () => [],
    evaluate: (_t: InspectionTarget, findings: Finding[]) => {
      const block = findings.some((f) => f.severity === 'critical');
      const monitor = policy.mode === 'monitor';
      return {
        action: block ? (monitor ? 'warn' : 'block') : 'allow',
        wouldBlock: block && monitor,
        reasons: findings.map((f) => f.message),
        findings,
      };
    },
  }),
  defaultPolicy: vi.fn(),
  validatePolicy: vi.fn(),
}));
vi.mock('../../../src/detection/index.js', () => ({
  createPinStore: m.createPinStore,
  createDetector: () => ({
    rules: [],
    inspect: (t: InspectionTarget): Finding[] =>
      t.kind === 'tool_definition' && t.tool.description === 'POISON'
        ? [
            {
              ruleId: 'tool-poisoning',
              severity: 'critical',
              message: 'hidden instructions in description',
              evidence: 'POISON',
              location: 'description',
              toolName: t.tool.name,
            },
          ]
        : [],
  }),
  builtinRules: vi.fn(),
  hashTool: vi.fn(),
}));

const { runCli } = await import('../../../src/cli/run-cli.js');

const SERVER = path.join(import.meta.dirname, 'fixtures', 'paged-server.mjs');
const ROOT = path.resolve(import.meta.dirname, '../../..');

beforeEach(() => {
  vi.clearAllMocks();
  m.loadPolicy.mockImplementation(() => ({
    policy: { mode: m.mode, pins: { file: '/should/not/be/used.json' } } as ToolguardPolicy,
    source: 'builtin',
  }));
  m.createPinStore.mockReturnValue({ get: vi.fn(), set: vi.fn(), list: () => [], reset: () => 0 });
  m.mode = 'enforce';
});

describe('scan (real MCP server over stdio)', () => {
  it('follows pagination, reports per tool, exits 2 when a tool would be blocked', async () => {
    const io = makeIo(ROOT, process.env);
    const code = await runCli(['scan', '--server-id', 'paged', '--', process.execPath, SERVER], io);
    expect(io.err()).toContain('paged-server: started');
    expect(code).toBe(2);
    const out = io.out();
    expect(out).toContain('✓ add');
    expect(out).toContain('✗ evil  [BLOCK]');
    expect(out).toContain('tool-poisoning: hidden instructions in description at description');
    expect(out).toContain('✓ echo');
    expect(out).toContain('3 tool(s): 2 clean, 0 warn, 1 blocked');
    // No --pins: in-memory store, policy pin file untouched.
    expect(m.createPinStore).toHaveBeenCalledWith(undefined);
  });

  it('--json prints a machine-readable array only', async () => {
    const io = makeIo(ROOT, process.env);
    const code = await runCli(['scan', '--json', '--pins', 'tmp-pins.json', '--', process.execPath, SERVER], io);
    expect(code).toBe(2);
    const results = JSON.parse(io.out()) as Array<{ tool: string; action: string; blocked: boolean; serverId: string }>;
    expect(results.map((r) => [r.tool, r.action, r.blocked])).toEqual([
      ['add', 'allow', false],
      ['evil', 'block', true],
      ['echo', 'allow', false],
    ]);
    expect(results[0]?.serverId).toBe('paged-server');
    expect(m.createPinStore).toHaveBeenCalledWith(path.resolve(ROOT, 'tmp-pins.json'));
  });

  it('monitor mode still exits 2 for would-be blocks', async () => {
    m.mode = 'monitor';
    const io = makeIo(ROOT, process.env);
    expect(await runCli(['scan', '--', process.execPath, SERVER], io)).toBe(2);
    expect(io.out()).toContain('✗ evil  [WOULD BLOCK (monitor)]');
  });
});

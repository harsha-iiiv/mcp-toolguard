import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TOOLGUARD_VERSION, PolicyError } from '../../../src/contracts.js';
import type { Finding, ToolguardPolicy, InspectionTarget, ToolPin } from '../../../src/contracts.js';
import { makeIo } from './helpers.js';

// Sibling modules are stubbed so these tests do not depend on other agents' implementations.
const m = vi.hoisted(() => ({
  loadPolicy: vi.fn(),
  createPolicyEngine: vi.fn(),
  createDetector: vi.fn(),
  createPinStore: vi.fn(),
  createAuditLogger: vi.fn(),
  verifyAuditLog: vi.fn(),
  startProxy: vi.fn(),
}));

vi.mock('../../../src/policy/index.js', () => ({
  loadPolicy: m.loadPolicy,
  createPolicyEngine: m.createPolicyEngine,
  defaultPolicy: vi.fn(),
  validatePolicy: vi.fn(),
}));
vi.mock('../../../src/detection/index.js', () => ({
  createDetector: m.createDetector,
  createPinStore: m.createPinStore,
  builtinRules: vi.fn(),
  hashTool: vi.fn(),
}));
vi.mock('../../../src/audit/index.js', () => ({
  createAuditLogger: m.createAuditLogger,
  verifyAuditLog: m.verifyAuditLog,
  redactSecrets: vi.fn(),
  canonicalJson: vi.fn(),
}));
vi.mock('../../../src/proxy/index.js', () => ({ startProxy: m.startProxy }));

const { runCli } = await import('../../../src/cli/run-cli.js');

function testPolicy(): ToolguardPolicy {
  return {
    version: 1,
    mode: 'enforce',
    tools: { allow: [], deny: [], unlisted: 'block', unknown: 'warn' },
    severityActions: { low: 'allow', medium: 'warn', high: 'block', critical: 'block' },
    rules: {},
    arguments: [],
    pins: { file: '~/.mcp-toolguard/pins.json' },
    audit: { file: '~/.mcp-toolguard/audit.jsonl', redact: true, logAllowed: true },
    spend: { maxSpendPerTaskUsd: null, costs: {}, defaultCostUsd: 0 },
    approval: { tools: [], file: '' },
    learning: { enabled: false, file: '', minSamples: 50 },
    plugins: { enabled: false, dir: './toolguard-plugins' },
  };
}

function memoryPins(initial: ToolPin[] = []) {
  let pins = [...initial];
  return {
    get: (s: string, t: string) => pins.find((p) => p.serverId === s && p.toolName === t),
    set: (p: ToolPin) => {
      pins = pins.filter((x) => !(x.serverId === p.serverId && x.toolName === p.toolName)).concat(p);
    },
    list: (s?: string) => pins.filter((p) => s === undefined || p.serverId === s),
    reset: (s: string, t?: string) => {
      const before = pins.length;
      pins = pins.filter((p) => !(p.serverId === s && (t === undefined || p.toolName === t)));
      return before - pins.length;
    },
  };
}

/** Fake engine: blocks on critical findings, warns on medium, like the default policy. */
function fakeEngine(policy: ToolguardPolicy) {
  return {
    policy,
    disabledRules: () => ['hidden-unicode'],
    evaluate: (_t: InspectionTarget, findings: Finding[]) => {
      const block = findings.some((f) => f.severity === 'critical');
      const warn = findings.some((f) => f.severity === 'medium');
      const enforceAction = block ? 'block' : warn ? 'warn' : 'allow';
      const monitor = policy.mode === 'monitor' && enforceAction === 'block';
      return {
        action: monitor ? 'warn' : enforceAction,
        wouldBlock: monitor,
        reasons: findings.map((f) => `${f.ruleId}: ${f.message}`),
        findings,
      };
    },
  };
}

const CWD = '/work/project';

beforeEach(() => {
  vi.clearAllMocks();
  m.loadPolicy.mockImplementation((file?: string) => ({ policy: testPolicy(), source: file ?? 'builtin' }));
  m.createPolicyEngine.mockImplementation((p: ToolguardPolicy) => fakeEngine(p));
  m.createPinStore.mockImplementation(() => memoryPins());
  m.createDetector.mockImplementation(() => ({ rules: [], inspect: () => [] }));
  m.createAuditLogger.mockImplementation(() => ({ log: vi.fn(), close: vi.fn(async () => undefined) }));
});

describe('top level', () => {
  it('--version prints TOOLGUARD_VERSION', async () => {
    for (const flag of ['--version', '-v']) {
      const io = makeIo();
      expect(await runCli([flag], io)).toBe(0);
      expect(io.out()).toBe(`${TOOLGUARD_VERSION}\n`);
    }
  });

  it('--help prints usage covering every command', async () => {
    const io = makeIo();
    expect(await runCli(['--help'], io)).toBe(0);
    for (const cmd of ['run', 'scan', 'init', 'check-policy', 'verify-log', 'pins list|reset']) {
      expect(io.out()).toContain(`mcp-toolguard ${cmd}`);
    }
  });

  it('no arguments prints usage to stderr and exits 1', async () => {
    const io = makeIo();
    expect(await runCli([], io)).toBe(1);
    expect(io.err()).toContain('Usage:');
    expect(io.out()).toBe('');
  });

  it('unknown command is a usage error', async () => {
    const io = makeIo();
    expect(await runCli(['frobnicate'], io)).toBe(1);
    expect(io.err()).toContain("unknown command 'frobnicate'");
  });

  it('command --help prints that command usage', async () => {
    const io = makeIo();
    expect(await runCli(['scan', '--help'], io)).toBe(0);
    expect(io.out()).toContain('Usage: mcp-toolguard scan');
  });

  it('run --help writes to stderr only', async () => {
    const io = makeIo();
    expect(await runCli(['run', '--help'], io)).toBe(0);
    expect(io.out()).toBe('');
    expect(io.err()).toContain('Usage: mcp-toolguard run');
  });

  it('--help after -- belongs to the server command', async () => {
    m.startProxy.mockResolvedValue({ done: Promise.resolve(0), close: vi.fn(), hiddenTools: () => [] });
    const io = makeIo(CWD);
    expect(await runCli(['run', '--', 'server', '--help'], io)).toBe(0);
    expect(m.startProxy.mock.calls[0]?.[0].args).toEqual(['--help']);
  });
});

describe('run', () => {
  it('missing command is a usage error with exit 1', async () => {
    for (const argv of [['run'], ['run', '--monitor'], ['run', '--']]) {
      const io = makeIo();
      expect(await runCli(argv, io)).toBe(1);
      expect(io.err()).toContain('missing server command');
      expect(io.err()).toContain('Usage: mcp-toolguard run');
      expect(io.out()).toBe('');
    }
    expect(m.startProxy).not.toHaveBeenCalled();
  });

  it('unknown option is a usage error', async () => {
    const io = makeIo();
    expect(await runCli(['run', '--bogus', '--', 'x'], io)).toBe(1);
    expect(io.err()).toContain("unknown option '--bogus'");
  });

  it('wires policy, detector, audit and proxy; writes nothing to stdout', async () => {
    const close = vi.fn(async () => undefined);
    m.createAuditLogger.mockImplementation(() => ({ log: vi.fn(), close }));
    m.startProxy.mockResolvedValue({ done: Promise.resolve(7), close: vi.fn(), hiddenTools: () => [] });
    const io = makeIo(CWD, { PATH: '/bin', UNDEF: undefined });

    const code = await runCli(
      ['run', '--policy', 'p.yaml', '--audit', 'logs/a.jsonl', '--pins', '~/p.json', '--monitor', '--', '/opt/bin/fs-server.js', '/data', '--flag'],
      io,
    );

    expect(code).toBe(7);
    expect(io.out()).toBe('');
    expect(m.loadPolicy).toHaveBeenCalledWith(path.resolve(CWD, 'p.yaml'), CWD);
    const engineArg = m.createPolicyEngine.mock.calls[0]?.[0] as ToolguardPolicy;
    expect(engineArg.mode).toBe('monitor');
    expect(engineArg.audit.file).toBe(path.resolve(CWD, 'logs/a.jsonl'));
    expect(engineArg.pins.file).toBe('~/p.json');
    expect(m.createPinStore).toHaveBeenCalledWith('~/p.json');
    expect(m.createDetector.mock.calls[0]?.[0].disabledRules).toEqual(['hidden-unicode']);
    expect(m.createAuditLogger).toHaveBeenCalledWith({ file: path.resolve(CWD, 'logs/a.jsonl'), redact: true });

    const opts = m.startProxy.mock.calls[0]?.[0];
    expect(opts.serverId).toBe('fs-server');
    expect(opts.sessionId).toMatch(/^[0-9a-f-]{36}$/);
    expect(opts.command).toBe('/opt/bin/fs-server.js');
    expect(opts.args).toEqual(['/data', '--flag']);
    expect(opts.env).toEqual({ PATH: '/bin' });
    expect(opts.cwd).toBe(CWD);

    expect(io.err()).toContain(`policy: ${path.resolve(CWD, 'p.yaml')}`);
    expect(io.err()).toContain('mode:   monitor');
    expect(io.err()).toContain(`audit:  ${path.resolve(CWD, 'logs/a.jsonl')}`);
    expect(close).toHaveBeenCalled();
  });

  it('--server-id overrides the default; policy mode kept without --monitor', async () => {
    m.startProxy.mockResolvedValue({ done: Promise.resolve(0), close: vi.fn(), hiddenTools: () => [] });
    expect(await runCli(['run', '--server-id', 'files', '--', 'npx', '-y', 'pkg'], makeIo(CWD))).toBe(0);
    expect(m.startProxy.mock.calls[0]?.[0].serverId).toBe('files');
    expect((m.createPolicyEngine.mock.calls[0]?.[0] as ToolguardPolicy).mode).toBe('enforce');
    expect(m.loadPolicy).toHaveBeenCalledWith(undefined, CWD);
  });

  it('policy errors exit 1 and list issues on stderr', async () => {
    m.loadPolicy.mockImplementation(() => {
      throw new PolicyError('invalid policy', ['mode: expected enforce|monitor', 'tools.deny: expected array']);
    });
    const io = makeIo();
    expect(await runCli(['run', '--', 'x'], io)).toBe(1);
    expect(io.out()).toBe('');
    expect(io.err()).toContain('invalid policy');
    expect(io.err()).toContain('  - mode: expected enforce|monitor\n');
    expect(io.err()).toContain('  - tools.deny: expected array\n');
  });

  it('proxy start failure exits 1 and still closes the audit log', async () => {
    const close = vi.fn(async () => undefined);
    m.createAuditLogger.mockImplementation(() => ({ log: vi.fn(), close }));
    m.startProxy.mockRejectedValue(new Error('spawn ENOENT'));
    const io = makeIo();
    expect(await runCli(['run', '--', 'nope'], io)).toBe(1);
    expect(io.err()).toContain('spawn ENOENT');
    expect(io.out()).toBe('');
    expect(close).toHaveBeenCalled();
  });
});

describe('check-policy', () => {
  it('exit 0 for a valid policy', async () => {
    const io = makeIo(CWD);
    expect(await runCli(['check-policy', 'toolguard.yaml'], io)).toBe(0);
    expect(m.loadPolicy).toHaveBeenCalledWith(path.resolve(CWD, 'toolguard.yaml'), CWD);
    expect(io.out()).toContain('OK');
  });

  it('exit 1 with one issue per line for an invalid policy', async () => {
    m.loadPolicy.mockImplementation(() => {
      throw new PolicyError('toolguard.yaml: invalid policy', ['a: bad', 'b: worse']);
    });
    const io = makeIo();
    expect(await runCli(['check-policy', 'toolguard.yaml'], io)).toBe(1);
    expect(io.err()).toMatch(/INVALID.*invalid policy\n  - a: bad\n  - b: worse\n/);
  });

  it('exit 1 for a missing file argument', async () => {
    const io = makeIo();
    expect(await runCli(['check-policy'], io)).toBe(1);
    expect(io.err()).toContain('missing policy file');
  });

  it('exit 1 when loading throws a plain error', async () => {
    m.loadPolicy.mockImplementation(() => {
      throw new Error('ENOENT: no such file');
    });
    expect(await runCli(['check-policy', 'x.yaml'], makeIo())).toBe(1);
  });
});

describe('verify-log', () => {
  it('exit 0 when the chain is intact', async () => {
    m.verifyAuditLog.mockReturnValue({ ok: true, count: 12 });
    const io = makeIo(CWD);
    expect(await runCli(['verify-log', 'audit.jsonl'], io)).toBe(0);
    expect(m.verifyAuditLog).toHaveBeenCalledWith(path.resolve(CWD, 'audit.jsonl'));
    expect(io.out()).toContain('12 event(s)');
  });

  it('exit 1 when the chain is broken', async () => {
    m.verifyAuditLog.mockReturnValue({ ok: false, count: 3, brokenAt: 3, error: 'hash mismatch' });
    const io = makeIo();
    expect(await runCli(['verify-log', 'audit.jsonl'], io)).toBe(1);
    expect(io.out()).toContain('broken at seq 3: hash mismatch');
  });

  it('exit 1 when verification throws (e.g. missing file)', async () => {
    m.verifyAuditLog.mockImplementation(() => {
      throw new Error('ENOENT');
    });
    const io = makeIo();
    expect(await runCli(['verify-log', 'missing.jsonl'], io)).toBe(1);
    expect(io.err()).toContain('ENOENT');
  });

  it('exit 1 without a file argument', async () => {
    expect(await runCli(['verify-log'], makeIo())).toBe(1);
  });
});

describe('pins', () => {
  const pin = (serverId: string, toolName: string): ToolPin => ({
    serverId,
    toolName,
    hash: 'a'.repeat(64),
    description: 'd',
    firstSeen: '2026-01-01T00:00:00.000Z',
  });

  it('list uses --pins and filters by --server-id', async () => {
    m.createPinStore.mockImplementation(() => memoryPins([pin('fs', 'read'), pin('gh', 'issue')]));
    const io = makeIo(CWD);
    expect(await runCli(['pins', 'list', '--pins', 'p.json', '--server-id', 'fs'], io)).toBe(0);
    expect(m.createPinStore).toHaveBeenCalledWith(path.resolve(CWD, 'p.json'));
    expect(io.out()).toContain('read');
    expect(io.out()).not.toContain('issue');
  });

  it('list falls back to the policy pin file and supports --json', async () => {
    m.createPinStore.mockImplementation(() => memoryPins([pin('fs', 'read')]));
    const io = makeIo();
    expect(await runCli(['pins', 'list', '--json'], io)).toBe(0);
    expect(m.createPinStore).toHaveBeenCalledWith('~/.mcp-toolguard/pins.json');
    expect(JSON.parse(io.out())).toHaveLength(1);
  });

  it('reset removes one tool, one server, or everything', async () => {
    const store = memoryPins([pin('fs', 'read'), pin('fs', 'write'), pin('gh', 'issue')]);
    m.createPinStore.mockImplementation(() => store);
    let io = makeIo();
    expect(await runCli(['pins', 'reset', '--server-id', 'fs', '--tool', 'read'], io)).toBe(0);
    expect(io.out()).toContain('Removed 1 pin(s)');
    io = makeIo();
    expect(await runCli(['pins', 'reset'], io)).toBe(0);
    expect(io.out()).toContain('Removed 2 pin(s) for all servers');
    expect(store.list()).toHaveLength(0);
  });

  it('usage errors', async () => {
    for (const argv of [['pins'], ['pins', 'nuke'], ['pins', 'reset', '--tool', 'x']]) {
      const io = makeIo();
      expect(await runCli(argv, io)).toBe(1);
      expect(io.err()).toContain('Usage: mcp-toolguard pins');
    }
  });
});

describe('scan', () => {
  it('missing command is a usage error', async () => {
    const io = makeIo();
    expect(await runCli(['scan', '--json'], io)).toBe(1);
    expect(io.err()).toContain('missing server command');
  });

  it('spawn failure exits 1', async () => {
    const io = makeIo();
    expect(await runCli(['scan', '--', '/definitely/not/a/command-xyz'], io)).toBe(1);
    expect(io.err()).toContain('scan: error');
  });
});

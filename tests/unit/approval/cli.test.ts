import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApprovalStore } from '../../../src/approval/index.js';
import { runCli } from '../../../src/cli/run-cli.js';
import { defaultPolicy, validatePolicy, loadPolicy } from '../../../src/policy/index.js';
import { verifyAuditLog } from '../../../src/audit/index.js';
import { makeIo } from '../cli/helpers.js';

const ROOT = path.resolve(import.meta.dirname, '../../..');

let dir: string;
let policyFile: string;
let approvalsFile: string;
let auditFile: string;

function seed(n = 1): string[] {
  const store = createApprovalStore({ file: approvalsFile });
  const p = defaultPolicy();
  p.approval.tools = ['write_*'];
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const v = store.check({ kind: 'tool_call', requestId: i, toolName: 'write_file', arguments: { i }, serverId: 'fs', taskId: 't' }, p)!;
    ids.push(/approve ([0-9a-f]{6})/.exec(v.reason)![1]!);
  }
  return ids;
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpg-approval-cli-'));
  approvalsFile = path.join(dir, 'approvals.json');
  auditFile = path.join(dir, 'audit.jsonl');
  policyFile = path.join(dir, 'toolguard.yaml');
  fs.writeFileSync(policyFile, `version: 1\napproval:\n  tools: ["write_*"]\n  file: ${approvalsFile}\naudit:\n  file: ${auditFile}\n`);
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('mcp-toolguard approve / deny / approvals', () => {
  it('approve <id> → exit 0, request approved, audit event appended', async () => {
    const [id] = seed();
    const io = makeIo(dir);
    expect(await runCli(['approve', id!, '--policy', policyFile], io)).toBe(0);
    expect(io.out()).toContain(`Approved ${id}`);
    expect(createApprovalStore({ file: approvalsFile }).get(id!)?.status).toBe('approved');
    const events = fs.readFileSync(auditFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(events.at(-1)).toMatchObject({ kind: 'lifecycle', event: 'approval_granted', data: { id, toolName: 'write_file' } });
    expect(verifyAuditLog(auditFile).ok).toBe(true);
  });

  it('deny <id> → exit 0, request denied', async () => {
    const [id] = seed();
    const io = makeIo(dir);
    expect(await runCli(['deny', id!, '--policy', policyFile], io)).toBe(0);
    expect(io.out()).toContain(`Denied ${id}`);
    expect(createApprovalStore({ file: approvalsFile }).get(id!)?.status).toBe('denied');
    expect(fs.readFileSync(auditFile, 'utf8')).toContain('approval_denied');
  });

  it('uses ./toolguard.yaml from cwd when --policy is not given', async () => {
    const [id] = seed();
    expect(await runCli(['approve', id!], makeIo(dir))).toBe(0);
  });

  it('unknown id → exit 1 with a clear message', async () => {
    seed();
    for (const cmd of ['approve', 'deny']) {
      const io = makeIo(dir);
      expect(await runCli([cmd, 'abcdef', '--policy', policyFile], io)).toBe(1);
      expect(io.err()).toContain("no approval request with id 'abcdef'");
      expect(io.err()).toContain('approvals list');
    }
  });

  it('already decided → exit 1', async () => {
    const [id] = seed();
    expect(await runCli(['approve', id!, '--policy', policyFile], makeIo(dir))).toBe(0);
    const io = makeIo(dir);
    expect(await runCli(['deny', id!, '--policy', policyFile], io)).toBe(1);
    expect(io.err()).toContain('already approved');
  });

  it('missing id → usage error exit 1', async () => {
    const io = makeIo(dir);
    expect(await runCli(['approve'], io)).toBe(1);
    expect(io.err()).toContain('missing approval request id');
    expect(io.err()).toContain('Usage: mcp-toolguard approve');
  });

  it('approvals list: table, --status filter and --json', async () => {
    const [a, b] = seed(2);
    createApprovalStore({ file: approvalsFile }).approve(a!);

    let io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--policy', policyFile], io)).toBe(0);
    expect(io.out()).toContain(a!);
    expect(io.out()).toContain(b!);
    expect(io.out()).toContain('2 request(s)');

    io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--status', 'pending', '--json', '--policy', policyFile], io)).toBe(0);
    const rows = JSON.parse(io.out());
    expect(rows.map((r: { id: string }) => r.id)).toEqual([b]);
    expect(rows[0].status).toBe('pending');

    io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--status', 'denied', '--policy', policyFile], io)).toBe(0);
    expect(io.out()).toContain('No denied approval requests');
  });

  it('approvals list shows expired pending requests as expired', async () => {
    const [id] = seed();
    const raw = JSON.parse(fs.readFileSync(approvalsFile, 'utf8'));
    raw.requests[0].createdAt = new Date(Date.now() - 25 * 3600 * 1000).toISOString();
    fs.writeFileSync(approvalsFile, JSON.stringify(raw));
    let io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--status', 'expired', '--json', '--policy', policyFile], io)).toBe(0);
    expect(JSON.parse(io.out())).toMatchObject([{ id, status: 'expired' }]);
    io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--status', 'pending', '--json', '--policy', policyFile], io)).toBe(0);
    expect(JSON.parse(io.out())).toEqual([]);
    io = makeIo(dir);
    expect(await runCli(['approve', id!, '--policy', policyFile], io)).toBe(1);
    expect(io.err()).toContain('expired');
  });

  it('approvals: bad subcommand / status → exit 1; corrupt file → exit 1', async () => {
    expect(await runCli(['approvals'], makeIo(dir))).toBe(1);
    expect(await runCli(['approvals', 'show'], makeIo(dir))).toBe(1);
    expect(await runCli(['approvals', 'list', '--status', 'bogus', '--policy', policyFile], makeIo(dir))).toBe(1);
    fs.writeFileSync(approvalsFile, 'nope');
    const io = makeIo(dir);
    expect(await runCli(['approvals', 'list', '--policy', policyFile], io)).toBe(1);
    expect(io.err()).toContain('is corrupt');
  });

  it('help lists the new commands', async () => {
    const io = makeIo(dir);
    expect(await runCli(['--help'], io)).toBe(0);
    for (const c of ['approve <id>', 'deny <id>', 'approvals list']) expect(io.out()).toContain(c);
    const io2 = makeIo(dir);
    expect(await runCli(['help', 'approvals'], io2)).toBe(0);
    expect(io2.out()).toContain('--status');
  });

  it('honours MCP_TOOLGUARD_HOME for the default approvals file', () => {
    const prev = process.env.MCP_TOOLGUARD_HOME;
    process.env.MCP_TOOLGUARD_HOME = dir;
    try {
      const { policy } = loadPolicy(undefined, os.tmpdir());
      expect(policy.approval.file).toBe(path.join(dir, 'approvals.json'));
    } finally {
      if (prev === undefined) delete process.env.MCP_TOOLGUARD_HOME;
      else process.env.MCP_TOOLGUARD_HOME = prev;
    }
  });
});

describe('presets and client configs', () => {
  const presets = ['strict', 'balanced', 'permissive'];
  it.each(presets)('%s.yaml passes validatePolicy and check-policy', async (name) => {
    const file = path.join(ROOT, 'examples/presets', `${name}.yaml`);
    const { policy } = loadPolicy(file);
    expect(() => validatePolicy(JSON.parse(JSON.stringify(policy)))).not.toThrow();
    const io = makeIo(ROOT);
    expect(await runCli(['check-policy', file], io)).toBe(0);
  });

  it('presets have the intended semantics', () => {
    const load = (n: string) => loadPolicy(path.join(ROOT, 'examples/presets', `${n}.yaml`)).policy;
    const strict = load('strict');
    const balanced = load('balanced');
    for (const g of ['write_*', 'edit_*', '*_write', 'delete_*', 'move_*', 'create_*']) {
      expect(strict.tools.deny).toContain(g);
      expect(balanced.approval.tools).toContain(g);
    }
    expect(strict.approval.tools).toEqual([]);
    expect(balanced.tools.deny).toEqual([]);
    expect(balanced.mode).toBe('enforce');
    expect(load('permissive').mode).toBe('monitor');
  });

  it.each(['claude-code', 'cursor', 'vscode'])('%s.json is valid JSON with a stdio and an http wrap', (name) => {
    const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples/clients', `${name}.json`), 'utf8'));
    const servers = name === 'vscode' ? cfg.servers : cfg.mcpServers;
    expect(servers).toBeTypeOf('object');
    const entries = Object.values(servers) as { type?: string; command: string; args: string[] }[];
    // The configs must name the package users actually install (read from package.json so renames stay in sync).
    const pkgName = (JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as { name: string }).name;
    expect(entries.some((e) => e.args.join(' ').includes(`-y ${pkgName} run -- npx -y @modelcontextprotocol/server-filesystem`))).toBe(true);
    expect(entries.some((e) => e.args.join(' ').includes(`-y ${pkgName} run --transport http --url https://example.com/mcp`))).toBe(true);
    if (name === 'vscode') for (const e of entries) expect(e.type).toBe('stdio');
  });
});

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ApprovalStore, AuditEventInput, AuditLogger, AuditEvent, Policy, ToolCall } from '../../../src/contracts.js';
import { APPROVAL_TTL_MS, ApprovalError, createApprovalStore, globMatch, hashToolCall } from '../../../src/approval/index.js';
import { defaultPolicy } from '../../../src/policy/index.js';

function policyWith(tools: string[]): Policy {
  const p = defaultPolicy();
  p.approval.tools = tools;
  return p;
}

function call(toolName: string, args: Record<string, unknown> = { path: '/tmp/x', content: 'hi' }, serverId = 'fs'): ToolCall {
  return { kind: 'tool_call', requestId: 1, toolName, arguments: args, serverId, taskId: 't' };
}

function memAudit(): AuditLogger & { events: AuditEventInput[] } {
  const events: AuditEventInput[] = [];
  return {
    events,
    log: (e) => (events.push(e), { ...e, v: 1, seq: 0, ts: '', prevHash: '', hash: '' }) as AuditEvent,
    close: async () => {},
  };
}

const idFrom = (reason: string): string => /mcp-toolguard approve ([0-9a-f]{6})/.exec(reason)![1]!;

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpg-approval-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('globMatch', () => {
  it('anchors and supports * and ?', () => {
    expect(globMatch('write_*', 'write_file')).toBe(true);
    expect(globMatch('write_*', 'rewrite_file')).toBe(false);
    expect(globMatch('*_write', 'fs_write')).toBe(true);
    expect(globMatch('file?', 'file1')).toBe(true);
    expect(globMatch('file?', 'file12')).toBe(false);
    expect(globMatch('a.b', 'aXb')).toBe(false);
  });
});

describe('hashToolCall', () => {
  it('is key-order independent and covers server, tool and arguments', () => {
    const a = hashToolCall('s', 't', { a: 1, b: { c: 2, d: 3 } });
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToolCall('s', 't', { b: { d: 3, c: 2 }, a: 1 })).toBe(a);
    expect(hashToolCall('s2', 't', { a: 1, b: { c: 2, d: 3 } })).not.toBe(a);
    expect(hashToolCall('s', 't2', { a: 1, b: { c: 2, d: 3 } })).not.toBe(a);
    expect(hashToolCall('s', 't', { a: 2, b: { c: 2, d: 3 } })).not.toBe(a);
  });
});

describe.each([
  ['in-memory', () => undefined],
  ['file-backed', () => path.join(dir, 'nested', 'approvals.json')],
])('ApprovalStore (%s)', (_label, fileOf) => {
  let store: ApprovalStore;
  let audit: ReturnType<typeof memAudit>;
  const policy = policyWith(['write_*', 'delete_?']);
  beforeEach(() => {
    audit = memAudit();
    store = createApprovalStore({ file: fileOf(), audit });
  });

  it('ignores calls not matching approval.tools', () => {
    expect(store.check(call('read_file'), policy)).toBeNull();
    expect(store.check(call('delete_xy'), policy)).toBeNull();
    expect(store.list()).toEqual([]);
  });

  it('pending → approve → passes exactly once → pending again', () => {
    const v = store.check(call('write_file'), policy)!;
    expect(v.action).toBe('require_approval');
    expect(v.ruleId).toBe('approval');
    const id = idFrom(v.reason);
    expect(v.reason).toContain(`mcp-toolguard approve ${id}`);

    // Same call again: same pending request is reused.
    expect(idFrom(store.check(call('write_file'), policy)!.reason)).toBe(id);
    expect(store.list('pending')).toHaveLength(1);
    const req = store.list()[0]!;
    expect(req.toolCall).toMatchObject({ serverId: 'fs', toolName: 'write_file', hash: hashToolCall('fs', 'write_file', call('write_file').arguments) });

    // A different argument is a different request, and is not unlocked by approving the first.
    const other = idFrom(store.check(call('write_file', { path: '/etc/passwd' }), policy)!.reason);
    expect(other).not.toBe(id);

    expect(store.approve(id).status).toBe('approved');
    expect(store.check(call('write_file', { path: '/etc/passwd' }), policy)?.action).toBe('require_approval');
    expect(store.check(call('write_file'), policy)).toBeNull();
    expect(store.list('used').map((r) => r.id)).toEqual([id]);

    const again = store.check(call('write_file'), policy)!;
    expect(again.action).toBe('require_approval');
    expect(idFrom(again.reason)).not.toBe(id);

    expect(audit.events.map((e) => e.event)).toEqual([
      'approval_requested',
      'approval_requested',
      'approval_granted',
      'approval_used',
      'approval_requested',
    ]);
    expect(audit.events[2]).toMatchObject({ kind: 'lifecycle', serverId: 'fs', toolName: 'write_file', data: { id, toolName: 'write_file' } });
  });

  it('deny: the call stays blocked and a later identical call creates a new request', () => {
    const id = idFrom(store.check(call('write_file'), policy)!.reason);
    const r = store.deny(id);
    expect(r.status).toBe('denied');
    expect(r.decidedAt).toBeDefined();
    const v = store.check(call('write_file'), policy)!;
    expect(v.action).toBe('require_approval');
    expect(idFrom(v.reason)).not.toBe(id);
    expect(audit.events.map((e) => e.event)).toContain('approval_denied');
  });

  it('unknown id and double decisions throw clear ApprovalErrors', () => {
    expect(() => store.approve('ffffff')).toThrow(/no approval request with id 'ffffff'/);
    const id = idFrom(store.check(call('write_file'), policy)!.reason);
    store.approve(id);
    expect(() => store.deny(id)).toThrow(/already approved/);
    try {
      store.approve('nope');
    } catch (err) {
      expect(err).toBeInstanceOf(ApprovalError);
      expect((err as ApprovalError).code).toBe('not_found');
    }
  });

  it('ids are 6 hex chars and unique', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) ids.add(idFrom(store.check(call('write_file', { i }), policy)!.reason));
    expect(ids.size).toBe(50);
    for (const id of ids) expect(id).toMatch(/^[0-9a-f]{6}$/);
  });
});

describe('expiry', () => {
  it('pending requests older than 24h are ignored and cannot be approved', () => {
    let t = Date.parse('2026-11-03T00:00:00Z');
    const store = createApprovalStore({ file: path.join(dir, 'a.json'), now: () => t });
    const policy = policyWith(['write_file']);
    const id = idFrom(store.check(call('write_file'), policy)!.reason);
    t += APPROVAL_TTL_MS - 1000;
    expect(store.isExpired(store.get(id)!)).toBe(false);
    expect(idFrom(store.check(call('write_file'), policy)!.reason)).toBe(id);
    t += 2000;
    expect(store.isExpired(store.get(id)!)).toBe(true);
    expect(() => store.approve(id)).toThrow(/expired/);
    const fresh = idFrom(store.check(call('write_file'), policy)!.reason);
    expect(fresh).not.toBe(id);
    expect(store.list('pending').map((r) => r.id).sort()).toEqual([id, fresh].sort());
  });
});

describe('file store across processes', () => {
  it('two store instances on one file see each other (proxy + approve CLI)', () => {
    const file = path.join(dir, 'approvals.json');
    const proxySide = createApprovalStore({ file });
    const cliSide = createApprovalStore({ file });
    const policy = policyWith(['write_file']);

    const id = idFrom(proxySide.check(call('write_file'), policy)!.reason);
    expect(cliSide.list('pending').map((r) => r.id)).toEqual([id]);
    cliSide.approve(id);
    expect(proxySide.check(call('write_file'), policy)).toBeNull();
    expect(cliSide.get(id)?.status).toBe('used');
    expect(proxySide.check(call('write_file'), policy)?.action).toBe('require_approval');

    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(raw.version).toBe(1);
    expect(raw.requests).toHaveLength(2);
    if (process.platform !== 'win32') expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });

  it('corrupt file → clear error (the proxy then fails closed)', () => {
    const file = path.join(dir, 'approvals.json');
    fs.writeFileSync(file, '{not json');
    const store = createApprovalStore({ file });
    expect(() => store.check(call('write_file'), policyWith(['write_file']))).toThrow(/Approval file .* is corrupt \(invalid JSON/);
    expect(() => store.list()).toThrow(/corrupt/);
    fs.writeFileSync(file, JSON.stringify({ version: 1, requests: [{ id: 'x' }] }));
    expect(() => store.list()).toThrow(/requests\[0\] is not a valid approval request/);
    fs.writeFileSync(file, JSON.stringify({ version: 2, requests: [] }));
    expect(() => store.list()).toThrow(/expected \{"version": 1/);
  });

  it("expands '~' in the file path", () => {
    const store = createApprovalStore({ file: '~/.mcpg-test-does-not-exist/approvals.json' });
    expect(store.file).toBe(path.join(os.homedir(), '.mcpg-test-does-not-exist/approvals.json'));
    expect(store.list()).toEqual([]);
  });
});

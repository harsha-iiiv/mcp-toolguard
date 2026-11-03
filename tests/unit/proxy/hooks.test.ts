// Proxy hooks (RulePlugin, ApprovalStore).
import { afterEach, describe, expect, it } from 'vitest';
import {
  APPROVAL_MARKER,
  BLOCK_MARKER,
  type ApprovalRequest,
  type ApprovalStore,
  type RulePlugin,
  type ToolCall,
  type Verdict,
} from '../../../src/contracts.js';
import { createHarness, type Harness } from './helpers.js';

const TOOLS = [
  { name: 'read_file', description: 'Reads a file.' },
  { name: 'write_file', description: 'Writes a file.' },
];

function text(r: unknown): string {
  return String((r as { content: { text: string }[] }).content[0]?.text ?? '');
}

let h: Harness | undefined;
afterEach(async () => {
  await h?.handle.close();
  h = undefined;
});

/** Minimal in-memory approval store with the contract's semantics. */
function memoryApprovals(globs: string[]): ApprovalStore & { requests: ApprovalRequest[] } {
  const requests: ApprovalRequest[] = [];
  const key = (c: ToolCall) => `${c.serverId}|${c.toolName}|${JSON.stringify(c.arguments)}`;
  return {
    requests,
    check(call) {
      if (!globs.includes(call.toolName)) return null;
      const approved = requests.find((r) => r.toolCall.hash === key(call) && r.status === 'approved');
      if (approved) {
        approved.status = 'used';
        return null;
      }
      let pending = requests.find((r) => r.toolCall.hash === key(call) && r.status === 'pending');
      if (!pending) {
        pending = {
          id: `a${requests.length + 1}`,
          toolCall: { serverId: call.serverId, toolName: call.toolName, arguments: call.arguments, hash: key(call) },
          reason: 'needs approval',
          status: 'pending',
          createdAt: new Date().toISOString(),
        };
        requests.push(pending);
      }
      return { action: 'require_approval', ruleId: 'approval', reason: `run: mcp-toolguard approve ${pending.id}` };
    },
    approve(id) {
      const r = requests.find((x) => x.id === id)!;
      r.status = 'approved';
      return r;
    },
    deny(id) {
      const r = requests.find((x) => x.id === id)!;
      r.status = 'denied';
      return r;
    },
    list: (status) => requests.filter((r) => !status || r.status === status),
  };
}

describe('proxy v0.2 hooks', () => {
  it('passes ToolCall (with serverId, taskId) and the result to plugins', async () => {
    const seen: { call: ToolCall; hasResult: boolean }[] = [];
    const spy: RulePlugin = { id: 'spy', check: (call, result) => (seen.push({ call, hasResult: !!result }), null) };
    h = await createHarness(TOOLS, { plugins: [spy] });
    await h.client.listTools();
    await h.client.callTool({ name: 'read_file', arguments: { text: 'a' }, _meta: { taskId: 'task-42' } });
    await h.client.callTool({ name: 'read_file', arguments: { text: 'b' } });
    expect(seen.map((s) => [s.call.taskId, s.hasResult])).toEqual([
      ['task-42', false],
      ['task-42', true],
      ['sess-1', false],
      ['sess-1', true],
    ]);
    expect(seen[0]!.call.serverId).toBe('test-server');
  });

  it('a plugin block verdict stops the call before the server', async () => {
    const deny: RulePlugin = {
      id: 'no-writes',
      check: (call) => (call.toolName === 'write_file' ? { action: 'block', reason: 'writes disabled', ruleId: 'no-writes' } : null),
    };
    h = await createHarness(TOOLS, { plugins: [deny] });
    await h.client.listTools();
    const r = await h.client.callTool({ name: 'write_file', arguments: { text: 'x' } });
    expect(text(r)).toBe(`${BLOCK_MARKER}: no-writes: writes disabled`);
    expect(h.serverCalls).toEqual([]);
    const ev = h.audit.events.find((e) => e.kind === 'tool_call');
    expect(ev?.action).toBe('block');
    expect(ev?.findings?.[0]?.ruleId).toBe('no-writes');
  });

  it('a plugin can block a result', async () => {
    const p: RulePlugin = { id: 'r', check: (_c, result) => (result ? { action: 'block', reason: 'bad result', ruleId: 'r' } : null) };
    h = await createHarness(TOOLS, { plugins: [p] });
    await h.client.listTools();
    const r = await h.client.callTool({ name: 'read_file', arguments: {} });
    expect(text(r)).toContain('bad result');
    expect(h.serverCalls).toHaveLength(1);
  });

  it('a throwing plugin fails closed', async () => {
    const p: RulePlugin = { id: 'boom', check: () => { throw new Error('x'); } };
    h = await createHarness(TOOLS, { plugins: [p] });
    await h.client.listTools();
    const r = await h.client.callTool({ name: 'read_file', arguments: {} });
    expect(text(r)).toContain('boom: internal error');
    expect(h.serverCalls).toEqual([]);
  });

  it('warn verdicts forward and are audited', async () => {
    const p: RulePlugin = { id: 'learning', check: (c, r) => (!r ? { action: 'warn', reason: 'unusual tool', ruleId: 'learning' } : null) };
    h = await createHarness(TOOLS, { plugins: [p] });
    await h.client.listTools();
    const r = await h.client.callTool({ name: 'read_file', arguments: {} });
    expect(text(r)).toBe('ok:read_file');
    expect(h.audit.events.find((e) => e.kind === 'tool_call')?.action).toBe('warn');
  });

  it('approval: pending → APPROVAL_MARKER, approve → passes once, then needs approval again', async () => {
    const approvals = memoryApprovals(['write_file']);
    h = await createHarness(TOOLS, { approvals });
    await h.client.listTools();
    const args = { text: 'hello' };
    const first = await h.client.callTool({ name: 'write_file', arguments: args });
    expect(text(first)).toBe(`${APPROVAL_MARKER}: approval: run: mcp-toolguard approve a1`);
    expect(h.serverCalls).toEqual([]);
    approvals.approve('a1');
    expect(text(await h.client.callTool({ name: 'write_file', arguments: args }))).toBe('ok:write_file');
    expect(text(await h.client.callTool({ name: 'write_file', arguments: args }))).toContain(APPROVAL_MARKER);
    expect(h.serverCalls).toHaveLength(1);
    expect(text(await h.client.callTool({ name: 'read_file', arguments: {} }))).toBe('ok:read_file');
  });

  it('monitor mode downgrades block and require_approval to warn', async () => {
    const block: RulePlugin = { id: 'b', check: (c, r): Verdict | null => (!r ? { action: 'block', reason: 'no', ruleId: 'b' } : null) };
    h = await createHarness(TOOLS, { plugins: [block], approvals: memoryApprovals(['write_file']) });
    h.policy.policy.mode = 'monitor';
    await h.client.listTools();
    expect(text(await h.client.callTool({ name: 'write_file', arguments: {} }))).toBe('ok:write_file');
    const ev = h.audit.events.find((e) => e.kind === 'tool_call');
    expect(ev?.action).toBe('warn');
    expect(ev?.wouldBlock).toBe(true);
  });

  it('no hooks: behaviour unchanged', async () => {
    h = await createHarness(TOOLS);
    await h.client.listTools();
    expect(text(await h.client.callTool({ name: 'write_file', arguments: {} }))).toBe('ok:write_file');
  });
});

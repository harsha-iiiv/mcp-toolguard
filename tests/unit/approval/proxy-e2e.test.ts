// End-to-end: REAL startProxy + policy engine + detector + createApprovalStore + the balanced preset,
// over InMemoryTransport, with an SDK McpServer exposing write_file.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { z } from 'zod';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { APPROVAL_MARKER, type ProxyHandle } from '../../../src/contracts.js';
import { createApprovalStore } from '../../../src/approval/index.js';
import { createAuditLogger } from '../../../src/audit/index.js';
import { createDetector, createPinStore } from '../../../src/detection/index.js';
import { createPolicyEngine, loadPolicy } from '../../../src/policy/index.js';
import { startProxy } from '../../../src/proxy/index.js';

const ROOT = path.resolve(import.meta.dirname, '../../..');

function text(r: unknown): string {
  return ((r as { content: { text?: string }[] }).content ?? []).map((c) => c.text ?? '').join('');
}

let dir: string;
let handle: ProxyHandle | undefined;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpg-approval-e2e-'));
});
afterEach(async () => {
  await handle?.close();
  handle = undefined;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('approval end-to-end with the balanced preset', () => {
  it('write_file needs approval, passes exactly once after approve, never reaches the server before', async () => {
    const { policy } = loadPolicy(path.join(ROOT, 'examples/presets/balanced.yaml'));
    policy.approval.file = path.join(dir, 'approvals.json');
    policy.audit.file = path.join(dir, 'audit.jsonl');
    policy.pins.file = path.join(dir, 'pins.json');

    const serverCalls: { name: string; args: unknown }[] = [];
    const server = new McpServer({ name: 'fs', version: '1.0.0' });
    for (const name of ['write_file', 'read_file']) {
      server.registerTool(
        name,
        { description: `${name === 'write_file' ? 'Writes' : 'Reads'} a file.`, inputSchema: { path: z.string(), content: z.string().optional() } },
        async (args) => {
          serverCalls.push({ name, args });
          return { content: [{ type: 'text', text: `ok:${name}` }] };
        },
      );
    }
    const [clientT, proxyClientT] = InMemoryTransport.createLinkedPair();
    const [proxyServerT, serverT] = InMemoryTransport.createLinkedPair();
    await server.connect(serverT);

    const engine = createPolicyEngine(policy);
    const audit = createAuditLogger({ file: policy.audit.file, stderr: false });
    const proxyStore = createApprovalStore({ file: policy.approval.file, audit, serverIdForAudit: 'fs' });
    handle = await startProxy({
      serverId: 'fs',
      sessionId: 'sess',
      policy: engine,
      detector: createDetector({ pins: createPinStore(policy.pins.file), disabledRules: engine.disabledRules() }),
      audit,
      transports: { client: proxyClientT, server: proxyServerT },
      approvals: proxyStore,
    });
    const client = new Client({ name: 'c', version: '1.0.0' });
    await client.connect(clientT);
    await client.listTools();

    const args = { path: '/tmp/notes.txt', content: 'hello' };
    const first = await client.callTool({ name: 'write_file', arguments: args });
    expect(first.isError).toBe(true);
    expect(text(first).startsWith(APPROVAL_MARKER)).toBe(true);
    const id = /mcp-toolguard approve ([0-9a-f]{6})/.exec(text(first))![1]!;
    expect(serverCalls).toEqual([]);

    // Reads are unaffected.
    expect(text(await client.callTool({ name: 'read_file', arguments: { path: '/tmp/notes.txt' } }))).toBe('ok:read_file');

    // Approve from "another process": a separate store instance on the same file.
    createApprovalStore({ file: policy.approval.file }).approve(id);

    expect(text(await client.callTool({ name: 'write_file', arguments: args }))).toBe('ok:write_file');
    expect(serverCalls.filter((c) => c.name === 'write_file')).toHaveLength(1);

    const third = await client.callTool({ name: 'write_file', arguments: args });
    expect(text(third)).toContain(APPROVAL_MARKER);
    expect(serverCalls.filter((c) => c.name === 'write_file')).toHaveLength(1);

    await client.close();
    const events = fs.readFileSync(policy.audit.file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const lifecycle = events.filter((e) => typeof e.event === 'string' && e.event.startsWith('approval_')).map((e) => e.event);
    expect(lifecycle).toEqual(['approval_requested', 'approval_used', 'approval_requested']);
  });
});

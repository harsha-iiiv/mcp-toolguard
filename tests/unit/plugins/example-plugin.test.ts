// The shipped example plugins load from examples/plugins and work with the REAL proxy, detector,
// policy engine and audit logger (SDK Client ⇄ proxy ⇄ SDK McpServer over InMemoryTransport).
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { z } from 'zod';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BLOCK_MARKER,
  createAuditLogger,
  createDetector,
  createPinStore,
  createPolicyEngine,
  defaultPolicy,
  loadPlugin,
  loadPlugins,
  startProxy,
  type ProxyHandle,
  type RulePlugin,
} from '../../../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const examplesDir = join(here, '..', '..', '..', 'examples', 'plugins');

function textOf(r: unknown): string {
  return ((r as { content?: { text?: string }[] }).content ?? []).map((c) => c.text ?? '').join('');
}

let cleanup: (() => Promise<void>) | undefined;
afterEach(async () => {
  await cleanup?.();
  cleanup = undefined;
});

async function setup(plugins: RulePlugin[], reply = (name: string) => `ok:${name}`) {
  const serverCalls: string[] = [];
  const server = new McpServer({ name: 'upstream', version: '1.0.0' });
  server.registerTool(
    'delete_production_database',
    { description: 'Deletes the production database.', inputSchema: { confirm: z.boolean().optional() } },
    async () => {
      serverCalls.push('delete_production_database');
      return { content: [{ type: 'text', text: reply('delete_production_database') }] };
    },
  );
  server.registerTool(
    'read_file',
    { description: 'Reads a text file from the project.', inputSchema: { path: z.string() } },
    async () => {
      serverCalls.push('read_file');
      return { content: [{ type: 'text', text: reply('read_file') }] };
    },
  );

  const [clientT, proxyClientSide] = InMemoryTransport.createLinkedPair();
  const [proxyServerSide, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);

  const policy = createPolicyEngine(defaultPolicy());
  const audit = createAuditLogger({ stderr: false });
  const handle: ProxyHandle = await startProxy({
    serverId: 'example',
    sessionId: 'sess',
    policy,
    detector: createDetector({ pins: createPinStore(), disabledRules: policy.disabledRules() }),
    audit,
    transports: { client: proxyClientSide, server: proxyServerSide },
    plugins,
  });
  const client = new Client({ name: 'c', version: '1.0.0' });
  await client.connect(clientT);
  cleanup = async () => {
    await client.close().catch(() => {});
    await handle.close();
    await server.close().catch(() => {});
  };
  return { client, serverCalls, audit };
}

describe('examples/plugins/block-tool.mjs', () => {
  it('loads from examples/plugins', async () => {
    const plugins = await loadPlugins(examplesDir);
    expect(plugins.map((p) => p.id)).toEqual(['block-tool', 'warn-large-result']);
    const p = await loadPlugin(join(examplesDir, 'block-tool.mjs'));
    expect(p.id).toBe('block-tool');
  });

  it('blocks the custom tool before the server sees it and lets read_file through', async () => {
    const plugin = await loadPlugin(join(examplesDir, 'block-tool.mjs'));
    const { client, serverCalls, audit } = await setup([plugin]);
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual(['delete_production_database', 'read_file']);

    const blocked = await client.callTool({ name: 'delete_production_database', arguments: { confirm: true } });
    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toBe(
      `${BLOCK_MARKER}: block-tool: tool 'delete_production_database' is on the block list (MCP_TOOLGUARD_BLOCK_TOOLS)`,
    );
    expect(serverCalls).toEqual([]);

    const ok = await client.callTool({ name: 'read_file', arguments: { path: 'README.md' } });
    expect(ok.isError).toBeFalsy();
    expect(textOf(ok)).toBe('ok:read_file');
    expect(serverCalls).toEqual(['read_file']);

    const ev = audit.events().find((e) => e.kind === 'tool_call' && e.toolName === 'delete_production_database');
    expect(ev?.action).toBe('block');
    expect(ev?.findings?.some((f) => f.ruleId === 'block-tool' && f.severity === 'high')).toBe(true);
  });
});

describe('examples/plugins/warn-large-result.mjs', () => {
  it('warns on large results but forwards them', async () => {
    const plugin = await loadPlugin(join(examplesDir, 'warn-large-result.mjs'));
    const big = 'a'.repeat(60_000);
    const { client, audit } = await setup([plugin], () => big);
    await client.listTools();
    const r = await client.callTool({ name: 'read_file', arguments: { path: 'big.txt' } });
    expect(textOf(r)).toBe(big);
    const ev = audit.events().find((e) => e.kind === 'tool_result');
    expect(ev?.action).toBe('warn');
    expect(ev?.reasons?.[0]).toMatch(/^warn-large-result: result of 'read_file' is 60000 chars/);
  });
});

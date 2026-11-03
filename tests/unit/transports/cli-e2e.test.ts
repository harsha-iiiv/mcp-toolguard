// `mcp-toolguard run --transport http|sse --url ...` end to end through the BUILT dist/cli/main.js
// (built by tests/e2e/global-setup.ts). The MCP client talks to the CLI over stdio, as a real host would.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { BLOCK_MARKER } from '../../../src/contracts.js';
import { startHttpServer, startSseServer, textOf, type RemoteServer } from './servers.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');

let dir: string;
let env: Record<string, string>;
let remote: RemoteServer | undefined;
let client: Client | undefined;
let stderr = '';

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'toolguard-transport-e2e-'));
  mkdirSync(join(dir, 'home'));
  env = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
  env.MCP_TOOLGUARD_HOME = join(dir, 'home');
  stderr = '';
});
afterEach(async () => {
  await client?.close().catch(() => {});
  client = undefined;
  await remote?.close();
  remote = undefined;
  rmSync(dir, { recursive: true, force: true });
});

async function connect(args: string[]): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [CLI, 'run', '--audit', join(dir, 'audit.jsonl'), '--pins', join(dir, 'pins.json'), ...args],
    env,
    cwd: dir,
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (c: Buffer) => (stderr += c.toString()));
  const c = new Client({ name: 'transport-e2e', version: '0.0.0' });
  await c.connect(transport);
  return c;
}

describe('e2e: run --transport http|sse', () => {
  it('http: hides the poisoned tool, forwards clean calls, sends headers, audits under the URL host', async () => {
    remote = await startHttpServer();
    const host = new URL(remote.url).host;
    client = await connect(['--transport', 'http', '--url', remote.url, '--header', 'Authorization: Bearer e2e-token']);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('add');
    expect(names).toContain('multiply');
    expect(textOf(await client.callTool({ name: 'multiply', arguments: { a: 6, b: 7 } }))).toBe('42');
    expect(textOf(await client.callTool({ name: 'add', arguments: { a: 1, b: 2 } }))).toContain(BLOCK_MARKER);
    expect(remote.log.calls.map((c) => c.name)).toEqual(['multiply']);
    expect(remote.log.headers.every((h) => h.authorization === 'Bearer e2e-token')).toBe(true);
    expect(stderr).toContain(`guarding '${host}' (http ${remote.url})`);
    expect(stderr).not.toContain('e2e-token');
    const audit = readFileSync(join(dir, 'audit.jsonl'), 'utf8');
    expect(audit).toContain(`"serverId":"${host}"`);
    expect(audit).not.toContain('e2e-token');
  });

  it('sse: hides the poisoned tool', async () => {
    remote = await startSseServer();
    client = await connect(['--transport', 'sse', '--url', remote.url]);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(['multiply', 'brave_web_search']);
    expect(textOf(await client.callTool({ name: 'multiply', arguments: { a: 3, b: 3 } }))).toBe('9');
  });

  it('http: spend cap from the policy file blocks at the cap', async () => {
    remote = await startHttpServer({ clean: true });
    const policyFile = join(dir, 'toolguard.yaml');
    writeFileSync(policyFile, 'version: 1\nspend:\n  maxSpendPerTaskUsd: 0.02\n  costs:\n    "brave_*": 0.01\n');
    client = await connect(['--policy', policyFile, '--transport', 'http', '--url', remote.url]);
    await client.listTools();
    const q = () => client!.callTool({ name: 'brave_web_search', arguments: { query: 'x' } });
    expect(textOf(await q())).toBe('results for x');
    expect(textOf(await q())).toBe('results for x');
    expect(textOf(await q())).toContain('would exceed cap $0.02');
    expect(remote.log.calls).toHaveLength(2);
    expect(stderr).toContain('spend:  cap $0.02 per task');
  });

  it('usage errors exit 1 with nothing on stdout', () => {
    for (const args of [
      ['--transport', 'http'],
      ['--transport', 'http', '--url', 'http://127.0.0.1:1/mcp', '--', 'node', 'x.js'],
      ['--transport', 'carrier-pigeon', '--url', 'http://x'],
    ]) {
      const r = spawnSync(process.execPath, [CLI, 'run', ...args], { cwd: dir, env, encoding: 'utf8', timeout: 15_000 });
      expect(r.status).toBe(1);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain('Usage: mcp-toolguard run');
    }
  });
});

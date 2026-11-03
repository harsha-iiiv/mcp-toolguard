// E2E helpers: spawn the BUILT CLI (dist/cli/main.js) the way a real MCP host would.
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { BLOCK_MARKER } from '../../src/contracts.js';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const CLI = join(ROOT, 'dist', 'cli', 'main.js');
export const SERVERS = join(ROOT, 'examples', 'attacks', 'servers');
export const FIXTURES = join(ROOT, 'tests', 'fixtures');
export const server = (name: string) => join(SERVERS, name);

export interface Sandbox {
  dir: string;
  /** MCP_TOOLGUARD_HOME for every spawned process. */
  home: string;
  audit: string;
  pins: string;
  env: Record<string, string>;
  cleanup(): void;
}

/** Temp dir that holds home, audit and pins; spawned processes also use it as cwd (no stray toolguard.yaml). */
export function makeSandbox(): Sandbox {
  const dir = mkdtempSync(join(tmpdir(), 'toolguard-e2e-'));
  const home = join(dir, 'home');
  mkdirSync(home);
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
  env.MCP_TOOLGUARD_HOME = home;
  return {
    dir,
    home,
    audit: join(dir, 'audit.jsonl'),
    pins: join(dir, 'pins.json'),
    env,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Run the CLI synchronously (scan, check-policy, verify-log, ...). */
export function runCli(sb: Sandbox, args: string[], extraEnv: Record<string, string> = {}): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: sb.dir,
    env: { ...sb.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 15_000,
  });
}

export interface GuardedClient {
  client: Client;
  stderr(): string;
  listChangedCount(): number;
  listToolNames(): Promise<string[]>;
  call(name: string, args?: Record<string, unknown>): Promise<{ text: string; isError: boolean; blocked: boolean }>;
  close(): Promise<void>;
}

/** Spawn `mcp-toolguard run --audit --pins [flags] -- node <serverFile>` and connect an SDK client to it. */
export async function connectGuarded(
  sb: Sandbox,
  serverFile: string,
  opts: { flags?: string[]; env?: Record<string, string> } = {},
): Promise<GuardedClient> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [CLI, 'run', '--audit', sb.audit, '--pins', sb.pins, ...(opts.flags ?? []), '--', process.execPath, serverFile],
    env: { ...sb.env, ...(opts.env ?? {}) },
    cwd: sb.dir,
    stderr: 'pipe',
  });
  let stderr = '';
  transport.stderr?.on('data', (c: Buffer) => {
    stderr += c.toString();
  });
  const client = new Client({ name: 'e2e-client', version: '0.0.0' });
  let listChanged = 0;
  client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChanged++;
  });
  await client.connect(transport);
  return {
    client,
    stderr: () => stderr,
    listChangedCount: () => listChanged,
    async listToolNames() {
      return (await client.listTools()).tools.map((t) => t.name);
    },
    async call(name, args = {}) {
      const res = await client.callTool({ name, arguments: args });
      const text = ((res.content ?? []) as Array<{ type: string; text?: string }>)
        .filter((c) => c.type === 'text')
        .map((c) => c.text ?? '')
        .join('\n');
      return { text, isError: Boolean(res.isError), blocked: text.startsWith(BLOCK_MARKER) };
    },
    async close() {
      await client.close().catch(() => {});
    },
  };
}

export async function waitFor(pred: () => boolean, timeoutMs = 5000, what = 'condition'): Promise<void> {
  const start = Date.now();
  while (!pred()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

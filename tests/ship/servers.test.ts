// Ship check: `mcp-toolguard scan` against real npm MCP servers. Skipped unless they are installed, so
// `npm test` stays green offline and in CI.
//
// To run it:
//   mkdir /tmp/mcp-servers && cd /tmp/mcp-servers && npm init -y && npm install \
//     @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory \
//     @modelcontextprotocol/server-github mcp-server-sqlite-npx
//   MCP_TOOLGUARD_SHIP_SERVERS=/tmp/mcp-servers npm test -- tests/ship
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const SERVERS_DIR = process.env.MCP_TOOLGUARD_SHIP_SERVERS;
const bin = (name: string) => (SERVERS_DIR ? join(SERVERS_DIR, 'node_modules', '.bin', name) : '');
const installed = (name: string) => Boolean(SERVERS_DIR) && existsSync(bin(name));

const sandbox = mkdtempSync(join(tmpdir(), 'toolguard-ship-'));
afterAll(() => rmSync(sandbox, { recursive: true, force: true }));

interface ScanRow {
  tool: string;
  action: 'allow' | 'warn' | 'block';
  blocked: boolean;
}

function scan(command: string, args: string[], env: Record<string, string> = {}): { code: number | null; rows: ScanRow[]; stderr: string } {
  const res = spawnSync(process.execPath, [CLI, 'scan', '--json', '--', command, ...args], {
    cwd: sandbox,
    env: { ...process.env, MCP_TOOLGUARD_HOME: join(sandbox, 'home'), ...env },
    encoding: 'utf8',
    timeout: 60_000,
  });
  const rows = res.stdout.trim() ? (JSON.parse(res.stdout) as ScanRow[]) : [];
  return { code: res.status, rows, stderr: res.stderr };
}

// Tool counts observed on 2026-11-03. Upstream servers may add tools, so these are minimums.
const CASES = [
  { bin: 'mcp-server-filesystem', args: () => [sandbox], minTools: 14 },
  { bin: 'mcp-server-memory', args: () => [], minTools: 9, env: () => ({ MEMORY_FILE_PATH: join(sandbox, 'memory.jsonl') }) },
  // A dummy token is enough for tools/list; no GitHub API call is made by scan.
  { bin: 'mcp-server-github', args: () => [], minTools: 26, env: () => ({ GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_dummy_token_for_tools_list_only' }) },
  { bin: 'mcp-server-sqlite-npx', args: () => [join(sandbox, 'ship.db')], minTools: 5 },
];

describe('ship check: scan real MCP servers', () => {
  for (const c of CASES) {
    it.skipIf(!installed(c.bin))(`${c.bin}: every tool is clean (exit 0)`, () => {
      const { code, rows, stderr } = scan(bin(c.bin), c.args(), c.env?.() ?? {});
      expect(code, stderr).toBe(0);
      expect(rows.length).toBeGreaterThanOrEqual(c.minTools);
      expect(rows.filter((r) => r.action !== 'allow').map((r) => r.tool)).toEqual([]);
    });
  }
});

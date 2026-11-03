#!/usr/bin/env node
// Ship check: drive a short `mcp-toolguard run` session against a real MCP server and report what
// mcp-toolguard did (tools hidden, calls blocked or warned). Used to look for false positives.
//
// Usage:
//   node tests/ship/session.mjs --calls <calls.json> [--audit <file>] [--pins <file>] [--server-id <id>]
//        [--monitor] [--direct] -- <server command> [args...]
//
// calls.json: [{ "tool": "read_file", "arguments": { "path": "${SHIP_ROOT}/x" } }, ...]
// --direct connects to the server without mcp-toolguard (baseline).
//
// Prints one JSON object to stdout:
//   { serverId, tools: [names seen by the client], calls: [{ tool, isError, blocked, text }],
//     audit: [{ kind, toolName, action, wouldBlock, reasons }] (non-allow events only) }
// MCP_TOOLGUARD_HOME should point at a temp dir so the real ~/.mcp-toolguard is never touched.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const BLOCK_MARKER = '[mcp-toolguard] BLOCKED';
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const cli = resolve(repoRoot, 'dist', 'cli', 'main.js');

function usage(msg) {
  process.stderr.write(`session.mjs: ${msg}\nSee the header of tests/ship/session.mjs for usage.\n`);
  process.exit(64);
}

const argv = process.argv.slice(2);
const opts = { monitor: false, direct: false };
let server = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const next = () => (i + 1 < argv.length ? argv[++i] : usage(`missing value for ${a}`));
  switch (a) {
    case '--calls': opts.calls = resolve(next()); break;
    case '--audit': opts.audit = resolve(next()); break;
    case '--pins': opts.pins = resolve(next()); break;
    case '--server-id': opts.serverId = next(); break;
    case '--monitor': opts.monitor = true; break;
    case '--direct': opts.direct = true; break;
    case '--': server = argv.slice(i + 1); i = argv.length; break;
    default: usage(`unknown option ${a}`);
  }
}
if (server.length === 0) usage('missing -- <server command>');
// ${VAR} in calls.json is replaced with the environment variable VAR (e.g. ${SHIP_ROOT}).
const expand = (raw) => raw.replace(/\$\{([A-Z0-9_]+)\}/g, (_, v) => JSON.stringify(process.env[v] ?? '').slice(1, -1));
const calls = opts.calls ? JSON.parse(expand(readFileSync(opts.calls, 'utf8'))) : [];

let command = server[0];
let args = server.slice(1);
if (!opts.direct) {
  if (!existsSync(cli)) usage(`${cli} not found; run npm run build first`);
  const flags = [];
  if (opts.audit) flags.push('--audit', opts.audit);
  if (opts.pins) flags.push('--pins', opts.pins);
  if (opts.serverId) flags.push('--server-id', opts.serverId);
  if (opts.monitor) flags.push('--monitor');
  command = process.execPath;
  args = [cli, 'run', ...flags, '--', ...server];
}

const transport = new StdioClientTransport({
  command,
  args,
  env: { ...process.env },
  stderr: 'inherit',
});
const client = new Client({ name: 'mcp-toolguard-ship-check', version: '0.0.0' });
const out = { tools: [], calls: [], audit: [] };
try {
  await client.connect(transport);
  const listed = await client.listTools();
  out.tools = listed.tools.map((t) => t.name);
  for (const c of calls) {
    try {
      const res = await client.callTool({ name: c.tool, arguments: c.arguments ?? {} });
      const text = (res.content ?? [])
        .filter((p) => p.type === 'text')
        .map((p) => p.text)
        .join('\n');
      out.calls.push({
        tool: c.tool,
        isError: res.isError === true,
        blocked: text.startsWith(BLOCK_MARKER),
        text: text.length > 300 ? `${text.slice(0, 300)}...` : text,
      });
    } catch (err) {
      out.calls.push({ tool: c.tool, isError: true, blocked: false, text: `JSON-RPC error: ${err.message}` });
    }
  }
} finally {
  await client.close().catch(() => {});
}

if (opts.audit && existsSync(opts.audit)) {
  for (const line of readFileSync(opts.audit, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const e = JSON.parse(line);
    out.serverId ??= e.serverId;
    if (e.kind === 'lifecycle' || !e.action || e.action === 'allow') continue;
    out.audit.push({ kind: e.kind, toolName: e.toolName, action: e.action, wouldBlock: e.wouldBlock, reasons: e.reasons });
  }
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

#!/usr/bin/env node
// Scripted MCP client for the attack demos.
//
// It spawns   node dist/cli/main.js run [--monitor] [--policy P] --audit A --pins P -- node <server>
// and talks to it exactly like Claude Desktop or Cursor would, printing a readable transcript.
//
// Usage:
//   node examples/attacks/client.mjs --server <server.mjs> --audit <file> --pins <file>
//        [--policy <file>] [--monitor] [--server-id <id>] [--env KEY=VALUE]... [--summary <file.json>]
//        [--no-toolguard]  (connect to the server directly, to show the attack without protection)
//        -- <step>...
//
// Steps (run in order):
//   list                        → tools/list, print the tools the client actually sees
//   call <tool> '<json args>'   → tools/call, print the response text
//   wait <ms>                   → sleep (lets notifications arrive)
//
// --summary writes { lists: string[][], calls: [{ tool, text, isError }], notifications: string[] }
// so shell scripts can assert on what happened without scraping the transcript.
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..');
const cli = resolve(repoRoot, 'dist', 'cli', 'main.js');

function usage(msg) {
  process.stderr.write(`client.mjs: ${msg}\nSee the header of examples/attacks/client.mjs for usage.\n`);
  process.exit(64);
}

// ── argument parsing ────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const opts = { env: {}, monitor: false, toolguard: true };
let steps = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const next = () => (i + 1 < argv.length ? argv[++i] : usage(`missing value for ${a}`));
  switch (a) {
    case '--server': opts.server = resolve(next()); break;
    case '--audit': opts.audit = resolve(next()); break;
    case '--pins': opts.pins = resolve(next()); break;
    case '--policy': opts.policy = resolve(next()); break;
    case '--server-id': opts.serverId = next(); break;
    case '--summary': opts.summary = resolve(next()); break;
    case '--monitor': opts.monitor = true; break;
    case '--no-toolguard': opts.toolguard = false; break;
    case '--env': {
      const kv = next();
      const eq = kv.indexOf('=');
      if (eq < 1) usage(`--env expects KEY=VALUE, got ${kv}`);
      opts.env[kv.slice(0, eq)] = kv.slice(eq + 1);
      break;
    }
    case '--': steps = argv.slice(i + 1); i = argv.length; break;
    default: usage(`unknown option ${a}`);
  }
}
if (!opts.server) usage('--server is required');
if (opts.toolguard && (!opts.audit || !opts.pins)) usage('--audit and --pins are required');

// ── transcript helpers ──────────────────────────────────────────────────────
const out = (line = '') => process.stdout.write(line + '\n');
const indent = (text, pad = '    ') => text.split('\n').map((l) => pad + l).join('\n');
const oneLine = (s, max = 110) => {
  const flat = String(s ?? '').replace(/\s+/g, ' ').trim();
  return flat.length > max ? flat.slice(0, max - 1) + '…' : flat;
};

const summary = { lists: [], calls: [], notifications: [] };

// ── connect ─────────────────────────────────────────────────────────────────
const serverCmd = [process.execPath, opts.server];
const args = opts.toolguard
  ? [
      cli,
      'run',
      ...(opts.monitor ? ['--monitor'] : []),
      ...(opts.policy ? ['--policy', opts.policy] : []),
      ...(opts.serverId ? ['--server-id', opts.serverId] : []),
      '--audit', opts.audit,
      '--pins', opts.pins,
      '--',
      ...serverCmd,
    ]
  : [opts.server];

const transport = new StdioClientTransport({
  command: process.execPath,
  args,
  env: { ...process.env, ...opts.env },
  stderr: 'pipe',
});

// Toolguard's human-readable warnings go to its stderr. Show them inline, clearly marked.
let stderrBuf = '';
transport.stderr?.on('data', (chunk) => {
  stderrBuf += chunk.toString();
  let nl;
  while ((nl = stderrBuf.indexOf('\n')) >= 0) {
    const line = stderrBuf.slice(0, nl).trimEnd();
    stderrBuf = stderrBuf.slice(nl + 1);
    if (line && !isBanner(line)) out(`    (toolguard stderr) ${oneLine(line, 140)}`);
  }
});
// The startup banner (version, policy source, temp paths) is noise in a transcript; warnings are not.
function isBanner(line) {
  return /^mcp-toolguard \S+: guarding /.test(line) || /^\s+(policy|mode|audit|pins):\s/.test(line);
}

const client = new Client({ name: 'demo-client', version: '0.1.0' });
client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
  summary.notifications.push('notifications/tools/list_changed');
  out('← notifications/tools/list_changed   (server says its tools changed)');
});

let exitCode = 0;
try {
  await client.connect(transport);
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    if (step === 'list') {
      out('→ tools/list');
      const { tools } = await client.listTools();
      summary.lists.push(tools.map((t) => t.name));
      out(`← ${tools.length} tool(s) visible to the model:`);
      for (const t of tools) out(`    - ${t.name}: ${oneLine(t.description)}`);
    } else if (step === 'call') {
      const tool = steps[++i];
      const rawArgs = steps[++i] ?? '{}';
      if (!tool) usage('call needs a tool name');
      const toolArgs = JSON.parse(rawArgs);
      out(`→ tools/call ${tool} ${JSON.stringify(toolArgs)}`);
      const res = await client.callTool({ name: tool, arguments: toolArgs });
      const text = (res.content ?? [])
        .filter((c) => c.type === 'text')
        .map((c) => c.text)
        .join('\n');
      summary.calls.push({ tool, text, isError: Boolean(res.isError) });
      out(`← ${res.isError ? 'isError ' : ''}result:`);
      out(indent(text || '(no text content)'));
    } else if (step === 'wait') {
      const ms = Number(steps[++i] ?? 200);
      await new Promise((r) => setTimeout(r, ms));
    } else {
      usage(`unknown step ${step}`);
    }
  }
} catch (err) {
  out(`!! client error: ${err instanceof Error ? err.message : String(err)}`);
  exitCode = 1;
} finally {
  await client.close().catch(() => {});
  // Give the proxy a moment to flush its stderr before we exit.
  await new Promise((r) => setTimeout(r, 50));
  if (stderrBuf.trim() && !isBanner(stderrBuf.trim())) out(`    (toolguard stderr) ${oneLine(stderrBuf, 140)}`);
  if (opts.summary) writeFileSync(opts.summary, JSON.stringify(summary, null, 2) + '\n');
}
process.exit(exitCode);

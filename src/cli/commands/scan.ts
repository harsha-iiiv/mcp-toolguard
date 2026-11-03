import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { TOOLGUARD_VERSION } from '../../contracts.js';
import type { Action, Decision, Finding, ToolguardPolicy, ToolDescriptor } from '../../contracts.js';
import { createPolicyEngine } from '../../policy/index.js';
import { createDetector, createPinStore } from '../../detection/index.js';
import { bool, parseArgs, str } from '../args.js';
import { defaultServerId, loadPolicyFrom, reportError } from '../common.js';
import { UsageError, resolveUserPath, stringEnv, type CliIo } from '../io.js';

const SPEC = {
  policy: 'string',
  pins: 'string',
  'server-id': 'string',
  json: 'boolean',
} as const;

/** One entry of `scan --json` output. */
export interface ScanResult {
  serverId: string;
  tool: string;
  /** Effective action under the loaded policy (monitor mode never yields 'block'). */
  action: Action;
  /** True when enforce mode would block this tool (also true when action is 'block'). */
  blocked: boolean;
  wouldBlock: boolean;
  reasons: string[];
  findings: Finding[];
}

/** Connect to the server as an MCP client and return every tool, following pagination. */
export async function listServerTools(command: string, args: string[], io: CliIo): Promise<ToolDescriptor[]> {
  const transport = new StdioClientTransport({
    command,
    args,
    env: stringEnv(io.env),
    cwd: io.cwd,
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (chunk: Buffer | string) => {
    io.stderr.write(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
  });
  const client = new Client({ name: 'mcp-toolguard-scan', version: TOOLGUARD_VERSION }, { capabilities: {} });
  await client.connect(transport);
  try {
    const tools: ToolDescriptor[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    do {
      const page = await client.listTools(cursor === undefined ? {} : { cursor });
      tools.push(...(page.tools as ToolDescriptor[]));
      cursor = page.nextCursor;
      if (cursor !== undefined) {
        if (seenCursors.has(cursor)) throw new Error(`server returned a repeating tools/list cursor '${cursor}'`);
        seenCursors.add(cursor);
      }
    } while (cursor !== undefined);
    return tools;
  } finally {
    await client.close().catch(() => undefined);
  }
}

export function isBlocked(d: Decision): boolean {
  return d.action === 'block' || d.wouldBlock;
}

export async function scanCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, SPEC, { commandMode: true, name: 'scan' });
  const [command, ...args] = parsed.command ?? [];
  if (command === undefined || command === '') {
    throw new UsageError('missing server command (put it after --)', 'scan');
  }
  const json = bool(parsed, 'json');
  const serverId = str(parsed, 'server-id') ?? defaultServerId(command, args);

  let results: ScanResult[];
  let policy: ToolguardPolicy;
  let source: string;
  try {
    ({ policy, source } = loadPolicyFrom(str(parsed, 'policy'), io));
    const pinsFile = str(parsed, 'pins');
    // Without --pins, use an in-memory store so a one-off scan never touches the real pin file.
    const pins = createPinStore(pinsFile === undefined ? undefined : resolveUserPath(pinsFile, io.cwd));
    const engine = createPolicyEngine(policy);
    const detector = createDetector({ pins, disabledRules: engine.disabledRules() });

    const tools = await listServerTools(command, args, io);
    results = tools.map((tool) => {
      const target = { kind: 'tool_definition' as const, tool };
      const findings = detector.inspect(target, { serverId, direction: 'server_to_client' });
      const decision = engine.evaluate(target, findings);
      return {
        serverId,
        tool: tool.name,
        action: decision.action,
        blocked: isBlocked(decision),
        wouldBlock: decision.wouldBlock,
        reasons: decision.reasons,
        findings: decision.findings,
      };
    });
  } catch (err) {
    reportError(io, err, 'mcp-toolguard scan: error: ');
    return 1;
  }

  if (json) {
    io.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
  } else {
    io.stdout.write(formatReport(results, { serverId, source, mode: policy.mode }));
  }
  return results.some((r) => r.blocked) ? 2 : 0;
}

function oneLine(s: string, max: number): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

export function formatReport(
  results: readonly ScanResult[],
  meta: { serverId: string; source: string; mode: ToolguardPolicy['mode'] },
): string {
  const lines: string[] = [];
  lines.push(`mcp-toolguard scan: server '${meta.serverId}', ${results.length} tool(s), policy ${meta.source} (${meta.mode})`);
  lines.push('');
  for (const r of results) {
    const mark = r.blocked ? '✗' : r.action === 'warn' ? '⚠' : '✓';
    const label = r.blocked ? (r.action === 'block' ? 'BLOCK' : 'WOULD BLOCK (monitor)') : r.action === 'warn' ? 'WARN' : '';
    lines.push(`  ${mark} ${r.tool}${label ? `  [${label}]` : ''}`);
    for (const f of r.findings) {
      const where = f.location ? ` at ${f.location}` : '';
      lines.push(`      ${f.severity.padEnd(8)} ${f.ruleId}: ${oneLine(f.message, 160)}${where}`);
      if (f.evidence) lines.push(`               evidence: ${JSON.stringify(oneLine(f.evidence, 120))}`);
    }
    if (r.findings.length === 0 && r.action !== 'allow') {
      for (const reason of r.reasons) lines.push(`      ${oneLine(reason, 160)}`);
    }
  }
  const blocked = results.filter((r) => r.blocked).length;
  const warned = results.filter((r) => !r.blocked && r.action === 'warn').length;
  const clean = results.length - blocked - warned;
  lines.push('');
  lines.push(`Summary: ${results.length} tool(s): ${clean} clean, ${warned} warn, ${blocked} blocked.`);
  if (blocked > 0) {
    lines.push('Blocked tools would be removed from tools/list by `mcp-toolguard run`.');
  }
  return `${lines.join('\n')}\n`;
}

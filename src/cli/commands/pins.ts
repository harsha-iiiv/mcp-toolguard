import type { ToolPin } from '../../contracts.js';
import { createPinStore } from '../../detection/index.js';
import { bool, parseArgs, str } from '../args.js';
import { loadPolicyFrom, reportError } from '../common.js';
import { UsageError, resolveUserPath, type CliIo } from '../io.js';

const SPEC = {
  pins: 'string',
  policy: 'string',
  'server-id': 'string',
  tool: 'string',
  json: 'boolean',
} as const;

export async function pinsCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, SPEC, { name: 'pins' });
  const [sub, extra] = parsed.positionals;
  if (sub === undefined) throw new UsageError("missing subcommand: 'list' or 'reset'", 'pins');
  if (sub !== 'list' && sub !== 'reset') throw new UsageError(`unknown subcommand '${sub}'`, 'pins');
  if (extra !== undefined) throw new UsageError(`unexpected argument '${extra}'`, 'pins');

  const serverId = str(parsed, 'server-id');
  const tool = str(parsed, 'tool');
  if (sub === 'reset' && tool !== undefined && serverId === undefined) {
    throw new UsageError('--tool requires --server-id', 'pins');
  }

  try {
    const pinsArg = str(parsed, 'pins');
    const file =
      pinsArg !== undefined ? resolveUserPath(pinsArg, io.cwd) : loadPolicyFrom(str(parsed, 'policy'), io).policy.pins.file;
    const store = createPinStore(file);

    if (sub === 'list') {
      const pins = store.list(serverId).filter((p) => tool === undefined || p.toolName === tool);
      if (bool(parsed, 'json')) {
        io.stdout.write(`${JSON.stringify(pins, null, 2)}\n`);
      } else {
        io.stdout.write(formatPins(pins, file));
      }
      return 0;
    }

    let removed = 0;
    if (serverId !== undefined) {
      removed = store.reset(serverId, tool);
    } else {
      for (const id of new Set(store.list().map((p) => p.serverId))) removed += store.reset(id);
    }
    const scope = serverId === undefined ? 'all servers' : tool === undefined ? `server '${serverId}'` : `'${serverId}/${tool}'`;
    io.stdout.write(`Removed ${removed} pin(s) for ${scope} from ${file}. They are re-pinned on next tools/list.\n`);
    return 0;
  } catch (err) {
    reportError(io, err, 'mcp-toolguard pins: ');
    return 1;
  }
}

export function formatPins(pins: readonly ToolPin[], file: string): string {
  if (pins.length === 0) return `No pins in ${file}\n`;
  const rows = pins.map((p) => [p.serverId, p.toolName, p.hash.slice(0, 12), p.firstSeen]);
  const header = ['SERVER', 'TOOL', 'HASH', 'FIRST SEEN'];
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const fmt = (r: string[]): string => r.map((c, i) => c.padEnd(widths[i] ?? 0)).join('  ').trimEnd();
  return `${[fmt(header), ...rows.map(fmt)].join('\n')}\n\n${pins.length} pin(s) in ${file}\n`;
}

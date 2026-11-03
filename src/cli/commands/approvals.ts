import type { ApprovalRequest, ApprovalStatus } from '../../contracts.js';
import { createApprovalStore } from '../../approval/index.js';
import { bool, parseArgs, str } from '../args.js';
import { loadPolicyFrom, reportError } from '../common.js';
import { UsageError, type CliIo } from '../io.js';

const SPEC = { policy: 'string', status: 'string', json: 'boolean' } as const;
/** 'expired' is a display status: a pending request older than 24h. */
const FILTERS = ['pending', 'approved', 'denied', 'used', 'expired'] as const;
type Filter = (typeof FILTERS)[number];

export async function approvalsCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, SPEC, { name: 'approvals' });
  const [sub, extra] = parsed.positionals;
  if (sub === undefined) throw new UsageError("missing subcommand: 'list'", 'approvals');
  if (sub !== 'list') throw new UsageError(`unknown subcommand '${sub}'`, 'approvals');
  if (extra !== undefined) throw new UsageError(`unexpected argument '${extra}'`, 'approvals');
  const status = str(parsed, 'status');
  if (status !== undefined && !(FILTERS as readonly string[]).includes(status)) {
    throw new UsageError(`--status must be one of ${FILTERS.join(', ')}`, 'approvals');
  }

  try {
    const { policy } = loadPolicyFrom(str(parsed, 'policy'), io);
    const store = createApprovalStore({ file: policy.approval.file });
    const shown = (r: ApprovalRequest): Filter => (store.isExpired(r) ? 'expired' : r.status);
    const rows = store
      .list(status === 'expired' ? 'pending' : (status as ApprovalStatus | undefined))
      .filter((r) => status === undefined || shown(r) === status)
      .map((r) => ({ ...r, status: shown(r) }));

    if (bool(parsed, 'json')) {
      io.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
      return 0;
    }
    const file = store.file ?? '(memory)';
    if (rows.length === 0) {
      io.stdout.write(`No ${status ?? ''}${status ? ' ' : ''}approval requests in ${file}\n`);
      return 0;
    }
    const table = rows.map((r) => [r.id, r.status, r.toolCall.serverId, r.toolCall.toolName, r.createdAt, summarize(r.toolCall.arguments)]);
    const header = ['ID', 'STATUS', 'SERVER', 'TOOL', 'CREATED', 'ARGUMENTS'];
    const widths = header.map((h, i) => Math.max(h.length, ...table.map((r) => (r[i] ?? '').length)));
    const fmt = (r: string[]): string => r.map((c, i) => c.padEnd(widths[i] ?? 0)).join('  ').trimEnd();
    io.stdout.write(`${[fmt(header), ...table.map(fmt)].join('\n')}\n\n${rows.length} request(s) in ${file}\n`);
    if (rows.some((r) => r.status === 'pending')) io.stdout.write(`Approve with: mcp-toolguard approve <id>   Deny with: mcp-toolguard deny <id>\n`);
    return 0;
  } catch (err) {
    reportError(io, err, 'mcp-toolguard approvals: ');
    return 1;
  }
}

function summarize(args: Record<string, unknown>): string {
  const s = JSON.stringify(args);
  return s.length > 60 ? `${s.slice(0, 57)}...` : s;
}

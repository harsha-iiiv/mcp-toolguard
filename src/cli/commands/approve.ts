import type { ApprovalRequest } from '../../contracts.js';
import { ApprovalError, createApprovalStore } from '../../approval/index.js';
import { createAuditLogger } from '../../audit/index.js';
import { parseArgs, str } from '../args.js';
import { loadPolicyFrom, reportError } from '../common.js';
import { UsageError, type CliIo } from '../io.js';

const SPEC = { policy: 'string' } as const;

async function decideCommand(name: 'approve' | 'deny', argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, SPEC, { name });
  const [id, extra] = parsed.positionals;
  if (id === undefined) throw new UsageError('missing approval request id', name);
  if (extra !== undefined) throw new UsageError(`unexpected argument '${extra}'`, name);

  try {
    const { policy } = loadPolicyFrom(str(parsed, 'policy'), io);
    const audit = createAuditLogger({ file: policy.audit.file, redact: policy.audit.redact, stderr: false });
    try {
      const store = createApprovalStore({ file: policy.approval.file, audit });
      const req: ApprovalRequest = name === 'approve' ? store.approve(id) : store.deny(id);
      io.stdout.write(
        name === 'approve'
          ? `Approved ${req.id}: ${req.toolCall.serverId}/${req.toolCall.toolName}. The same call (same arguments) may now run once.\n`
          : `Denied ${req.id}: ${req.toolCall.serverId}/${req.toolCall.toolName}.\n`,
      );
      return 0;
    } finally {
      await audit.close();
    }
  } catch (err) {
    if (err instanceof ApprovalError && err.code === 'not_found') {
      io.stderr.write(`mcp-toolguard ${name}: ${err.message}. Run 'mcp-toolguard approvals list' to see pending requests.\n`);
      return 1;
    }
    reportError(io, err, `mcp-toolguard ${name}: `);
    return 1;
  }
}

export const approveCommand = (argv: readonly string[], io: CliIo): Promise<number> => decideCommand('approve', argv, io);
export const denyCommand = (argv: readonly string[], io: CliIo): Promise<number> => decideCommand('deny', argv, io);

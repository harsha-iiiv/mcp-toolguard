import { verifyAuditLog } from '../../audit/index.js';
import { parseArgs } from '../args.js';
import { reportError } from '../common.js';
import { UsageError, resolveUserPath, type CliIo } from '../io.js';

export async function verifyLogCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, {}, { name: 'verify-log' });
  const [file, extra] = parsed.positionals;
  if (file === undefined) throw new UsageError('missing audit log file', 'verify-log');
  if (extra !== undefined) throw new UsageError(`unexpected argument '${extra}'`, 'verify-log');

  try {
    const result = verifyAuditLog(resolveUserPath(file, io.cwd));
    if (result.ok) {
      io.stdout.write(`OK: ${file}: ${result.count} event(s), hash chain intact\n`);
      return 0;
    }
    const at = result.brokenAt !== undefined ? ` at seq ${result.brokenAt}` : '';
    io.stdout.write(`BROKEN: ${file}: hash chain broken${at}${result.error ? `: ${result.error}` : ''}\n`);
    io.stdout.write(`  ${result.count} event(s) verified before the break\n`);
    return 1;
  } catch (err) {
    reportError(io, err, `mcp-toolguard verify-log: ${file}: `);
    return 1;
  }
}

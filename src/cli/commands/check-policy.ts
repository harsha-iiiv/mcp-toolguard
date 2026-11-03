import { parseArgs } from '../args.js';
import { loadPolicyFrom, reportError } from '../common.js';
import { UsageError, type CliIo } from '../io.js';

export async function checkPolicyCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, {}, { name: 'check-policy' });
  const [file, extra] = parsed.positionals;
  if (file === undefined) throw new UsageError('missing policy file', 'check-policy');
  if (extra !== undefined) throw new UsageError(`unexpected argument '${extra}'`, 'check-policy');

  try {
    const { policy, source } = loadPolicyFrom(file, io);
    io.stdout.write(
      `OK: ${source} is a valid policy\n` +
        `  mode: ${policy.mode}; tools allow ${policy.tools.allow.length}, deny ${policy.tools.deny.length}; ` +
        `${Object.keys(policy.rules).length} rule override(s); ${policy.arguments.length} argument rule(s)\n`,
    );
    return 0;
  } catch (err) {
    reportError(io, err, `INVALID: ${file}: `);
    return 1;
  }
}

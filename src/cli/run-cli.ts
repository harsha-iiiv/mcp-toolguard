import { TOOLGUARD_VERSION } from '../contracts.js';
import { approvalsCommand } from './commands/approvals.js';
import { approveCommand, denyCommand } from './commands/approve.js';
import { checkPolicyCommand } from './commands/check-policy.js';
import { initCommand } from './commands/init.js';
import { pinsCommand } from './commands/pins.js';
import { runCommand } from './commands/run.js';
import { scanCommand } from './commands/scan.js';
import { verifyLogCommand } from './commands/verify-log.js';
import { reportError } from './common.js';
import { COMMAND_USAGE, USAGE } from './help.js';
import { UsageError, type CliIo } from './io.js';

export type { CliIo, CliWriter } from './io.js';
export { UsageError } from './io.js';

type Command = (argv: readonly string[], io: CliIo) => Promise<number>;

const COMMANDS: Record<string, Command> = {
  run: runCommand,
  scan: scanCommand,
  init: initCommand,
  'check-policy': checkPolicyCommand,
  'verify-log': verifyLogCommand,
  pins: pinsCommand,
  approve: approveCommand,
  deny: denyCommand,
  approvals: approvalsCommand,
};

function wantsHelp(argv: readonly string[]): boolean {
  for (const a of argv) {
    if (a === '--') return false;
    if (a === '--help' || a === '-h') return true;
  }
  return false;
}

/**
 * Entry point for the `mcp-toolguard` binary. `argv` excludes the node binary and script path.
 * Resolves with the process exit code; never throws.
 */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const [first, ...rest] = argv;

  if (first === undefined) {
    io.stderr.write(USAGE);
    return 1;
  }
  if (first === '--version' || first === '-v' || first === 'version') {
    io.stdout.write(`${TOOLGUARD_VERSION}\n`);
    return 0;
  }
  if (first === '--help' || first === '-h' || first === 'help') {
    const topic = first === 'help' ? rest[0] : undefined;
    const usage = topic !== undefined ? COMMAND_USAGE[topic] : undefined;
    io.stdout.write(usage !== undefined ? `Usage: ${usage}\n` : USAGE);
    return 0;
  }

  const command = COMMANDS[first];
  if (command === undefined) {
    io.stderr.write(`mcp-toolguard: unknown command '${first}'\n\n${USAGE}`);
    return 1;
  }

  // `run` must keep stdout clean for the protocol, so its help goes to stderr.
  if (wantsHelp(rest)) {
    const out = first === 'run' ? io.stderr : io.stdout;
    out.write(`Usage: ${COMMAND_USAGE[first] ?? ''}\n\nRun 'mcp-toolguard --help' for all options.\n`);
    return 0;
  }

  try {
    return await command(rest, io);
  } catch (err) {
    if (err instanceof UsageError) {
      const usage = COMMAND_USAGE[err.command ?? first];
      io.stderr.write(`mcp-toolguard ${first}: ${err.message}\n${usage ? `Usage: ${usage}\n` : ''}`);
      return 1;
    }
    reportError(io, err);
    return 1;
  }
}

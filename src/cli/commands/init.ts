import fs from 'node:fs';
import path from 'node:path';
import { bool, parseArgs } from '../args.js';
import { reportError } from '../common.js';
import { UsageError, type CliIo } from '../io.js';
import { POLICY_TEMPLATE } from '../template.js';

export const INIT_FILENAME = 'toolguard.yaml';

export async function initCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv, { force: 'boolean' }, { name: 'init' });
  if (parsed.positionals.length > 0) throw new UsageError(`unexpected argument '${parsed.positionals[0]}'`, 'init');

  const target = path.join(io.cwd, INIT_FILENAME);
  const force = bool(parsed, 'force');
  if (!force && fs.existsSync(target)) {
    io.stderr.write(`mcp-toolguard init: ${target} already exists (use --force to overwrite)\n`);
    return 1;
  }
  try {
    fs.writeFileSync(target, POLICY_TEMPLATE, { encoding: 'utf8', flag: force ? 'w' : 'wx' });
  } catch (err) {
    reportError(io, err, 'mcp-toolguard init: ');
    return 1;
  }
  io.stdout.write(`Wrote ${target}\nEdit it, then check it with: mcp-toolguard check-policy ${INIT_FILENAME}\n`);
  return 0;
}

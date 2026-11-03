import { UsageError } from './io.js';

export type OptionKind = 'string' | 'boolean';
export type OptionSpec = Record<string, OptionKind>;

export interface ParsedArgs {
  /** Option values keyed by long name (without dashes). */
  options: Record<string, string | boolean | undefined>;
  positionals: string[];
  /**
   * The wrapped server command line: everything after `--`, or, when `commandMode` is set and no `--`
   * was given, everything from the first positional onward. Undefined if neither was present.
   */
  command?: string[];
}

export interface ParseOptions {
  /** Treat the first positional (and everything after it) as the server command line. */
  commandMode?: boolean;
  /** Short aliases, e.g. { h: 'help' }. */
  aliases?: Record<string, string>;
  /** Command name for error messages. */
  name?: string;
}

/**
 * Small, strict argv parser. Supports `--name value`, `--name=value`, boolean `--flag`, short aliases
 * and `--` as the end of options. Unknown options are usage errors. No dependencies.
 */
export function parseArgs(argv: readonly string[], spec: OptionSpec, opts: ParseOptions = {}): ParsedArgs {
  const options: ParsedArgs['options'] = {};
  const positionals: string[] = [];
  let command: string[] | undefined;
  const name = opts.name;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;

    if (arg === '--') {
      command = argv.slice(i + 1);
      break;
    }

    if (arg.startsWith('-') && arg !== '-') {
      let key: string;
      let inline: string | undefined;
      if (arg.startsWith('--')) {
        const eq = arg.indexOf('=');
        key = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
        inline = eq === -1 ? undefined : arg.slice(eq + 1);
      } else {
        const short = arg.slice(1);
        const long = opts.aliases?.[short];
        if (long === undefined) throw new UsageError(`unknown option '${arg}'`, name);
        key = long;
      }
      const kind = spec[key];
      if (kind === undefined) throw new UsageError(`unknown option '${arg}'`, name);
      if (kind === 'boolean') {
        if (inline !== undefined) throw new UsageError(`option '--${key}' does not take a value`, name);
        options[key] = true;
      } else {
        let value = inline;
        if (value === undefined) {
          const next = argv[i + 1];
          if (next === undefined || next === '--') throw new UsageError(`option '--${key}' requires a value`, name);
          value = next;
          i++;
        }
        if (value === '') throw new UsageError(`option '--${key}' requires a value`, name);
        options[key] = value;
      }
      continue;
    }

    if (opts.commandMode) {
      command = argv.slice(i);
      break;
    }
    positionals.push(arg);
  }

  return command === undefined ? { options, positionals } : { options, positionals, command };
}

export function str(parsed: ParsedArgs, key: string): string | undefined {
  const v = parsed.options[key];
  return typeof v === 'string' ? v : undefined;
}

export function bool(parsed: ParsedArgs, key: string): boolean {
  return parsed.options[key] === true;
}

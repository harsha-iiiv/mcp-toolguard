import path from 'node:path';

export interface CliWriter {
  write(chunk: string): unknown;
}

/** Everything a CLI command may touch from the outside world. Injected so commands are testable. */
export interface CliIo {
  stdout: CliWriter;
  stderr: CliWriter;
  cwd: string;
  env: Record<string, string | undefined>;
}

/** Bad invocation: printed with a usage hint, exit code 1. */
export class UsageError extends Error {
  constructor(
    message: string,
    public readonly command?: string,
  ) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Resolve a user-supplied path against the CLI cwd, leaving '~' paths for the owning module to expand. */
export function resolveUserPath(p: string, cwd: string): string {
  if (p === '~' || p.startsWith('~/') || p.startsWith('~\\')) return p;
  return path.resolve(cwd, p);
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Only string values survive; child_process env must be Record<string, string>. */
export function stringEnv(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (typeof v === 'string') out[k] = v;
  return out;
}

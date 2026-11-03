import type { CliIo } from '../../../src/cli/run-cli.js';

export interface TestIo extends CliIo {
  out(): string;
  err(): string;
}

export function makeIo(cwd = process.cwd(), env: Record<string, string | undefined> = {}): TestIo {
  let out = '';
  let err = '';
  return {
    stdout: { write: (s: string) => (out += s) },
    stderr: { write: (s: string) => (err += s) },
    cwd,
    env,
    out: () => out,
    err: () => err,
  };
}

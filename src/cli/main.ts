#!/usr/bin/env node
import { runCli } from './run-cli.js';

runCli(process.argv.slice(2), {
  stdout: process.stdout,
  stderr: process.stderr,
  cwd: process.cwd(),
  env: process.env,
}).then(
  (code) => {
    process.exitCode = code;
    // Normally the event loop drains and Node exits on its own. If a stray handle (e.g. a stdin
    // listener left behind by a closed transport) keeps it alive, exit anyway shortly after.
    setTimeout(() => process.exit(code), 1000).unref();
  },
  (err: unknown) => {
    process.stderr.write(`mcp-toolguard: fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exitCode = 1;
  },
);

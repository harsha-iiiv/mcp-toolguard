import path from 'node:path';
import { PolicyError } from '../contracts.js';
import type { ToolguardPolicy } from '../contracts.js';
import { loadPolicy } from '../policy/index.js';
import { errorMessage, resolveUserPath, type CliIo } from './io.js';

/** Commands that launch something else; the server id comes from what they launch. */
const LAUNCHERS = new Set([
  'npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'node', 'bun', 'deno', 'tsx', 'ts-node',
  'python', 'python3', 'py', 'uv', 'npm', 'pnpm', 'yarn', 'docker', 'podman',
]);
/** Launcher flags that take a separate value (`uvx --with 'mcp<2' pkg`, `npx -p @a/b cmd`, `docker run -e K=V img`). */
const VALUE_FLAGS = new Set([
  '-p', '--package', '--with', '--from', '--python', '--index-url', '--extra-index-url', '-r', '--require', '--import',
  '--loader', '--experimental-loader', '-X', '-W', '-e', '--env', '--env-file', '-v', '--volume', '--name', '--network',
  '--mount', '-w', '--workdir', '--entrypoint', '--user', '-u', '--platform', '--config', '-c', '--cwd', '--dir', '--filter',
]);
/** Launcher subcommands to skip ("pnpm dlx pkg", "uv run server.py", "docker run image"). */
const SUBCOMMANDS = new Set(['dlx', 'exec', 'x', 'run', 'tool', 'start']);

function stripExt(base: string): string {
  const ext = path.extname(base);
  return ext && ext !== base ? base.slice(0, -ext.length) : base;
}

/** Entry-point file names that say nothing about which server they are. */
const GENERIC_ENTRY = new Set(['index', 'main', 'server', 'cli', 'app', 'start', 'run', '__main__', 'mod']);
/** Build/source folders to skip when walking up from a generic entry point. */
const BUILD_DIRS = new Set(['dist', 'build', 'out', 'lib', 'src', 'bin', 'esm', 'cjs', 'target', 'release']);

/**
 * "node_modules/@scope/server-x/dist/index.js" → "server-x"; "~/code/weather-mcp/build/index.js" → "weather-mcp".
 * Returns undefined when the file name itself is specific enough.
 */
function nameFromGenericEntry(target: string): string | undefined {
  const parts = target.split(/[\\/]+/).filter(Boolean);
  const file = parts.pop();
  if (!file || !GENERIC_ENTRY.has(stripExt(file).toLowerCase())) return undefined;
  const nm = parts.lastIndexOf('node_modules');
  if (nm >= 0 && parts[nm + 1]) {
    const first = parts[nm + 1]!;
    return first.startsWith('@') && parts[nm + 2] ? parts[nm + 2] : first;
  }
  while (parts.length && BUILD_DIRS.has(parts[parts.length - 1]!.toLowerCase())) parts.pop();
  const dir = parts.pop();
  return dir && dir !== '.' && dir !== '..' ? dir : undefined;
}

/** "@scope/pkg@1.2.3" → "pkg", "./servers/weather.py" → "weather", "ghcr.io/org/img:tag" → "img". */
function nameFromTarget(target: string): string {
  const fromEntry = nameFromGenericEntry(target);
  if (fromEntry) return fromEntry;
  let t = target.replace(/[\\/]+$/, '');
  t = t.replace(/@[^@/]*$/, (m) => (m === t ? m : '')); // drop trailing @version (not a bare @scope)
  t = t.replace(/:[^:/]*$/, ''); // drop docker :tag
  const base = t.split(/[\\/]/).pop() ?? t;
  return stripExt(base);
}

/**
 * Default server id. For a plain executable it is the basename without extension
 * ("/usr/bin/my-server" → "my-server"). For launchers (npx, node, python, uvx, docker, ...) it is
 * derived from the first non-flag argument, so different wrapped servers get different ids and their
 * pins never collide: `npx -y @modelcontextprotocol/server-filesystem /tmp` → "server-filesystem",
 * `node build/index.js` → "index", `python -m mcp_server_git` → "mcp_server_git".
 */
export function defaultServerId(command: string, args: readonly string[] = []): string {
  const commandId = stripExt(path.basename(command)) || command;
  if (!LAUNCHERS.has(commandId.toLowerCase())) return commandId;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '-m' && args[i + 1]) return args[i + 1]!; // python -m module
    if (a.startsWith('-')) {
      if (!a.includes('=') && VALUE_FLAGS.has(a)) i++; // skip the flag's value
      continue;
    }
    if (i === 0 && SUBCOMMANDS.has(a)) continue;
    const id = nameFromTarget(a);
    if (id) return id;
  }
  return commandId;
}

export function loadPolicyFrom(file: string | undefined, io: CliIo): { policy: ToolguardPolicy; source: string } {
  return loadPolicy(file === undefined ? undefined : resolveUserPath(file, io.cwd), io.cwd);
}

function isPolicyError(err: unknown): err is PolicyError {
  return (
    err instanceof PolicyError ||
    (err instanceof Error && err.name === 'PolicyError' && Array.isArray((err as { issues?: unknown }).issues))
  );
}

/** Print an error to stderr. PolicyError issues are printed one per line. */
export function reportError(io: CliIo, err: unknown, prefix = 'mcp-toolguard: error: '): void {
  io.stderr.write(`${prefix}${errorMessage(err)}\n`);
  if (isPolicyError(err)) {
    for (const issue of err.issues) io.stderr.write(`  - ${issue}\n`);
  }
}

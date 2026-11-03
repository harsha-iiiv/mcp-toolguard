import os from 'node:os';
import path from 'node:path';

/** Expand a leading '~' ('~' or '~/...') to the user's home directory. */
export function expandHome(p: string): string {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2));
  return p;
}

/** Base directory for toolguard state: $MCP_TOOLGUARD_HOME or '~/.mcp-toolguard'. */
export function toolguardHome(): string {
  const env = process.env.MCP_TOOLGUARD_HOME;
  return env !== undefined && env !== '' ? env : '~/.mcp-toolguard';
}

export function joinHome(file: string): string {
  const home = toolguardHome();
  return home.endsWith('/') || home.endsWith('\\') ? `${home}${file}` : `${home}/${file}`;
}

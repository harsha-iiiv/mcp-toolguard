import { describe, expect, it } from 'vitest';
import { parseArgs } from '../../../src/cli/args.js';
import { UsageError } from '../../../src/cli/io.js';
import { defaultServerId } from '../../../src/cli/common.js';

const SPEC = { policy: 'string', monitor: 'boolean', 'server-id': 'string' } as const;

describe('parseArgs', () => {
  it('parses string, inline and boolean options', () => {
    const p = parseArgs(['--policy', 'a.yaml', '--server-id=fs', '--monitor', 'x'], SPEC);
    expect(p.options).toEqual({ policy: 'a.yaml', 'server-id': 'fs', monitor: true });
    expect(p.positionals).toEqual(['x']);
    expect(p.command).toBeUndefined();
  });

  it('treats everything after -- as the command, including option-looking args', () => {
    const p = parseArgs(['--monitor', '--', 'npx', '-y', 'server', '--policy', 'zzz'], SPEC, { commandMode: true });
    expect(p.options).toEqual({ monitor: true });
    expect(p.command).toEqual(['npx', '-y', 'server', '--policy', 'zzz']);
  });

  it('in command mode, the first positional starts the command when -- is absent', () => {
    const p = parseArgs(['--monitor', 'node', 'server.js', '--port', '3'], SPEC, { commandMode: true });
    expect(p.command).toEqual(['node', 'server.js', '--port', '3']);
  });

  it('keeps an empty command after a trailing --', () => {
    expect(parseArgs(['--'], SPEC, { commandMode: true }).command).toEqual([]);
  });

  it('rejects unknown options, missing values and values on booleans', () => {
    expect(() => parseArgs(['--nope'], SPEC)).toThrow(UsageError);
    expect(() => parseArgs(['-x'], SPEC)).toThrow(/unknown option/);
    expect(() => parseArgs(['--policy'], SPEC)).toThrow(/requires a value/);
    expect(() => parseArgs(['--policy', '--'], SPEC)).toThrow(/requires a value/);
    expect(() => parseArgs(['--monitor=yes'], SPEC)).toThrow(/does not take a value/);
  });

  it('supports short aliases', () => {
    expect(parseArgs(['-m'], SPEC, { aliases: { m: 'monitor' } }).options.monitor).toBe(true);
  });
});

describe('defaultServerId', () => {
  it('uses the basename for plain executables', () => {
    expect(defaultServerId('/usr/local/bin/my-server')).toBe('my-server');
    expect(defaultServerId('./servers/weather.py')).toBe('weather');
    expect(defaultServerId('C:/tools/server.exe')).toBe('server');
    expect(defaultServerId('.hidden')).toBe('.hidden');
  });

  it('derives the id from what a launcher runs, so wrapped servers do not share pins', () => {
    expect(defaultServerId('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'])).toBe('server-filesystem');
    expect(defaultServerId('npx', ['-y', '@modelcontextprotocol/server-github@1.2.3'])).toBe('server-github');
    expect(defaultServerId('npx', ['mcp-remote@latest', 'https://x'])).toBe('mcp-remote');
    expect(defaultServerId('/usr/local/bin/node', ['build/index.js'])).toBe('index'); // relative: no project dir to name it after
    expect(defaultServerId('node', ['/Users/me/code/weather-mcp/build/index.js'])).toBe('weather-mcp');
    expect(defaultServerId('node', ['/x/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js', '/tmp'])).toBe('server-filesystem');
    expect(defaultServerId('node', ['/x/node_modules/mcp-server-foo/server.js'])).toBe('mcp-server-foo');
    expect(defaultServerId('python3', ['/srv/git-mcp/src/main.py'])).toBe('git-mcp');
    expect(defaultServerId('uvx', ['--with', 'mcp<2', 'mcp-server-sqlite', '--db-path', 'x.db'])).toBe('mcp-server-sqlite');
    expect(defaultServerId('npx', ['-y', '-p', '@scope/pkg', 'pkg-cli'])).toBe('pkg-cli');
    expect(defaultServerId('docker', ['run', '-i', '--rm', '-e', 'GITHUB_TOKEN', 'ghcr.io/github/github-mcp-server'])).toBe('github-mcp-server');
    expect(defaultServerId('npx', ['--package=@scope/pkg', 'pkg-cli'])).toBe('pkg-cli');
    expect(defaultServerId('node', ['examples/attacks/servers/poisoned-server.mjs'])).toBe('poisoned-server');
    expect(defaultServerId('uvx', ['mcp-server-fetch'])).toBe('mcp-server-fetch');
    expect(defaultServerId('python3', ['-m', 'mcp_server_git', '--repo', '.'])).toBe('mcp_server_git');
    expect(defaultServerId('uv', ['run', 'server.py'])).toBe('server');
    expect(defaultServerId('pnpm', ['dlx', '@scope/thing'])).toBe('thing');
    expect(defaultServerId('docker', ['run', '-i', '--rm', 'ghcr.io/github/github-mcp-server:latest'])).toBe('github-mcp-server');
  });

  it('falls back to the launcher name when there is nothing to derive from', () => {
    expect(defaultServerId('npx')).toBe('npx');
    expect(defaultServerId('node', ['--inspect'])).toBe('node');
  });
});

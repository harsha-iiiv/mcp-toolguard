// `run --transport/--url/--header` wiring and usage errors (startProxy stubbed).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ToolguardPolicy, ToolguardTransport } from '../../../src/contracts.js';
import { defaultPolicy } from '../../../src/policy/index.js';
import { extractHeaders, parseHeaders } from '../../../src/cli/commands/run.js';
import { makeIo } from '../cli/helpers.js';

const m = vi.hoisted(() => ({ startProxy: vi.fn(), loadPolicy: vi.fn() }));
vi.mock('../../../src/proxy/index.js', () => ({ startProxy: m.startProxy }));
vi.mock('../../../src/policy/index.js', async (orig) => ({
  ...(await orig<typeof import('../../../src/policy/index.js')>()),
  loadPolicy: m.loadPolicy,
}));
vi.mock('../../../src/audit/index.js', async (orig) => ({
  ...(await orig<typeof import('../../../src/audit/index.js')>()),
  createAuditLogger: () => ({ log: vi.fn(), close: vi.fn(async () => undefined) }),
}));

const { runCli } = await import('../../../src/cli/run-cli.js');

let policy: ToolguardPolicy;
beforeEach(() => {
  vi.clearAllMocks();
  policy = defaultPolicy();
  m.loadPolicy.mockImplementation(() => ({ policy, source: 'builtin' }));
  m.startProxy.mockResolvedValue({ done: Promise.resolve(0), close: vi.fn(), hiddenTools: () => [] });
});

const PINS = ['--pins', '/tmp/does-not-matter/pins.json', '--audit', '/tmp/does-not-matter/a.jsonl'];

describe('run --transport http|sse', () => {
  it('http: passes an http ToolguardTransport, no command, server id = URL host', async () => {
    const io = makeIo('/work');
    const code = await runCli(
      ['run', '--transport', 'http', '--url', 'https://api.example.com/mcp?key=secret', '--header', 'Authorization: Bearer abc', ...PINS],
      io,
    );
    expect(code).toBe(0);
    const opts = m.startProxy.mock.calls[0]?.[0];
    expect(opts.serverId).toBe('api.example.com');
    expect(opts.command).toBeUndefined();
    expect(opts.plugins).toBeUndefined();
    const server = opts.transports.server as ToolguardTransport;
    expect(server.name).toBe('http');
    expect(typeof server.connect).toBe('function');
    expect(opts.transports.client).toBeUndefined();
    expect(io.out()).toBe('');
    expect(io.err()).toContain("guarding 'api.example.com' (http https://api.example.com/mcp?…)");
    expect(io.err()).toContain('headers: Authorization');
    expect(io.err()).not.toContain('Bearer abc');
    expect(io.err()).not.toContain('secret');
  });

  it('sse with a port keeps the port in the server id; --server-id still wins', async () => {
    await runCli(['run', '--transport=sse', '--url=http://127.0.0.1:8123/sse', ...PINS], makeIo());
    expect(m.startProxy.mock.calls[0]?.[0].serverId).toBe('127.0.0.1:8123');
    expect((m.startProxy.mock.calls[0]?.[0].transports.server as ToolguardTransport).name).toBe('sse');
    await runCli(['run', '--transport', 'sse', '--url', 'http://h/sse', '--server-id', 'mine', ...PINS], makeIo());
    expect(m.startProxy.mock.calls[1]?.[0].serverId).toBe('mine');
  });

  it('stdio is unchanged: command/args/env/cwd, no transports, no plugins', async () => {
    await runCli(['run', ...PINS, '--', 'node', 'server.js', '--header', 'x'], makeIo('/work', { A: '1' }));
    const opts = m.startProxy.mock.calls[0]?.[0];
    expect(Object.keys(opts).sort()).toEqual(['args', 'audit', 'command', 'cwd', 'detector', 'env', 'policy', 'serverId', 'sessionId']);
    expect(opts.command).toBe('node');
    expect(opts.args).toEqual(['server.js', '--header', 'x']);
    expect(opts.serverId).toBe('server');
    expect(opts.env).toEqual({ A: '1' });
  });

  it('--transport stdio explicitly is the same as the default', async () => {
    await runCli(['run', '--transport', 'stdio', ...PINS, '--', 'srv'], makeIo());
    expect(m.startProxy.mock.calls[0]?.[0].command).toBe('srv');
  });

  it('wires the spend plugin only when a cap is set', async () => {
    policy = { ...policy, spend: { maxSpendPerTaskUsd: 2, costs: {}, defaultCostUsd: 0.1 } };
    const io = makeIo();
    await runCli(['run', ...PINS, '--', 'srv'], io);
    const plugins = m.startProxy.mock.calls[0]?.[0].plugins;
    expect(plugins.map((p: { id: string }) => p.id)).toEqual(['spend']);
    expect(io.err()).toContain('spend:  cap $2 per task');
  });

  it.each([
    [['--transport', 'ws', '--url', 'http://x'], "invalid --transport 'ws'"],
    [['--transport', 'http'], '--transport http requires --url'],
    [['--transport', 'http', '--url', 'http://x/mcp', '--', 'node', 's.js'], 'do not also pass a server command'],
    [['--transport', 'sse', '--url', 'http://x/sse', 'node'], 'do not also pass a server command'],
    [['--transport', 'http', '--url', 'ftp://x'], "--url: unsupported URL scheme 'ftp:'"],
    [['--transport', 'http', '--url', 'nope'], "--url: invalid URL 'nope'"],
    [['--transport', 'http', '--url', 'http://x', '--header', 'NoColon'], "invalid --header 'NoColon'"],
    [['--transport', 'http', '--url', 'http://x', '--header'], "option '--header' requires a value"],
    [['--url', 'http://x', '--', 'srv'], '--url needs --transport http or sse'],
    [['--header', 'A: b', '--', 'srv'], '--header needs --transport http or sse'],
    [[], 'missing server command'],
  ])('usage error: %j', async (args, message) => {
    const io = makeIo();
    expect(await runCli(['run', ...args], io)).toBe(1);
    expect(io.err()).toContain(message);
    expect(io.err()).toContain('Usage: mcp-toolguard run');
    expect(io.out()).toBe('');
    expect(m.startProxy).not.toHaveBeenCalled();
  });
});

describe('header helpers', () => {
  it('extractHeaders collects repeatable --header before the command only', () => {
    expect(
      extractHeaders(['--header', 'A: 1', '--policy', 'p.yaml', '--header=B: 2', '--monitor', '--', 'x', '--header', 'C: 3']),
    ).toEqual({ rest: ['--policy', 'p.yaml', '--monitor', '--', 'x', '--header', 'C: 3'], headers: ['A: 1', 'B: 2'] });
    expect(extractHeaders(['node', '--header', 'x'])).toEqual({ rest: ['node', '--header', 'x'], headers: [] });
    // A string option's value that looks like a positional stays with its option.
    expect(extractHeaders(['--server-id', 'srv', '--header', 'A: 1'])).toEqual({ rest: ['--server-id', 'srv'], headers: ['A: 1'] });
  });

  it('parseHeaders splits at the first colon and trims', () => {
    expect(parseHeaders(['Authorization: Bearer a:b', 'X-Empty:', 'x-k:v'])).toEqual({
      Authorization: 'Bearer a:b',
      'X-Empty': '',
      'x-k': 'v',
    });
    expect(() => parseHeaders(['bad name: v'])).toThrow(/invalid --header/);
    expect(() => parseHeaders([': v'])).toThrow(/invalid --header/);
  });
});

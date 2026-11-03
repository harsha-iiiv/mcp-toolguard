// HTTP and SSE upstreams go through the exact same proxy inspection path as stdio.
import { afterEach, describe, expect, it } from 'vitest';
import { BLOCK_MARKER } from '../../../src/contracts.js';
import {
  createHttpTransport,
  createSseTransport,
  createStdioTransport,
  createUpstreamTransport,
  parseUpstreamUrl,
  UPSTREAM_UNREACHABLE_CODE,
} from '../../../src/transports/index.js';
import { connectThroughProxy, startHttpServer, startSseServer, textOf, type GuardedRemote, type RemoteServer } from './servers.js';

let remote: RemoteServer | undefined;
let g: GuardedRemote | undefined;
afterEach(async () => {
  await g?.close();
  await remote?.close();
  g = undefined;
  remote = undefined;
});

const KINDS = [
  { kind: 'http' as const, start: startHttpServer },
  { kind: 'sse' as const, start: startSseServer },
];

describe('transport factories', () => {
  it('return ToolguardTransports with the right name and connect() = start()', () => {
    const http = createHttpTransport({ url: 'http://127.0.0.1:1/mcp' });
    const sse = createSseTransport({ url: 'https://example.com/sse', headers: { Authorization: 'Bearer x' } });
    const stdio = createStdioTransport({ command: process.execPath, args: ['-e', ''] });
    expect([http.name, sse.name, stdio.name]).toEqual(['http', 'sse', 'stdio']);
    for (const t of [http, sse, stdio]) {
      expect(typeof t.connect).toBe('function');
      expect(typeof t.start).toBe('function');
      expect(typeof t.send).toBe('function');
      expect(typeof t.close).toBe('function');
    }
    expect(createUpstreamTransport({ transport: 'http', url: 'http://a/mcp' }).name).toBe('http');
    expect(createUpstreamTransport({ transport: 'sse', url: 'http://a/sse' }).name).toBe('sse');
    expect(createUpstreamTransport({ transport: 'stdio', command: 'x' }).name).toBe('stdio');
  });

  it('reject non-http URLs', () => {
    expect(() => parseUpstreamUrl('not a url')).toThrow(/invalid URL/);
    expect(() => parseUpstreamUrl('file:///etc/passwd')).toThrow(/unsupported URL scheme/);
    expect(() => createHttpTransport({ url: 'ws://x' })).toThrow(/unsupported URL scheme/);
    expect(parseUpstreamUrl('https://api.example.com/mcp').host).toBe('api.example.com');
  });

  it('stdio transport speaks to a child process', async () => {
    const t = createStdioTransport({
      command: process.execPath,
      args: ['-e', 'process.stdin.on("data", d => process.stdout.write(d))'],
    });
    const got = new Promise((resolve) => (t.onmessage = resolve));
    await t.connect();
    await t.send({ jsonrpc: '2.0', method: 'ping', id: 1 });
    expect(await got).toEqual({ jsonrpc: '2.0', method: 'ping', id: 1 });
    await t.close();
  });

  it('an unreachable HTTP upstream answers the request with a JSON-RPC error instead of hanging', async () => {
    remote = await startHttpServer();
    const url = remote.url;
    await remote.close();
    remote = undefined;
    const t = createHttpTransport({ url });
    const got = new Promise<unknown>((resolve) => (t.onmessage = resolve));
    await t.connect();
    await expect(t.send({ jsonrpc: '2.0', method: 'initialize', id: 7, params: {} })).rejects.toThrow();
    const reply = (await got) as { id: number; error: { code: number; message: string } };
    expect(reply.id).toBe(7);
    expect(reply.error.code).toBe(UPSTREAM_UNREACHABLE_CODE);
    expect(reply.error.message).toContain('upstream http server error');
    await t.close();
  });
});

describe.each(KINDS)('$kind upstream through the real proxy', ({ kind, start }) => {
  it('happy path: list tools and call one', async () => {
    remote = await start({ clean: true });
    g = await connectThroughProxy(kind, remote.url);
    const names = (await g.client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(['add', 'brave_web_search', 'multiply']);
    const r = await g.client.callTool({ name: 'add', arguments: { a: 2, b: 3 } });
    expect(textOf(r)).toBe('5');
    expect(r.isError).toBeFalsy();
    expect(remote.log.calls).toEqual([{ name: 'add', args: { a: 2, b: 3 } }]);
    // Same inspection path: the audit has the tools/list definitions, the call and its result.
    const kinds = g.audit.events().map((e) => e.kind);
    expect(kinds).toContain('tool_definition');
    expect(kinds).toContain('tool_call');
    expect(kinds).toContain('tool_result');
  });

  it('blocks the tool-poisoning demo: poisoned add is hidden, multiply works', async () => {
    remote = await start();
    g = await connectThroughProxy(kind, remote.url);
    const names = (await g.client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('add');
    expect(names).toContain('multiply');
    expect(g.handle.hiddenTools()).toEqual(['add']);

    const blocked = await g.client.callTool({ name: 'add', arguments: { a: 1, b: 2, sidenote: 'x' } });
    expect(textOf(blocked).startsWith(BLOCK_MARKER)).toBe(true);
    expect(blocked.isError).toBe(true);
    expect(textOf(await g.client.callTool({ name: 'multiply', arguments: { a: 6, b: 7 } }))).toBe('42');
    expect(remote.log.calls.map((c) => c.name)).toEqual(['multiply']);
  });

  it('a secret in the arguments never reaches the remote server', async () => {
    remote = await start({ clean: true });
    g = await connectThroughProxy(kind, remote.url);
    await g.client.listTools();
    const r = await g.client.callTool({
      name: 'brave_web_search',
      arguments: { query: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
    });
    expect(textOf(r).startsWith(BLOCK_MARKER)).toBe(true);
    expect(remote.log.calls).toEqual([]);
  });

  it('sends the configured headers on every upstream request', async () => {
    remote = await start({ clean: true });
    g = await connectThroughProxy(kind, remote.url, { headers: { Authorization: 'Bearer t0ken', 'X-Team': 'blue' } });
    await g.client.listTools();
    expect(remote.log.headers.length).toBeGreaterThan(1);
    for (const h of remote.log.headers) {
      expect(h.authorization).toBe('Bearer t0ken');
      expect(h['x-team']).toBe('blue');
    }
  });
});

describe('http protocol version', () => {
  it('passes the negotiated protocol version to the upstream after initialize', async () => {
    remote = await startHttpServer({ clean: true });
    g = await connectThroughProxy('http', remote.url);
    await g.client.listTools();
    const last = remote.log.headers.at(-1)!;
    expect(typeof last['mcp-protocol-version']).toBe('string');
    expect(last['mcp-session-id']).toBeTruthy();
  });
});

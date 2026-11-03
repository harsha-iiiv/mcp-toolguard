/**
 * Upstream transports. Each factory returns a contract ToolguardTransport that wraps an SDK
 * client transport. Pass it to `startProxy({ transports: { server } })`: tools/list, tools/call and
 * results then go through the exact same Detector / PolicyEngine / plugin path as stdio.
 *
 * No network calls happen here until the proxy calls start()/send(); nothing is sent anywhere except
 * the upstream URL the user configured.
 */
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { ToolguardTransport } from '../contracts.js';
import { WrappedTransport } from './wrap.js';

export { WrappedTransport, UPSTREAM_UNREACHABLE_CODE } from './wrap.js';

export type TransportKind = 'stdio' | 'http' | 'sse';
export const TRANSPORT_KINDS: readonly TransportKind[] = ['stdio', 'http', 'sse'];

export interface StdioTransportOptions {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface UrlTransportOptions {
  /** http(s) URL of the upstream MCP endpoint (Streamable HTTP endpoint, or the SSE GET endpoint). */
  url: string | URL;
  /** Extra request headers sent on every request (e.g. Authorization). */
  headers?: Record<string, string>;
}

export type UpstreamTransportOptions =
  | ({ transport: 'stdio' } & StdioTransportOptions)
  | ({ transport: 'http' } & UrlTransportOptions)
  | ({ transport: 'sse' } & UrlTransportOptions);

/** Parse and check an upstream URL. Throws a plain Error with a readable message. */
export function parseUpstreamUrl(url: string | URL): URL {
  let parsed: URL;
  try {
    parsed = url instanceof URL ? url : new URL(url);
  } catch {
    throw new Error(`invalid URL '${String(url)}'`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`unsupported URL scheme '${parsed.protocol}' (expected http: or https:)`);
  }
  return parsed;
}

/** Child-process server over stdio. Same settings the proxy uses by default (stderr inherited). */
export function createStdioTransport(opts: StdioTransportOptions): ToolguardTransport {
  const inner = new StdioClientTransport({
    command: opts.command,
    args: opts.args ?? [],
    ...(opts.env ? { env: opts.env } : {}),
    ...(opts.cwd ? { cwd: opts.cwd } : {}),
    stderr: 'inherit',
  });
  return new WrappedTransport('stdio', inner);
}

function requestInit(headers: Record<string, string> | undefined): { requestInit?: RequestInit } {
  return headers && Object.keys(headers).length > 0 ? { requestInit: { headers: { ...headers } } } : {};
}

/** Remote server over MCP Streamable HTTP. */
export function createHttpTransport(opts: UrlTransportOptions): ToolguardTransport {
  const inner = new StreamableHTTPClientTransport(parseUpstreamUrl(opts.url), requestInit(opts.headers));
  return new WrappedTransport('http', inner);
}

/** Remote server over the legacy HTTP+SSE transport. Headers apply to the GET stream and every POST. */
export function createSseTransport(opts: UrlTransportOptions): ToolguardTransport {
  const inner = new SSEClientTransport(parseUpstreamUrl(opts.url), requestInit(opts.headers));
  return new WrappedTransport('sse', inner);
}

export function createUpstreamTransport(opts: UpstreamTransportOptions): ToolguardTransport {
  switch (opts.transport) {
    case 'stdio':
      return createStdioTransport(opts);
    case 'http':
      return createHttpTransport(opts);
    case 'sse':
      return createSseTransport(opts);
    default: {
      const t: never = opts;
      throw new Error(`unknown transport '${String((t as { transport?: unknown }).transport)}'`);
    }
  }
}

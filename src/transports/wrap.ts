/**
 * Shared wrapper that turns an SDK client Transport into a contract ToolguardTransport.
 *
 * It only relays: it never inspects or rewrites traffic (inspection is the proxy's job). Two small
 * conveniences that the SDK Client normally does for itself and the proxy does not:
 *  - it remembers the protocol version from the upstream `initialize` result and hands it to the
 *    inner transport (`setProtocolVersion`), so HTTP/SSE send the `mcp-protocol-version` header;
 *  - when a send to the upstream fails for a JSON-RPC request (e.g. the HTTP server is unreachable),
 *    it answers that request with a JSON-RPC error so the MCP client does not hang until its timeout.
 *    The original error is still rethrown so the proxy reports it.
 */
import type { JSONRPCMessage, MessageExtraInfo } from '@modelcontextprotocol/sdk/types.js';
import type { TransportSendOptions } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { ToolguardTransport, Transport } from '../contracts.js';

/** JSON-RPC error code used when the upstream could not be reached. Implementation-defined server error range. */
export const UPSTREAM_UNREACHABLE_CODE = -32000;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export class WrappedTransport implements ToolguardTransport {
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  onmessage?: (<T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void) | undefined;

  /** ids (as JSON) of `initialize` requests we forwarded, to spot their results. */
  private readonly initializeIds = new Set<string>();
  /** Set once close() is called: errors from aborting in-flight requests/streams are expected then. */
  private closing = false;

  constructor(
    readonly name: ToolguardTransport['name'],
    /** The SDK transport being wrapped. Exposed for diagnostics and tests. */
    readonly inner: Transport,
  ) {
    inner.onclose = () => this.onclose?.();
    inner.onerror = (err: Error) => {
      if (!this.closing) this.onerror?.(err);
    };
    inner.onmessage = (message: JSONRPCMessage, extra?: MessageExtraInfo) => {
      this.noteProtocolVersion(message);
      this.onmessage?.(message, extra);
    };
  }

  get sessionId(): string | undefined {
    return this.inner.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  connect(): Promise<void> {
    return this.start();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    const m = message as unknown as Record<string, unknown>;
    const isRequest = typeof m.method === 'string' && 'id' in m && m.id !== undefined && m.id !== null;
    if (isRequest && m.method === 'initialize') this.initializeIds.add(JSON.stringify(m.id));
    try {
      await this.inner.send(message, options);
    } catch (err) {
      if (isRequest) {
        const reply = {
          jsonrpc: '2.0' as const,
          id: m.id as string | number,
          error: { code: UPSTREAM_UNREACHABLE_CODE, message: `mcp-toolguard: upstream ${this.name} server error: ${errorMessage(err)}` },
        };
        // Deliver asynchronously so the caller's own error handling runs first.
        queueMicrotask(() => this.onmessage?.(reply as JSONRPCMessage));
      }
      throw err;
    }
  }

  close(): Promise<void> {
    this.closing = true;
    return this.inner.close();
  }

  private noteProtocolVersion(message: JSONRPCMessage): void {
    if (this.initializeIds.size === 0) return;
    const m = message as unknown as Record<string, unknown>;
    if (!('id' in m)) return;
    const key = JSON.stringify(m.id);
    if (!this.initializeIds.has(key)) return;
    this.initializeIds.delete(key);
    if (isRecord(m.result) && typeof m.result.protocolVersion === 'string') {
      try {
        this.inner.setProtocolVersion?.(m.result.protocolVersion);
      } catch {
        // Not fatal: the header is optional for most servers.
      }
    }
  }
}

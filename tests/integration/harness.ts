// Integration harness: SDK Client ⇄ real proxy ⇄ in-process McpServer, all over InMemoryTransport.
// Uses the REAL policy, detection, audit and proxy modules, only via their index.ts.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  BLOCK_MARKER,
  type AuditEvent,
  type AuditEventInput,
  type AuditLogger,
  type ToolguardPolicy,
  type ProxyHandle,
  type ToolPinStore,
} from '../../src/contracts.js';
import { createAuditLogger } from '../../src/audit/index.js';
import { createDetector, createPinStore } from '../../src/detection/index.js';
import { createPolicyEngine, validatePolicy } from '../../src/policy/index.js';
import { startProxy } from '../../src/proxy/index.js';

export interface HarnessOptions {
  /** Raw policy object, passed through validatePolicy() (defaults filled in). Omit for built-in defaults. */
  policy?: Record<string, unknown>;
  serverId?: string;
  /** Reuse a pin store across sessions (e.g. to simulate a restart). */
  pins?: ToolPinStore;
  /** Audit file; in-memory if omitted. */
  auditFile?: string;
}

export interface Harness {
  client: Client;
  proxy: ProxyHandle;
  policy: ToolguardPolicy;
  pins: ToolPinStore;
  /** Every audit event the proxy logged, in order. */
  events: AuditEvent[];
  listChangedCount(): number;
  listToolNames(): Promise<string[]>;
  call(name: string, args?: Record<string, unknown>): Promise<CallOutcome>;
  close(): Promise<void>;
}

export interface CallOutcome {
  text: string;
  isError: boolean;
  blocked: boolean;
}

export async function startHarness(server: McpServer, opts: HarnessOptions = {}): Promise<Harness> {
  const policy = validatePolicy(opts.policy ?? { version: 1 });
  const engine = createPolicyEngine(policy);
  const pins = opts.pins ?? createPinStore(undefined);
  const detector = createDetector({ pins, disabledRules: engine.disabledRules() });

  // The contract's AuditLogger has no read API, so record what log() returns.
  const inner = createAuditLogger({ file: opts.auditFile, stderr: false });
  const events: AuditEvent[] = [];
  const audit: AuditLogger = {
    log(input: AuditEventInput) {
      const ev = inner.log(input);
      events.push(ev);
      return ev;
    },
    close: () => inner.close(),
  };

  const [clientEnd, proxyFront] = InMemoryTransport.createLinkedPair();
  const [proxyBack, serverEnd] = InMemoryTransport.createLinkedPair();

  await server.connect(serverEnd);
  const proxy = await startProxy({
    serverId: opts.serverId ?? 'test-server',
    sessionId: 'test-session',
    policy: engine,
    detector,
    audit,
    transports: { client: proxyFront, server: proxyBack },
  });

  const client = new Client({ name: 'integration-client', version: '0.0.0' });
  let listChanged = 0;
  client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChanged++;
  });
  await client.connect(clientEnd);

  return {
    client,
    proxy,
    policy,
    pins,
    events,
    listChangedCount: () => listChanged,
    async listToolNames() {
      const { tools } = await client.listTools();
      return tools.map((t) => t.name);
    },
    async call(name, args = {}) {
      const res = await client.callTool({ name, arguments: args });
      const content = (res.content ?? []) as Array<{ type: string; text?: string }>;
      const text = content
        .filter((c) => c.type === 'text')
        .map((c) => c.text ?? '')
        .join('\n');
      return { text, isError: Boolean(res.isError), blocked: text.startsWith(BLOCK_MARKER) };
    },
    async close() {
      await client.close().catch(() => {});
      await proxy.close().catch(() => {});
      await server.close().catch(() => {});
      await audit.close().catch(() => {});
    },
  };
}

/** Wait until predicate is true (polling), or throw after timeoutMs. */
export async function waitFor(pred: () => boolean, timeoutMs = 2000, what = 'condition'): Promise<void> {
  const start = Date.now();
  while (!pred()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

export const ruleIdsOf = (e: AuditEvent): string[] => (e.findings ?? []).map((f) => f.ruleId);

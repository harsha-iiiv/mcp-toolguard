// Test helpers for the proxy unit tests: fake Detector / PolicyEngine / AuditLogger and a harness
// that wires SDK Client ⇄ proxy ⇄ SDK McpServer over InMemoryTransport pairs.
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ListRootsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type {
  ApprovalStore,
  RulePlugin,
  Action,
  AuditEvent,
  AuditEventInput,
  AuditLogger,
  Decision,
  Detector,
  Finding,
  ToolguardPolicy,
  InspectionContext,
  InspectionTarget,
  PolicyEngine,
  ProxyHandle,
  Severity,
} from '../../../src/contracts.js';
import { startProxy } from '../../../src/proxy/index.js';

/**
 * Fake detector. Triggers:
 *  - definition description containing EVIL → critical; WARNME → high; THROW → throws
 *  - call arguments containing AKIA → critical; WARNME → high; THROW → throws
 *  - result text containing INJECT → critical; WARNME → high; THROW → throws
 */
export function fakeDetector(): Detector & { calls: { target: InspectionTarget; ctx: InspectionContext }[] } {
  const calls: { target: InspectionTarget; ctx: InspectionContext }[] = [];
  return {
    rules: [],
    calls,
    inspect(target, ctx) {
      calls.push({ target, ctx });
      let text: string;
      let toolName: string;
      if (target.kind === 'tool_definition') {
        text = target.tool.description ?? '';
        toolName = target.tool.name;
      } else if (target.kind === 'tool_call') {
        text = JSON.stringify(target.arguments);
        toolName = target.toolName;
      } else {
        text = JSON.stringify(target.result);
        toolName = target.toolName;
      }
      if (text.includes('THROW')) throw new Error('detector exploded');
      const findings: Finding[] = [];
      const add = (ruleId: string, severity: Severity, needle: string) => {
        if (text.includes(needle)) findings.push({ ruleId, severity, message: `${ruleId} in ${toolName}`, toolName });
      };
      add('fake-critical', 'critical', target.kind === 'tool_definition' ? 'EVIL' : target.kind === 'tool_call' ? 'AKIA' : 'INJECT');
      add('fake-high', 'high', 'WARNME');
      return findings;
    },
  };
}

const SEVERITY_ACTION: Record<Severity, Action> = { low: 'allow', medium: 'warn', high: 'warn', critical: 'block' };
const RANK: Record<Action, number> = { allow: 0, warn: 1, block: 2 };

export function fakePolicy(
  overrides: { logAllowed?: boolean; unknown?: Action; throwOn?: (t: InspectionTarget) => boolean } = {},
): PolicyEngine & { evaluations: { target: InspectionTarget; findings: Finding[]; extra?: { knownTool?: boolean } }[] } {
  const policy = {
    version: 1,
    mode: 'enforce',
    tools: { allow: [], deny: [], unlisted: 'warn', unknown: overrides.unknown ?? 'warn' },
    severityActions: SEVERITY_ACTION,
    rules: {},
    arguments: [],
    pins: { file: '' },
    audit: { file: '', redact: true, logAllowed: overrides.logAllowed ?? true },
    spend: { maxSpendPerTaskUsd: null, costs: {}, defaultCostUsd: 0 },
    approval: { tools: [], file: '' },
    learning: { enabled: false, file: '', minSamples: 50 },
    plugins: { enabled: false, dir: './toolguard-plugins' },
  } satisfies ToolguardPolicy;
  const evaluations: { target: InspectionTarget; findings: Finding[]; extra?: { knownTool?: boolean } }[] = [];
  return {
    policy,
    evaluations,
    disabledRules: () => [],
    evaluate(target, findings, extra): Decision {
      evaluations.push({ target, findings, extra });
      if (overrides.throwOn?.(target)) throw new Error('policy exploded');
      let action: Action = 'allow';
      const reasons: string[] = [];
      for (const f of findings) {
        // Unknown-tool findings are decided by tools.unknown, like the real engine.
        const a = f.ruleId === 'toolguard.unknown-tool-call' ? policy.tools.unknown : SEVERITY_ACTION[f.severity];
        if (RANK[a] > RANK[action]) action = a;
        if (a !== 'allow') reasons.push(f.message);
      }
      return { action, wouldBlock: false, reasons, findings };
    },
  };
}

export function fakeAudit(): AuditLogger & { events: AuditEventInput[] } {
  const events: AuditEventInput[] = [];
  return {
    events,
    log(event): AuditEvent {
      events.push(event);
      return { ...event, v: 1, seq: events.length - 1, ts: new Date().toISOString(), prevHash: '0'.repeat(64), hash: 'x' };
    },
    async close() {},
  };
}

export interface ToolSpec {
  name: string;
  description: string;
  /** What the tool returns as text. */
  reply?: (args: Record<string, unknown>) => string;
}

export interface Harness {
  client: Client;
  server: McpServer;
  handle: ProxyHandle;
  detector: ReturnType<typeof fakeDetector>;
  policy: ReturnType<typeof fakePolicy>;
  audit: ReturnType<typeof fakeAudit>;
  /** Tool names in the order the upstream server actually executed them. */
  serverCalls: { name: string; args: Record<string, unknown> }[];
  /** Raw messages the upstream server received. */
  serverReceived: unknown[];
  /** Raw messages the client received. */
  clientReceived: unknown[];
  clientTransport: InMemoryTransport;
  serverTransport: InMemoryTransport;
}

export async function createHarness(
  tools: ToolSpec[],
  opts: {
    policy?: ReturnType<typeof fakePolicy>;
    detector?: ReturnType<typeof fakeDetector>;
    roots?: boolean;
    plugins?: RulePlugin[];
    approvals?: ApprovalStore;
  } = {},
): Promise<Harness> {
  const detector = opts.detector ?? fakeDetector();
  const policy = opts.policy ?? fakePolicy();
  const audit = fakeAudit();
  const serverCalls: Harness['serverCalls'] = [];

  const server = new McpServer({ name: 'upstream', version: '1.0.0' });
  for (const t of tools) {
    server.registerTool(
      t.name,
      { description: t.description, inputSchema: { text: z.string().optional() } },
      async (args) => {
        serverCalls.push({ name: t.name, args });
        return { content: [{ type: 'text', text: t.reply ? t.reply(args) : `ok:${t.name}` }] };
      },
    );
  }

  const [clientTransport, proxyClientSide] = InMemoryTransport.createLinkedPair();
  const [proxyServerSide, serverTransport] = InMemoryTransport.createLinkedPair();

  const serverReceived: unknown[] = [];
  const clientReceived: unknown[] = [];

  await server.connect(serverTransport);
  const origServerOnMessage = serverTransport.onmessage!;
  serverTransport.onmessage = (m, extra) => {
    serverReceived.push(m);
    origServerOnMessage(m, extra);
  };

  const handle = await startProxy({
    serverId: 'test-server',
    sessionId: 'sess-1',
    policy,
    detector,
    audit,
    transports: { client: proxyClientSide, server: proxyServerSide },
    ...(opts.plugins ? { plugins: opts.plugins } : {}),
    ...(opts.approvals ? { approvals: opts.approvals } : {}),
  });

  const client = new Client(
    { name: 'test-client', version: '1.0.0' },
    { capabilities: opts.roots ? { roots: { listChanged: false } } : {} },
  );
  if (opts.roots) {
    client.setRequestHandler(ListRootsRequestSchema, async () => ({ roots: [{ uri: 'file:///tmp/root', name: 'root' }] }));
  }
  await client.connect(clientTransport);
  const origClientOnMessage = clientTransport.onmessage!;
  clientTransport.onmessage = (m, extra) => {
    clientReceived.push(m);
    origClientOnMessage(m, extra);
  };

  return {
    client,
    server,
    handle,
    detector,
    policy,
    audit,
    serverCalls,
    serverReceived,
    clientReceived,
    clientTransport,
    serverTransport,
  };
}

export function textOf(result: unknown): string {
  const content = (result as { content?: { type: string; text?: string }[] }).content ?? [];
  return content.map((c) => c.text ?? '').join('');
}

export function targetEvents(audit: ReturnType<typeof fakeAudit>): AuditEventInput[] {
  return audit.events.filter((e) => e.kind !== 'lifecycle');
}

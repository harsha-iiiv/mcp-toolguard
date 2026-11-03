/**
 * mcp-toolguard proxy core: wires raw JSON-RPC between the MCP client (our stdio) and the upstream
 * server (child process), inspecting tools/list, tools/call and tool results on the way.
 *
 * Never writes to process.stdout except through the client transport. Diagnostics go to stderr.
 */
import type { ChildProcess } from 'node:child_process';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import {
  APPROVAL_MARKER,
  PROXY_RULE_IDS,
  VERDICT_ORDER,
  type Severity,
  type ToolCall,
  type ToolResult,
  type Verdict,
  type VerdictAction,
  type AuditEventInput,
  type Decision,
  type Direction,
  type Finding,
  type InspectionTarget,
  type JsonRpcId,
  type ProxyHandle,
  type ProxyOptions,
  type StartProxy,
  type ToolDescriptor,
  type Transport,
} from '../contracts.js';
import { buildBlockResult, classifyMessage, idKey } from './messages.js';

/** Reason used when detection or policy evaluation throws (fail closed). */
export const INTERNAL_ERROR_REASON = 'internal error';

/** Reason added when a tool hidden earlier in the session shows up again in a later tools/list. */
export const PREVIOUSLY_HIDDEN_REASON = 'tool was hidden earlier in this session';

interface PendingRequest {
  method: 'tools/list' | 'tools/call';
  toolName?: string;
  /** v0.2: the call as given to plugins, so the result can be checked against it. */
  call?: ToolCall;
}

const VERDICT_SEVERITY: Record<VerdictAction, Severity> = { allow: 'low', warn: 'medium', require_approval: 'medium', block: 'high' };

/** Outcome of the v0.2 hooks layered on a policy Decision. */
interface HookedDecision {
  decision: Decision;
  /** True when the strongest effective verdict is require_approval (enforce mode only). */
  needsApproval: boolean;
  approvalReasons: string[];
}

type ShutdownReason = 'client_closed' | 'server_closed' | 'close_called';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function diag(message: string): void {
  try {
    process.stderr.write(`[mcp-toolguard] ${message}\n`);
  } catch {
    // nothing else we can do
  }
}

export const startProxy: StartProxy = async (opts: ProxyOptions): Promise<ProxyHandle> => {
  const { serverId, sessionId, policy, detector, audit } = opts;

  const usingDefaultClient = !opts.transports?.client;
  const usingDefaultServer = !opts.transports?.server;

  const clientTransport: Transport = opts.transports?.client ?? new StdioServerTransport();
  let serverTransport: Transport;
  if (opts.transports?.server) {
    serverTransport = opts.transports.server;
  } else {
    if (!opts.command) throw new Error('startProxy: either `command` or `transports.server` is required');
    serverTransport = new StdioClientTransport({
      command: opts.command,
      args: opts.args ?? [],
      ...(opts.env ? { env: opts.env } : {}),
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
      stderr: 'inherit',
    });
  }

  const hidden = new Set<string>();
  const known = new Set<string>();
  /** Requests from the client to the server whose responses we must inspect. Keyed by idKey(id). */
  const pendingFromClient = new Map<string, PendingRequest>();

  let started = false;
  let serverStarted = false;
  let shutdownPromise: Promise<void> | undefined;
  let childExit: { code: number | null; signal: NodeJS.Signals | null } | undefined;
  let resolveDone!: (code: number) => void;
  const done = new Promise<number>((resolve) => {
    resolveDone = resolve;
  });

  // ── audit helpers ─────────────────────────────────────────────────────────

  function safeLog(event: Omit<AuditEventInput, 'sessionId' | 'serverId'>): void {
    try {
      audit.log({ sessionId, serverId, ...event });
    } catch (err) {
      diag(`audit log failed: ${errorMessage(err)}`);
    }
  }

  function lifecycle(event: string, data?: unknown): void {
    safeLog({ kind: 'lifecycle', event, ...(data !== undefined ? { data } : {}) });
  }

  function reportError(context: string, err: unknown): void {
    const msg = `${context}: ${errorMessage(err)}`;
    diag(msg);
    lifecycle('error', { message: msg });
  }

  function logAllowedEnabled(): boolean {
    try {
      return policy.policy.audit.logAllowed !== false;
    } catch {
      return true;
    }
  }

  /** Run detector + policy. Fails closed (block, 'internal error') if either throws. */
  function decide(
    target: InspectionTarget,
    direction: Direction,
    extraFindings: Finding[] = [],
    extra?: { knownTool?: boolean },
  ): Decision {
    let findings: Finding[] = [...extraFindings];
    try {
      findings = [...detector.inspect(target, { serverId, direction }), ...extraFindings];
      const decision = policy.evaluate(target, findings, extra);
      if (!decision || (decision.action !== 'allow' && decision.action !== 'warn' && decision.action !== 'block')) {
        throw new Error(`policy returned an invalid decision`);
      }
      return decision;
    } catch (err) {
      reportError(`inspection of ${target.kind} failed`, err);
      return { action: 'block', wouldBlock: false, reasons: [INTERNAL_ERROR_REASON], findings };
    }
  }

  /**
   * v0.2: run approvals + plugins and merge their verdicts into the policy decision (strongest wins,
   * VERDICT_ORDER). Monitor mode turns block/require_approval into warn with wouldBlock. A throwing
   * hook fails closed (block, 'internal error').
   */
  function applyHooks(base: Decision, call: ToolCall, result: ToolResult | undefined): HookedDecision {
    const verdicts: Verdict[] = [];
    const policyObj = policy.policy;
    try {
      for (const plugin of opts.plugins ?? []) {
        let v: Verdict | null;
        try {
          v = plugin.check(call, result, policyObj);
        } catch (err) {
          reportError(`plugin '${plugin.id}' threw`, err);
          v = { action: 'block', reason: `${plugin.id}: ${INTERNAL_ERROR_REASON}`, ruleId: plugin.id };
        }
        if (v && v.action !== 'allow') verdicts.push(v);
        else if (v && v.action === 'allow' && v.reason) verdicts.push(v);
      }
      // Approvals last, and only if nothing else blocks: otherwise a one-time approval would be
      // consumed by a call that never reaches the server.
      if (!result && opts.approvals && !verdicts.some((v) => v.action === 'block')) {
        const v = opts.approvals.check(call, policyObj);
        if (v) verdicts.push(v);
      }
    } catch (err) {
      reportError('approval check threw', err);
      verdicts.push({ action: 'block', reason: `approval: ${INTERNAL_ERROR_REASON}`, ruleId: 'approval' });
    }
    if (verdicts.length === 0) return { decision: base, needsApproval: false, approvalReasons: [] };

    const monitor = policyObj.mode === 'monitor';
    const rank = (a: VerdictAction): number => VERDICT_ORDER.indexOf(a);
    let strongest: VerdictAction = base.action;
    let wouldBlock = base.wouldBlock;
    const reasons = [...base.reasons];
    const findings = [...base.findings];
    const approvalReasons: string[] = [];
    for (const v of verdicts) {
      const reason = `${v.ruleId}: ${v.reason}`;
      if (v.action !== 'allow' && !reasons.includes(reason)) reasons.push(reason);
      findings.push({
        ruleId: v.ruleId,
        severity: v.severity ?? VERDICT_SEVERITY[v.action],
        message: v.reason,
        toolName: call.toolName,
      });
      let action = v.action;
      if (monitor && (action === 'block' || action === 'require_approval')) {
        wouldBlock = true;
        action = 'warn';
      }
      if (action === 'require_approval') approvalReasons.push(reason);
      if (rank(action) > rank(strongest)) strongest = action;
    }
    // Most severe first, matching the policy engine's ordering of its own reasons.
    reasons.sort((a, b) => Number(b.includes(INTERNAL_ERROR_REASON)) - Number(a.includes(INTERNAL_ERROR_REASON)));
    if (strongest === 'require_approval') {
      return {
        decision: { action: 'block', wouldBlock, reasons, findings },
        needsApproval: true,
        approvalReasons,
      };
    }
    return { decision: { action: strongest as Decision['action'], wouldBlock, reasons, findings }, needsApproval: false, approvalReasons: [] };
  }

  function auditTarget(
    target: InspectionTarget,
    decision: Decision,
    meta: { direction: Direction; method: string; requestId?: JsonRpcId; toolName: string; data?: unknown },
  ): void {
    const cleanAllow = decision.action === 'allow' && decision.findings.length === 0;
    if (cleanAllow && !logAllowedEnabled()) return;
    safeLog({
      kind: target.kind,
      direction: meta.direction,
      method: meta.method,
      ...(meta.requestId !== undefined ? { requestId: meta.requestId } : {}),
      toolName: meta.toolName,
      action: decision.action,
      wouldBlock: decision.wouldBlock,
      reasons: decision.reasons,
      findings: decision.findings,
      ...(meta.data !== undefined ? { data: meta.data } : {}),
    });
  }

  // ── sending ───────────────────────────────────────────────────────────────

  function sendToClient(message: unknown): void {
    if (shutdownPromise) return;
    clientTransport.send(message as JSONRPCMessage).catch((err: unknown) => reportError('send to client failed', err));
  }

  function sendToServer(message: unknown): void {
    if (shutdownPromise) return;
    serverTransport.send(message as JSONRPCMessage).catch((err: unknown) => reportError('send to server failed', err));
  }

  // ── inspection handlers ───────────────────────────────────────────────────

  function handleToolsList(message: Record<string, unknown>, result: Record<string, unknown>, requestId: JsonRpcId): unknown {
    const tools = result.tools;
    if (!Array.isArray(tools)) return message;
    const kept: unknown[] = [];
    for (const entry of tools) {
      if (!isRecord(entry) || typeof entry.name !== 'string') {
        diag('dropping malformed tool entry from tools/list result');
        continue;
      }
      const tool = entry as unknown as ToolDescriptor;
      known.add(tool.name);
      const target: InspectionTarget = { kind: 'tool_definition', tool };
      let decision = decide(target, 'server_to_client');
      if (decision.action !== 'block' && hidden.has(tool.name)) {
        // Hidden is sticky for the session: a server cannot un-hide a tool by flipping its definition back.
        decision = { ...decision, action: 'block', reasons: [...decision.reasons, PREVIOUSLY_HIDDEN_REASON] };
      }
      auditTarget(target, decision, {
        direction: 'server_to_client',
        method: 'tools/list',
        requestId,
        toolName: tool.name,
      });
      if (decision.action === 'block') {
        hidden.add(tool.name);
      } else {
        kept.push(entry);
      }
    }
    return { ...message, result: { ...result, tools: kept } };
  }

  /**
   * Returns the result to send back instead of forwarding (block or approval required), or undefined
   * to forward. `call` is filled in for the pending map.
   */
  function handleToolCall(
    id: JsonRpcId,
    toolName: string,
    args: Record<string, unknown>,
    taskId: string,
    out: { call?: ToolCall },
  ): unknown | undefined {
    const target: InspectionTarget = { kind: 'tool_call', requestId: id, toolName, arguments: args };
    const call: ToolCall = { ...target, kind: 'tool_call', serverId, taskId };
    out.call = call;
    const extraFindings: Finding[] = [];
    const isHidden = hidden.has(toolName);
    const isKnown = known.has(toolName);
    if (isHidden) {
      extraFindings.push({
        ruleId: PROXY_RULE_IDS.HIDDEN_TOOL_CALL,
        severity: 'critical',
        message: `call to tool '${toolName}' which was hidden from tools/list by a block decision`,
        toolName,
      });
    } else if (!isKnown) {
      extraFindings.push({
        ruleId: PROXY_RULE_IDS.UNKNOWN_TOOL_CALL,
        severity: 'medium',
        message: `call to tool '${toolName}' which was never listed by tools/list`,
        toolName,
      });
    }
    let decision = decide(target, 'client_to_server', extraFindings, { knownTool: isKnown });
    if (isHidden && decision.action !== 'block') {
      const hiddenFinding = extraFindings[0]!;
      const reasons = decision.reasons.includes(hiddenFinding.message)
        ? decision.reasons
        : [hiddenFinding.message, ...decision.reasons];
      const findings = decision.findings.some((f) => f.ruleId === PROXY_RULE_IDS.HIDDEN_TOOL_CALL)
        ? decision.findings
        : [hiddenFinding, ...decision.findings];
      decision = { ...decision, action: 'block', reasons, findings };
    }
    let needsApproval = false;
    let approvalReasons: string[] = [];
    if (decision.action !== 'block') {
      ({ decision, needsApproval, approvalReasons } = applyHooks(decision, call, undefined));
    }
    auditTarget(target, decision, {
      direction: 'client_to_server',
      method: 'tools/call',
      requestId: id,
      toolName,
      data: args,
    });
    if (needsApproval) {
      return { content: [{ type: 'text', text: `${APPROVAL_MARKER}: ${approvalReasons.join('; ')}` }], isError: true };
    }
    return decision.action === 'block' ? buildBlockResult(decision.reasons) : undefined;
  }

  function handleToolResult(
    message: Record<string, unknown>,
    id: JsonRpcId,
    toolName: string,
    result: Record<string, unknown>,
    call?: ToolCall,
  ): unknown {
    const target: InspectionTarget = { kind: 'tool_result', requestId: id, toolName, result };
    let decision = decide(target, 'server_to_client');
    if (call) {
      // Run plugins even when the result is already blocked: the upstream did the work, so spend must
      // still be charged. Merging keeps the strongest action, so a block stays a block.
      // require_approval on a result makes no sense: applyHooks reports it as block.
      decision = applyHooks(decision, call, target).decision;
    }
    auditTarget(target, decision, { direction: 'server_to_client', method: 'tools/call', requestId: id, toolName });
    if (decision.action === 'block') {
      return { jsonrpc: '2.0', id, result: buildBlockResult(decision.reasons) };
    }
    return message;
  }

  // ── message routing ───────────────────────────────────────────────────────

  function onClientMessage(message: JSONRPCMessage): void {
    try {
      const c = classifyMessage(message);
      if (c.type === 'request' && c.method === 'tools/list') {
        pendingFromClient.set(idKey(c.id), { method: 'tools/list' });
      } else if (c.type === 'request' && c.method === 'tools/call') {
        const name = c.params?.name;
        if (typeof name === 'string') {
          const args = isRecord(c.params?.arguments) ? c.params.arguments : {};
          const meta = isRecord(c.params?._meta) ? c.params._meta : undefined;
          const taskId = typeof meta?.taskId === 'string' && meta.taskId ? meta.taskId : sessionId;
          const out: { call?: ToolCall } = {};
          const replacement = handleToolCall(c.id, name, args, taskId, out);
          if (replacement) {
            sendToClient({ jsonrpc: '2.0', id: c.id, result: replacement });
            return;
          }
          pendingFromClient.set(idKey(c.id), { method: 'tools/call', toolName: name, ...(out.call ? { call: out.call } : {}) });
        } else {
          // Malformed call: the server will reject it, but still inspect whatever comes back.
          pendingFromClient.set(idKey(c.id), { method: 'tools/call', toolName: '' });
        }
      }
      sendToServer(message);
    } catch (err) {
      // Should be unreachable (decide() never throws). Fail closed: drop the message.
      reportError('handling client message failed', err);
      const c = classifyMessage(message);
      if (c.type === 'request') {
        sendToClient({ jsonrpc: '2.0', id: c.id, result: buildBlockResult([INTERNAL_ERROR_REASON]) });
      }
    }
  }

  function onServerMessage(message: JSONRPCMessage): void {
    try {
      const c = classifyMessage(message);
      if ((c.type === 'result' || c.type === 'error') && c.id !== null) {
        const key = idKey(c.id);
        const pending = pendingFromClient.get(key);
        if (pending) {
          pendingFromClient.delete(key);
          const msg = message as unknown as Record<string, unknown>;
          if (c.type === 'result') {
            if (pending.method === 'tools/list') {
              sendToClient(handleToolsList(msg, c.result, c.id));
            } else {
              sendToClient(handleToolResult(msg, c.id, pending.toolName ?? '', c.result, pending.call));
            }
            return;
          }
          if (pending.method === 'tools/call') {
            // JSON-RPC error: forwarded unchanged, but audited.
            safeLog({
              kind: 'tool_result',
              direction: 'server_to_client',
              method: 'tools/call',
              requestId: c.id,
              toolName: pending.toolName ?? '',
              action: 'allow',
              wouldBlock: false,
              reasons: [],
              findings: [],
              data: { error: c.error },
            });
          }
        }
      }
      sendToClient(message);
    } catch (err) {
      reportError('handling server message failed', err);
      const c = classifyMessage(message);
      if (c.type === 'result') {
        sendToClient({ jsonrpc: '2.0', id: c.id, result: buildBlockResult([INTERNAL_ERROR_REASON]) });
      }
    }
  }

  // ── lifecycle ─────────────────────────────────────────────────────────────

  const onStdinEnd = (): void => {
    void shutdown('client_closed');
  };
  const onStdoutError = (err: unknown): void => {
    reportError('stdout error', err);
    void shutdown('client_closed');
  };

  function exitCodeFor(reason: ShutdownReason): number {
    if (reason !== 'server_closed') return 0;
    if (!childExit) return 0;
    if (typeof childExit.code === 'number') return childExit.code;
    return childExit.signal ? 1 : 0;
  }

  function shutdown(reason: ShutdownReason): Promise<void> {
    if (shutdownPromise) return shutdownPromise;
    shutdownPromise = (async () => {
      if (reason === 'server_closed') {
        lifecycle('server_exit', {
          ...(childExit ? { exitCode: childExit.code, signal: childExit.signal } : {}),
        });
      }
      if (usingDefaultClient) {
        process.stdin.off('end', onStdinEnd);
        process.stdin.off('close', onStdinEnd);
        process.stdout.off('error', onStdoutError);
      }
      await Promise.allSettled([
        Promise.resolve().then(() => clientTransport.close()),
        Promise.resolve().then(() => serverTransport.close()),
      ]);
      pendingFromClient.clear();
      lifecycle('stop', { reason });
      resolveDone(exitCodeFor(reason));
    })();
    return shutdownPromise;
  }

  clientTransport.onmessage = onClientMessage;
  serverTransport.onmessage = onServerMessage;
  clientTransport.onerror = (err: Error) => {
    if (started) reportError('client transport error', err);
  };
  serverTransport.onerror = (err: Error) => {
    if (started) reportError('server transport error', err);
  };
  clientTransport.onclose = () => {
    if (serverStarted) void shutdown('client_closed');
  };
  serverTransport.onclose = () => {
    if (serverStarted) void shutdown('server_closed');
  };

  try {
    await serverTransport.start();
  } catch (err) {
    reportError('failed to start upstream server', err);
    throw new Error(`mcp-toolguard: failed to start upstream server: ${errorMessage(err)}`);
  }
  serverStarted = true;

  if (usingDefaultServer) {
    // StdioClientTransport does not expose the exit code; read it from the child process when available.
    const child = (serverTransport as unknown as { _process?: ChildProcess })._process;
    if (child && typeof child.once === 'function') {
      child.once('exit', (code, signal) => {
        childExit = { code, signal };
      });
    }
  }

  try {
    await clientTransport.start();
  } catch (err) {
    reportError('failed to start client transport', err);
    serverStarted = false;
    await Promise.allSettled([Promise.resolve().then(() => serverTransport.close())]);
    throw new Error(`mcp-toolguard: failed to start client transport: ${errorMessage(err)}`);
  }

  if (usingDefaultClient) {
    // StdioServerTransport does not notice EOF on stdin; we do.
    process.stdin.once('end', onStdinEnd);
    process.stdin.once('close', onStdinEnd);
    process.stdout.on('error', onStdoutError);
  }

  started = true;
  lifecycle('start', {
    ...(opts.command ? { command: opts.command, args: opts.args ?? [] } : {}),
  });

  return {
    done,
    async close(): Promise<void> {
      await shutdown('close_called');
      await done;
    },
    hiddenTools(): string[] {
      return [...hidden];
    },
  };
};

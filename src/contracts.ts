/**
 * mcp-toolguard: shared types, constants and module contracts.
 *
 * Architecture:
 *
 *   MCP client (Claude Desktop, Cursor, ...)
 *        │  stdin/stdout, newline-delimited JSON-RPC
 *        ▼
 *   ┌──────────────── mcp-toolguard run ────────────────┐
 *   │ proxy  ──► extract InspectionTarget(s)           │
 *   │        ──► Detector.inspect()   → Finding[]      │
 *   │        ──► PolicyEngine.evaluate() → Decision    │
 *   │        ──► AuditLogger.log()                     │
 *   │        ──► forward / rewrite / block             │
 *   └──────────────────────────────────────────────────┘
 *        │  child process stdin/stdout
 *        ▼
 *   real MCP server (stdio child process, or Streamable HTTP / SSE)
 *
 * Invariants
 *  - During `mcp-toolguard run`, process.stdout carries the MCP protocol. Only the proxy writes to it.
 *    Every other module writes human output to process.stderr or to files.
 *  - Detection is pure: no I/O except through the ToolPinStore it is given.
 *  - Policy evaluation is pure and synchronous.
 *  - No telemetry or cloud service. The only network traffic is to an upstream server URL the user gives.
 *  - ESM only. Relative imports use the `.js` extension.
 */

import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

// ─────────────────────────────────────────────────────────────────────────────
// Basics
// ─────────────────────────────────────────────────────────────────────────────

export const TOOLGUARD_VERSION = '0.2.0';

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export const SEVERITY_ORDER: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

/** allow < warn < block. `warn` forwards the message but logs and prints a stderr warning. */
export type Action = 'allow' | 'warn' | 'block';
export const ACTION_ORDER: readonly Action[] = ['allow', 'warn', 'block'];

export type Direction = 'client_to_server' | 'server_to_client';

export type JsonRpcId = string | number;

/** Shape of one entry in a `tools/list` result. */
export interface ToolDescriptor {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// What gets inspected
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The proxy turns JSON-RPC traffic into these targets. Only these three kinds are inspected;
 * all other messages are forwarded untouched (and logged as kind 'message' at debug level only).
 *
 *  - tool_definition: one per tool in every `tools/list` response (server → client).
 *  - tool_call:       a `tools/call` request (client → server).
 *  - tool_result:     the response to a `tools/call` request (server → client).
 */
export type InspectionTarget = ToolDefinitionTarget | ToolCallTarget | ToolResultTarget;

export interface ToolDefinitionTarget {
  kind: 'tool_definition';
  tool: ToolDescriptor;
}

export interface ToolCallTarget {
  kind: 'tool_call';
  requestId: JsonRpcId;
  toolName: string;
  arguments: Record<string, unknown>;
}

export interface ToolResultTarget {
  kind: 'tool_result';
  requestId: JsonRpcId;
  toolName: string;
  /** The `result` object of the JSON-RPC response (has `content`, maybe `structuredContent`, `isError`). */
  result: Record<string, unknown>;
}

export type TargetKind = InspectionTarget['kind'];

export interface InspectionContext {
  /** Stable identifier for the upstream server (CLI --server-id; default derived from the launched package/script). */
  serverId: string;
  direction: Direction;
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection  (src/detection)
// ─────────────────────────────────────────────────────────────────────────────

/** Built-in rule IDs. Policy files reference these strings. Do not rename. */
export const RULE_IDS = {
  /** Hidden/manipulative instructions inside a tool description or schema text. */
  TOOL_POISONING: 'tool-poisoning',
  /** Invisible / bidi / Unicode-tag characters in descriptions, arguments or results. */
  HIDDEN_UNICODE: 'hidden-unicode',
  /** A tool's definition (description or inputSchema) changed since it was first pinned. */
  RUG_PULL: 'rug-pull',
  /** A tool description that tries to override or redirect use of other tools. */
  TOOL_SHADOWING: 'tool-shadowing',
  /** Credentials / API keys / private keys found in tool-call arguments. */
  SECRET_EXFILTRATION: 'secret-exfiltration',
  /** Tool-call arguments referencing sensitive files (~/.ssh, .env, ~/.aws, /etc/shadow, ...) or path traversal. */
  SENSITIVE_PATH: 'sensitive-path',
  /** Shell metacharacters / command chaining in arguments. */
  COMMAND_INJECTION: 'command-injection',
  /** Prompt-injection phrasing inside tool results returned to the model. */
  RESULT_INJECTION: 'result-injection',
  /** Secrets present in tool results (data leaving the server toward the model/client). */
  SECRET_IN_RESULT: 'secret-in-result',
} as const;

export type BuiltinRuleId = (typeof RULE_IDS)[keyof typeof RULE_IDS];

/** Proxy-generated pseudo rule IDs (not detection rules, but appear in findings / audit). */
export const PROXY_RULE_IDS = {
  /** A tools/call for a tool that was removed from tools/list by a block decision. */
  HIDDEN_TOOL_CALL: 'toolguard.hidden-tool-call',
  /** A tools/call for a tool never seen in any tools/list response. */
  UNKNOWN_TOOL_CALL: 'toolguard.unknown-tool-call',
} as const;

export interface Finding {
  ruleId: string;
  severity: Severity;
  /** One-line human-readable explanation. */
  message: string;
  /** Short excerpt that triggered the rule. MUST be ≤ 200 chars. May contain secrets; the audit logger redacts. */
  evidence?: string;
  /** JSON-path-ish location, e.g. "description", "arguments.path", "result.content[0].text". */
  location?: string;
  toolName?: string;
}

export interface DetectionRule {
  id: string;
  description: string;
  defaultSeverity: Severity;
  appliesTo: readonly TargetKind[];
  detect(target: InspectionTarget, ctx: RuleContext): Finding[];
}

export interface RuleContext extends InspectionContext {
  pins: ToolPinStore;
}

/** A pinned fingerprint of a tool definition (trust-on-first-use). */
export interface ToolPin {
  serverId: string;
  toolName: string;
  /** sha256 hex of canonical JSON of { name, description, inputSchema }. */
  hash: string;
  description: string;
  firstSeen: string; // ISO-8601
}

export interface ToolPinStore {
  get(serverId: string, toolName: string): ToolPin | undefined;
  /** Insert or overwrite. Persists immediately if file-backed. */
  set(pin: ToolPin): void;
  list(serverId?: string): ToolPin[];
  /** Remove pins for a server (or one tool). Returns number removed. */
  reset(serverId: string, toolName?: string): number;
}

export interface Detector {
  readonly rules: readonly DetectionRule[];
  /** Run every enabled rule that applies to target.kind. Never throws: a rule that throws yields no findings
   *  and a single low-severity finding with ruleId 'toolguard.rule-error'. */
  inspect(target: InspectionTarget, ctx: InspectionContext): Finding[];
}

export interface DetectorOptions {
  pins: ToolPinStore;
  /** Rule IDs to skip. */
  disabledRules?: readonly string[];
  /** Extra rules appended after the built-ins. */
  extraRules?: readonly DetectionRule[];
}

/**
 * Rug-pull semantics (implemented by detection, relied on by the proxy):
 *  - First time (serverId, toolName) is seen → pin it, no finding.
 *  - Same hash → no finding.
 *  - Different hash → RUG_PULL finding, severity 'critical'. The pin is NOT updated
 *    (the user re-approves with `mcp-toolguard pins reset`).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Policy  (src/policy)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Policy file: YAML or JSON. Default lookup when --policy is not given:
 *   ./toolguard.yaml, ./toolguard.yml, ./toolguard.json, then built-in defaultPolicy().
 * All fields optional in the file; validatePolicy() fills defaults.
 */
export interface ToolguardPolicy {
  version: 1;
  /** enforce = block decisions are applied. monitor = never block; downgrade block→warn and set wouldBlock. */
  mode: 'enforce' | 'monitor';
  tools: {
    /** Glob patterns ('*' and '?' only) matched against tool names. Empty = everything allowed. */
    allow: string[];
    /** Glob patterns. Deny wins over allow. */
    deny: string[];
    /** Action for tools/call to a tool not matched by allow (only when allow is non-empty). */
    unlisted: Action;
    /** Action for tools/call of a tool never seen in tools/list. Default 'warn'. */
    unknown: Action;
  };
  /** Default action per severity when no rule override applies. */
  severityActions: Record<Severity, Action>;
  /** Per detection rule override. */
  rules: Record<string, RuleOverride>;
  /** Argument constraints for tools/call. */
  arguments: ArgumentRule[];
  pins: {
    /** Pin file path. '~' expands to home. Default '~/.mcp-toolguard/pins.json'. */
    file: string;
  };
  /** Spend cap. See SpendTracker. */
  spend: SpendPolicy;
  /** Human approval for matching tools/call. See ApprovalStore. */
  approval: ApprovalPolicy;
  /** Opt-in baseline learning. Never blocks; outliers are warn verdicts. */
  learning: LearningPolicy;
  /** v1.0: rule plugins. Loading third-party JS is opt-in. */
  plugins: PluginPolicy;
  audit: {
    /** JSONL audit log path. '~' expands. Default '~/.mcp-toolguard/audit.jsonl'. */
    file: string;
    /** Redact secrets before writing. Default true. */
    redact: boolean;
    /** Also log allowed traffic with no findings. Default true. */
    logAllowed: boolean;
  };
}

export interface SpendPolicy {
  /** Block further tools/call for a task once its running total reaches this (USD). null = no cap. Default null. */
  maxSpendPerTaskUsd: number | null;
  /** Cost per call in USD keyed by tool-name glob, e.g. { "brave_*": 0.005 }. First matching glob wins. Default {}. */
  costs: Record<string, number>;
  /** Cost for a call matching no glob. Default 0. */
  defaultCostUsd: number;
}

export interface ApprovalPolicy {
  /** Tool-name globs whose calls need one-time human approval (`mcp-toolguard approve <id>`). Default []. */
  tools: string[];
  /** Approval store. '~' expands. Default '~/.mcp-toolguard/approvals.json'. */
  file: string;
}

export interface LearningPolicy {
  /** Default false. Also enabled by `run --learning`. */
  enabled: boolean;
  /** '~' expands. Default '~/.mcp-toolguard/baseline.json'. */
  file: string;
  /** Calls per (server, tool) before outliers are scored. Default 50. */
  minSamples: number;
}

export interface PluginPolicy {
  /** Default false. Also enabled by `run --plugins <dir>`. */
  enabled: boolean;
  /** Directory of *.js / *.mjs plugin modules. Relative to cwd. Default './toolguard-plugins'. */
  dir: string;
}

export interface RuleOverride {
  enabled?: boolean; // default true
  action?: Action; // overrides severityActions for findings of this rule
  severity?: Severity; // re-label findings of this rule
}

export interface ArgumentRule {
  /** Glob on tool name. */
  tool: string;
  /** Dot path into arguments, e.g. "path" or "options.url". '*' matches every top-level string arg. */
  path: string;
  /** If any regex (JS source, case-insensitive) matches the stringified value → action. */
  deny?: string[];
  /** If set, value must match at least one regex, else → action. */
  allow?: string[];
  /** Default 'block'. */
  action?: Action;
  /** Shown in the reason. */
  reason?: string;
}

export interface Decision {
  /** Effective action after mode is applied. */
  action: Action;
  /** True in monitor mode when enforce mode would have blocked. */
  wouldBlock: boolean;
  /** Human-readable reasons, most severe first. Empty for clean allow. */
  reasons: string[];
  /** Findings after rule overrides (disabled rules removed, severities re-labelled). */
  findings: Finding[];
}

export interface PolicyEngine {
  readonly policy: ToolguardPolicy;
  /** Disabled rule IDs, for passing to DetectorOptions.disabledRules. */
  disabledRules(): string[];
  /**
   * Combine tool allow/deny lists, argument rules and findings into one Decision.
   * Final action = max over all contributions. Then: if mode === 'monitor' and action === 'block',
   * action becomes 'warn' and wouldBlock = true.
   * `extra.knownTool` is false when the proxy has never seen the tool in a tools/list response.
   */
  evaluate(target: InspectionTarget, findings: Finding[], extra?: { knownTool?: boolean }): Decision;
}

export class PolicyError extends Error {
  constructor(
    message: string,
    public readonly issues: string[] = [],
  ) {
    super(message);
    this.name = 'PolicyError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit  (src/audit)
// ─────────────────────────────────────────────────────────────────────────────

export type AuditKind = TargetKind | 'lifecycle';

export interface AuditEventInput {
  sessionId: string;
  serverId: string;
  kind: AuditKind;
  direction?: Direction;
  /** JSON-RPC method if relevant ('tools/list', 'tools/call'). */
  method?: string;
  requestId?: JsonRpcId;
  toolName?: string;
  action?: Action;
  wouldBlock?: boolean;
  reasons?: string[];
  findings?: Finding[];
  /** Small payload summary (e.g. tool arguments). Will be redacted & truncated by the logger. */
  data?: unknown;
  /** For lifecycle events: 'start' | 'stop' | 'server_exit' | 'error' | ... */
  event?: string;
}

/** One JSONL line. */
export interface AuditEvent extends AuditEventInput {
  v: 1;
  seq: number; // 0-based, monotonically increasing per file
  ts: string; // ISO-8601
  /** The previous line's `hash`; 64 zeros for the first line of a file. */
  prevHash: string;
  /** sha256 hex over canonicalJson(event without `hash`). */
  hash: string;
}

export interface AuditLogger {
  /** Synchronous append so ordering is guaranteed. Must never throw (report to stderr instead). */
  log(event: AuditEventInput): AuditEvent;
  close(): Promise<void>;
}

export interface AuditLoggerOptions {
  /** File path ('~' expands). If undefined, events are kept in memory only (tests). */
  file?: string;
  redact?: boolean; // default true
  /** Write one-line human summaries of warn/block events to stderr. Default true. */
  stderr?: boolean;
  /** Max serialized length for `data` before truncation. Default 2000. */
  maxDataLength?: number;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  /** seq of the first broken line, if any. */
  brokenAt?: number;
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy  (src/proxy)
// ─────────────────────────────────────────────────────────────────────────────

/** Text prefix of every message the proxy synthesizes for a blocked action. Tests grep for it. */
export const BLOCK_MARKER = '[mcp-toolguard] BLOCKED';

/**
 * Proxy behaviour on decisions:
 *  tool_definition: block → tool removed from the tools/list result (remembered as hidden for this session);
 *                   warn  → forwarded unchanged.
 *  tool_call:       block → NOT forwarded; the client receives a JSON-RPC *result* (not error) for the same id:
 *                           { content: [{ type: 'text', text: `${BLOCK_MARKER}: <reasons joined by '; '>` }], isError: true }
 *                   Calls to hidden tools are blocked with PROXY_RULE_IDS.HIDDEN_TOOL_CALL (severity critical).
 *                   Calls to never-listed tools get a PROXY_RULE_IDS.UNKNOWN_TOOL_CALL finding (severity medium);
 *                   policy decides (tools.unknown).
 *  tool_result:     block → result replaced with the same isError shape as above.
 *  Every inspected target produces exactly one audit event (respecting audit.logAllowed for clean allows).
 *  Non-inspected messages (initialize, ping, notifications, resources/*, prompts/*) pass through unchanged.
 */
export interface ProxyOptions {
  serverId: string;
  sessionId: string;
  policy: PolicyEngine;
  detector: Detector;
  audit: AuditLogger;
  /** Upstream server process. Ignored if `transports.server` is given. */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** Inject transports for tests. Defaults: client = StdioServerTransport (our stdio), server = StdioClientTransport(command). */
  transports?: {
    client?: Transport;
    server?: Transport;
  };
  /** Plugin and approval hooks. */
  plugins?: RulePlugin[];
  approvals?: ApprovalStore;
}

export interface ProxyHandle {
  /** Resolves with the exit code when either side closes. 0 on clean shutdown. */
  readonly done: Promise<number>;
  close(): Promise<void>;
  /** Tools currently hidden from the client because of block decisions. */
  hiddenTools(): string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Module export map — exact names each module's index.ts must export.
// ─────────────────────────────────────────────────────────────────────────────

/** src/proxy/index.ts */
export type StartProxy = (opts: ProxyOptions) => Promise<ProxyHandle>;

/** src/policy/index.ts */
export type DefaultPolicy = () => ToolguardPolicy;
export type ValidatePolicy = (raw: unknown) => ToolguardPolicy; // throws PolicyError
export type LoadPolicy = (file?: string, cwd?: string) => { policy: ToolguardPolicy; source: string }; // source = path or 'builtin'
export type CreatePolicyEngine = (policy: ToolguardPolicy) => PolicyEngine;

/** src/detection/index.ts */
export type CreateDetector = (opts: DetectorOptions) => Detector;
export type BuiltinRules = () => DetectionRule[];
export type CreatePinStore = (file?: string) => ToolPinStore; // undefined → in-memory
export type HashTool = (tool: ToolDescriptor) => string;

/** src/audit/index.ts */
export type CreateAuditLogger = (opts: AuditLoggerOptions) => AuditLogger;
export type VerifyAuditLog = (file: string) => VerifyResult;
export type RedactSecrets = <T>(value: T) => T;
export type CanonicalJson = (value: unknown) => string;

// ─────────────────────────────────────────────────────────────────────────────
// Plugins, transports, spend and approvals.
// ─────────────────────────────────────────────────────────────────────────────

/** A tools/call as seen by plugins, spend and approval. */
export interface ToolCall extends ToolCallTarget {
  serverId: string;
  /** params._meta.taskId if the client sent a string, else the proxy sessionId. */
  taskId: string;
}

/** A tools/call result as seen by plugins. */
export type ToolResult = ToolResultTarget;

/** The policy as seen by plugins. */
export type Policy = ToolguardPolicy;

/** allow < warn < require_approval < block. */
export type VerdictAction = Action | 'require_approval';
export const VERDICT_ORDER: readonly VerdictAction[] = ['allow', 'warn', 'require_approval', 'block'];

export interface Verdict {
  action: VerdictAction;
  /** One line, shown to the model/user and written to the audit log. */
  reason: string;
  /** Who produced it, e.g. 'spend', 'approval', 'learning', or a plugin id. Becomes the finding's ruleId. */
  ruleId: string;
  /** Default: block→high, require_approval→medium, warn→medium, allow→low. */
  severity?: Severity;
}

/** Text prefix of the isError result the client gets when a call waits for approval. */
export const APPROVAL_MARKER = '[mcp-toolguard] APPROVAL REQUIRED';

/**
 * Rule plugin. The proxy calls check(call, undefined, policy) before forwarding a tools/call and
 * check(call, result, policy) on its result. null = no opinion. Verdicts combine with the policy Decision
 * by VERDICT_ORDER (strongest wins). In monitor mode block/require_approval become warn (wouldBlock true).
 * A plugin that throws is treated as block with reason 'internal error' (fail closed).
 * Plugins must be synchronous, pure apart from their own state, and never write to stdout.
 */
export interface RulePlugin {
  id: string;
  check(call: ToolCall, result: ToolResult | undefined, policy: Policy): Verdict | null;
}

/**
 * Upstream transport. Extends the SDK Transport (which the proxy drives with start/send/close);
 * connect() is an alias for start(). stdio, Streamable HTTP and SSE all implement this.
 */
export interface ToolguardTransport extends Transport {
  readonly name: 'stdio' | 'http' | 'sse' | (string & {});
  connect(): Promise<void>;
}

/** Spend per task. Implemented as a RulePlugin by src/rules/spend.ts. */
export interface SpendTracker {
  track(taskId: string, costUsd: number): void;
  /** block once total(taskId) >= cap, reason includes the running total; else allow. */
  check(taskId: string): Verdict;
  total(taskId: string): number;
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'used';

export interface ApprovalRequest {
  /** Short, typeable id, e.g. 'a7f3c2'. */
  id: string;
  toolCall: { serverId: string; toolName: string; arguments: Record<string, unknown>; /** sha256 of canonical {serverId, toolName, arguments} */ hash: string };
  reason: string;
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
}

/** Persistent approvals (~/.mcp-toolguard/approvals.json). Implemented by src/approval/index.ts. */
export interface ApprovalStore {
  /**
   * For a call matching policy.approval.tools: if an approved, unused request with the same hash exists,
   * mark it used and return null (call proceeds once). Otherwise create (or reuse) a pending request and
   * return a require_approval verdict whose reason contains the id and `mcp-toolguard approve <id>`.
   * Calls not matching policy.approval.tools → null.
   */
  check(call: ToolCall, policy: Policy): Verdict | null;
  approve(id: string): ApprovalRequest;
  deny(id: string): ApprovalRequest;
  list(status?: ApprovalStatus): ApprovalRequest[];
}

export type { Transport };

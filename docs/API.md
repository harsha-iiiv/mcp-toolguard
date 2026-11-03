# mcp-toolguard library API (v1)

`mcp-toolguard` is a CLI first, but everything the CLI does is available as a library, so you can embed the
proxy in your own launcher, test harness or agent host.

```ts
import { startProxy, loadPolicy, createPolicyEngine /* ... */ } from 'mcp-toolguard-cli';
```

ESM only, Node 20+. All types come from the same entry point (`import type { RulePlugin } from 'mcp-toolguard-cli'`).

## Stability promise

The eight names below are **frozen from v1.0**. They will not be renamed or removed, and their existing
parameters and return values will keep their meaning for every 1.x release. Changes are **additive only**:
new optional options fields, new optional interface members, new exports. A test
(`tests/unit/plugins/api.test.ts`) fails CI if any frozen name disappears.

| Frozen export | Purpose |
|---|---|
| `startProxy` | Run the proxy between an MCP client and an upstream server |
| `loadPolicy` | Load and validate `toolguard.yaml` / `.yml` / `.json` (or the built-in default) |
| `createPolicyEngine` | Turn a policy into a `PolicyEngine` that produces decisions |
| `createDetector` | Detection rules (tool poisoning, rug pull, secrets, ...) |
| `createPinStore` | Trust-on-first-use tool definition pins (file-backed or in-memory) |
| `createAuditLogger` | Hash-chained JSONL audit log |
| `verifyAuditLog` | Verify an audit log's hash chain |
| `loadPlugin` | Load one rule plugin (see [PLUGINS.md](PLUGINS.md)) |

Also exported (stable, but not part of the frozen eight): `defaultPolicy`, `validatePolicy`, `builtinRules`,
`hashTool`, `redactSecrets`, `canonicalJson`, `loadPlugins`, `definePlugin`, `PluginError`, `PolicyError`,
`runCli`, `UsageError`, every constant and type in `src/contracts.ts` (`BLOCK_MARKER`, `APPROVAL_MARKER`,
`VERDICT_ORDER`, `RULE_IDS`, `TOOLGUARD_VERSION`, `RulePlugin`, `Verdict`, `ToolCall`, `ToolResult`,
`Policy`, `ToolguardPolicy`, `ProxyOptions`, ...).

## Signatures

Copied from `src/contracts.ts` and the module `index.ts` files.

### startProxy

```ts
function startProxy(opts: ProxyOptions): Promise<ProxyHandle>;

interface ProxyOptions {
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
  /** v0.2 hooks. */
  plugins?: RulePlugin[];
  approvals?: ApprovalStore;
}

interface ProxyHandle {
  /** Resolves with the exit code when either side closes. 0 on clean shutdown. */
  readonly done: Promise<number>;
  close(): Promise<void>;
  /** Tools currently hidden from the client because of block decisions. */
  hiddenTools(): string[];
}
```

With the default transports the proxy speaks MCP on **this process's stdout**. Do not write anything else to
stdout while it runs; log to stderr.

### loadPolicy

```ts
function loadPolicy(file?: string, cwd?: string): { policy: ToolguardPolicy; source: string };
```

Without `file`, looks for `./toolguard.yaml`, `./toolguard.yml`, `./toolguard.json` in `cwd`, then falls back to
`defaultPolicy()`. `source` is the path that was read, or `'builtin'`. Throws `PolicyError` (with `issues`)
on invalid input.

### createPolicyEngine

```ts
function createPolicyEngine(policy: ToolguardPolicy): PolicyEngine;

interface PolicyEngine {
  readonly policy: ToolguardPolicy;
  disabledRules(): string[];
  evaluate(target: InspectionTarget, findings: Finding[], extra?: { knownTool?: boolean }): Decision;
}
```

### createDetector

```ts
function createDetector(opts: DetectorOptions): Detector;

interface DetectorOptions {
  pins: ToolPinStore;
  /** Rule IDs to skip. */
  disabledRules?: readonly string[];
  /** Extra rules appended after the built-ins. */
  extraRules?: readonly DetectionRule[];
}

interface Detector {
  readonly rules: readonly DetectionRule[];
  inspect(target: InspectionTarget, ctx: InspectionContext): Finding[];
}
```

### createPinStore

```ts
function createPinStore(file?: string): ToolPinStore; // undefined → in-memory; '~' expands

interface ToolPinStore {
  get(serverId: string, toolName: string): ToolPin | undefined;
  set(pin: ToolPin): void;
  list(serverId?: string): ToolPin[];
  reset(serverId: string, toolName?: string): number;
}
```

### createAuditLogger

```ts
function createAuditLogger(opts: AuditLoggerOptions): InspectableAuditLogger;

interface AuditLoggerOptions {
  /** File path ('~' expands). If undefined, events are kept in memory only (tests). */
  file?: string;
  redact?: boolean; // default true
  /** Write one-line human summaries of warn/block events to stderr. Default true. */
  stderr?: boolean;
  /** Max serialized length for `data` before truncation. Default 2000. */
  maxDataLength?: number;
}

interface InspectableAuditLogger extends AuditLogger {
  // AuditLogger: log(event: AuditEventInput): AuditEvent; close(): Promise<void>;
  events(): AuditEvent[];
  readonly file: string | undefined;
}
```

### verifyAuditLog

```ts
function verifyAuditLog(file: string): VerifyResult;

interface VerifyResult {
  ok: boolean;
  count: number;
  /** seq of the first broken line, if any. */
  brokenAt?: number;
  error?: string;
}
```

### loadPlugin (and loadPlugins, definePlugin)

```ts
function loadPlugin(fileOrModule: string | object): Promise<RulePlugin>;
function loadPlugins(dir: string, opts?: { cwd?: string }): Promise<RulePlugin[]>;
function definePlugin(p: RulePlugin): RulePlugin;

interface RulePlugin {
  id: string;
  check(call: ToolCall, result: ToolResult | undefined, policy: Policy): Verdict | null;
}
```

`loadPlugin` accepts a file path (default export or named `plugin` export) or an already-imported module /
plugin object. `loadPlugins` loads every `*.js` / `*.mjs` directly inside `dir`, sorted by file name, rejects
duplicate ids, and returns `[]` when `dir` does not exist. Both throw `PluginError`. **Plugins run
in-process with your full user permissions.** Details: [PLUGINS.md](PLUGINS.md).

## Embedding example (stdio)

What `mcp-toolguard run` does, in about 20 lines. Your process's stdin/stdout face the MCP client; the
upstream server is spawned over stdio.

```ts
import { randomUUID } from 'node:crypto';
import {
  startProxy, loadPolicy, createPolicyEngine, createDetector,
  createPinStore, createAuditLogger, verifyAuditLog, loadPlugins,
} from 'mcp-toolguard-cli';

const { policy, source } = loadPolicy();             // ./toolguard.yaml, or built-in defaults
const engine = createPolicyEngine(policy);
const detector = createDetector({ pins: createPinStore(policy.pins.file), disabledRules: engine.disabledRules() });
const audit = createAuditLogger({ file: policy.audit.file, redact: policy.audit.redact });
const plugins = policy.plugins.enabled ? await loadPlugins(policy.plugins.dir) : [];

const proxy = await startProxy({
  serverId: 'server-filesystem',
  sessionId: randomUUID(),
  policy: engine, detector, audit, plugins,
  command: 'npx',
  args: ['-y', '@modelcontextprotocol/server-filesystem', process.cwd()],
});
process.stderr.write(`mcp-toolguard: policy from ${source}\n`); // never stdout
const code = await proxy.done;
await audit.close();
process.exitCode = verifyAuditLog(policy.audit.file).ok ? code : 1;
```

## Embedding example (in-memory, for tests)

Inject both transports to run the proxy entirely in-process, for example around an SDK `McpServer`:

```ts
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { BLOCK_MARKER, createAuditLogger, createDetector, createPinStore, createPolicyEngine,
         defaultPolicy, loadPlugin, startProxy } from 'mcp-toolguard-cli';

const [clientSide, proxyClientSide] = InMemoryTransport.createLinkedPair();
const [proxyServerSide, serverSide] = InMemoryTransport.createLinkedPair();
await myMcpServer.connect(serverSide);                        // an SDK McpServer

const engine = createPolicyEngine(defaultPolicy());
const proxy = await startProxy({
  serverId: 'test', sessionId: 'test-session', policy: engine,
  detector: createDetector({ pins: createPinStore(), disabledRules: engine.disabledRules() }),
  audit: createAuditLogger({ stderr: false }),               // in memory
  plugins: [await loadPlugin('./examples/plugins/block-tool.mjs')],
  transports: { client: proxyClientSide, server: proxyServerSide },
});

const client = new Client({ name: 'test', version: '1.0.0' });
await client.connect(clientSide);
await client.listTools();
const r = await client.callTool({ name: 'delete_production_database', arguments: {} });
// r.isError === true, r.content[0].text starts with BLOCK_MARKER
await proxy.close();
```

The same setup runs in `tests/unit/plugins/example-plugin.test.ts`.

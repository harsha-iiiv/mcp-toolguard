# Rule plugins

A rule plugin is a small JavaScript module that adds your own allow / warn / block / require-approval rules
to `tools/call` traffic, next to the built-in detection rules and the policy file.

> **Security warning.** A plugin is ordinary code that runs **inside the mcp-toolguard process, with your full
> user permissions**: it can read your files and environment variables, spawn processes and open network
> connections. There is no sandbox. Only load plugins you wrote or have reviewed, and keep the plugin
> directory writable only by you. Loading plugins is **off by default**.

## The contract

From `src/contracts.ts` (exported by the package as types):

```ts
interface RulePlugin {
  id: string;
  check(call: ToolCall, result: ToolResult | undefined, policy: Policy): Verdict | null;
}

interface ToolCall {             // extends ToolCallTarget
  kind: 'tool_call';
  requestId: string | number;
  toolName: string;
  arguments: Record<string, unknown>;
  serverId: string;
  /** params._meta.taskId if the client sent a string, else the proxy sessionId. */
  taskId: string;
}

type ToolResult = {              // ToolResultTarget
  kind: 'tool_result';
  requestId: string | number;
  toolName: string;
  /** The JSON-RPC `result` object: content, maybe structuredContent, isError. */
  result: Record<string, unknown>;
};

type Policy = ToolguardPolicy;    // the loaded, validated policy (read-only for plugins)

type VerdictAction = 'allow' | 'warn' | 'require_approval' | 'block';
const VERDICT_ORDER = ['allow', 'warn', 'require_approval', 'block'];

interface Verdict {
  action: VerdictAction;
  /** One line, shown to the model/user and written to the audit log. */
  reason: string;
  /** Who produced it; becomes the finding's ruleId. Use your plugin id. */
  ruleId: string;
  /** Default: block→high, require_approval→medium, warn→medium, allow→low. */
  severity?: 'low' | 'medium' | 'high' | 'critical';
}
```

Rules for plugin code:

- `id` is a non-empty string matching `/^[a-z0-9][a-z0-9._-]*$/` and unique among loaded plugins.
- `check` is **synchronous**. Returning a Promise is an error (and fails closed, see below).
- Return `null` for "no opinion". Keep state only inside your own module.
- **Never write to stdout**: during `mcp-toolguard run`, stdout is the MCP protocol channel. Use stderr.

## When `check` is called

For every `tools/call` the client sends, the proxy:

1. runs the built-in detectors and the policy (allow/deny lists, argument rules, severities);
2. if that did not already block, calls **`check(call, undefined, policy)`** on every plugin, in load order,
   **before forwarding** the call. A blocking verdict means the upstream server never receives the call; the
   client gets an `isError` result whose text starts with `[mcp-toolguard] BLOCKED: <ruleId>: <reason>`;
3. when the server answers, inspects the result the same way and, if not already blocked, calls
   **`check(call, result, policy)`** with the same `call` object. Blocking here replaces the result with the
   same `isError` shape.

Plugins are not called for `tools/list`, notifications or any other message, and are not called for a call
or result that the built-in rules already blocked.

## How verdicts combine

Every non-null verdict becomes a finding (with `ruleId`, `severity` and `reason`) in the audit event. The
effective action is the strongest of the policy decision and all plugin verdicts by `VERDICT_ORDER`
(`allow < warn < require_approval < block`). A plugin cannot weaken a decision: returning `allow` never
overrides another rule's `warn` or `block`.

- `warn`: the message is forwarded unchanged; the audit log and stderr record the reason.
- `block`: see above.
- `require_approval` on a call: the client gets `[mcp-toolguard] APPROVAL REQUIRED: ...`. On a result it is
  treated as `block`.

### Monitor mode

In `mode: monitor` (or `run --monitor`), `block` and `require_approval` verdicts are downgraded to `warn`
and the audit event gets `wouldBlock: true`. Nothing is blocked; you can trial a plugin safely this way.

### Fail closed

If `check` throws, the proxy treats it as `{ action: 'block', reason: '<id>: internal error' }` and reports
the error on stderr. Plugins loaded with `loadPlugin` / `loadPlugins` are additionally wrapped so that a
malformed return value (a Promise, an unknown `action`, a missing `reason`) also throws, and therefore also
blocks. A missing `ruleId` defaults to the plugin id. (In monitor mode the block is downgraded to warn like
any other block.)

## Enabling plugins

Plugins load only when you opt in, from a directory of `*.js` / `*.mjs` files (non-recursive, loaded in
file-name order; hidden files and subdirectories are ignored). A missing directory loads nothing.

Either in `toolguard.yaml`:

```yaml
plugins:
  enabled: true
  dir: ./toolguard-plugins     # relative to the current directory
```

or on the command line (overrides the policy):

```
mcp-toolguard run --plugins ./toolguard-plugins -- npx -y @modelcontextprotocol/server-filesystem .
```

A module exposes its plugin as the **default export** or as a **named export `plugin`**. `.js` files are
ESM only when the nearest `package.json` says `"type": "module"`; use `.mjs` to be safe.

From code (see [API.md](API.md)):

```ts
import { loadPlugin, loadPlugins, definePlugin, startProxy } from 'mcp-toolguard-cli';

const plugins = await loadPlugins('./toolguard-plugins');           // [] if missing
const one = await loadPlugin('./toolguard-plugins/block-tool.mjs');
const inline = definePlugin({ id: 'no-shell', check: (c) =>
  c.toolName === 'run_shell' ? { action: 'block', reason: 'no shell', ruleId: 'no-shell' } : null });
await startProxy({ /* ... */ plugins: [...plugins, inline] });
```

`loadPlugin`, `loadPlugins` and `definePlugin` throw `PluginError` with a message naming the file and the
problem (invalid id, missing `check`, duplicate id, import failure).

## Example: block a tool by name

`examples/plugins/block-tool.mjs`, in full:

```js
// mcp-toolguard example rule plugin: block calls to specific tools by name.
//
// Plain JavaScript, no imports. Enable with `mcp-toolguard run --plugins examples/plugins -- <server>`
// or `plugins: { enabled: true, dir: ./examples/plugins }` in toolguard.yaml.
//
// Configure the blocked tool names with a comma-separated env var (read once, when the plugin loads):
//   MCP_TOOLGUARD_BLOCK_TOOLS="delete_production_database,drop_table"
// Default: delete_production_database
//
// SECURITY: plugins run inside the mcp-toolguard process with your full user permissions. Only load code you trust.
// Plugins must be synchronous and must never write to stdout (stdout is the MCP channel).

const DEFAULT_BLOCKED = ['delete_production_database'];

function parseList(value) {
  if (typeof value !== 'string') return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const fromEnv = parseList(process.env.MCP_TOOLGUARD_BLOCK_TOOLS);
const blocked = new Set(fromEnv.length > 0 ? fromEnv : DEFAULT_BLOCKED);

/** @type {import('mcp-toolguard-cli').RulePlugin} */
export default {
  id: 'block-tool',
  check(call, result /* , policy */) {
    // Decide before the call is forwarded (result is undefined); no opinion on results.
    if (result !== undefined) return null;
    if (!blocked.has(call.toolName)) return null;
    return {
      action: 'block',
      ruleId: 'block-tool',
      severity: 'high',
      reason: `tool '${call.toolName}' is on the block list (MCP_TOOLGUARD_BLOCK_TOOLS)`,
    };
  },
};
```

A client calling `delete_production_database` then receives:

```
[mcp-toolguard] BLOCKED: block-tool: tool 'delete_production_database' is on the block list (MCP_TOOLGUARD_BLOCK_TOOLS)
```

and the server never sees the call. Every other tool passes through.

`examples/plugins/warn-large-result.mjs` is a second example that looks only at results (named `plugin`
export) and warns when a result is longer than `MCP_TOOLGUARD_MAX_RESULT_CHARS` (default 50000).

Both examples are exercised against the real proxy in `tests/unit/plugins/example-plugin.test.ts`.

# Changelog

## 0.2.0

First public release. Install: `npm install -g mcp-toolguard-cli` (command: `mcp-toolguard`).

- Local proxy between an MCP client and an MCP server. Upstream servers can be stdio, Streamable HTTP
  (`--transport http --url …`) or SSE (`--transport sse --url …`), with repeatable `--header`.
- Inspects tool definitions (`tools/list`), tool calls and tool results with 9 detection rules: tool
  poisoning, hidden Unicode, rug pull (trust-on-first-use pins), tool shadowing, secret exfiltration,
  sensitive paths, command injection, result injection and secrets in results.
- YAML/JSON policy (`toolguard.yaml`): tool allow/deny lists, argument rules, per-rule overrides,
  severity actions and a `monitor` mode that warns instead of blocking.
- Human approval for selected tools: `approval.tools`, then `mcp-toolguard approve|deny <id>` and
  `approvals list`.
- Spend cap per task (`spend.maxSpendPerTaskUsd`, per-tool costs), keyed by `_meta.taskId` or the session.
- Hash-chained, redacted JSONL audit log with `mcp-toolguard verify-log`.
- `mcp-toolguard scan` to check a server's tools before trusting it (exit 2 when a tool would be blocked).
- Presets (`examples/presets/`), client configs for Claude Code, Cursor and VS Code (`examples/clients/`).
- Opt-in baseline learning (`run --learning`, warn only, stores value shapes, never raw values).
- Opt-in rule plugins (`run --plugins <dir>`) and a stable library API ([docs/API.md](docs/API.md),
  [docs/PLUGINS.md](docs/PLUGINS.md)).
- Detection benchmark with 50 injection and 50 clean samples; current numbers in
  [evals/README.md](evals/README.md).

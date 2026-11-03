# Client configs

Copy-paste examples that put `mcp-toolguard` in front of an MCP server. In every client the change is
the same: the client launches `mcp-toolguard run` over stdio, and mcp-toolguard launches (or connects to)
the real server.

| File | Client | Where it goes | Top-level key |
|---|---|---|---|
| `claude-code.json` | Claude Code | `.mcp.json` in your project (or `claude mcp add-json`) | `mcpServers` |
| `cursor.json` | Cursor | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project) | `mcpServers` |
| `vscode.json` | VS Code (Copilot agent mode) | `.vscode/mcp.json` in your workspace | `servers`, each with `"type": "stdio"` |

Each file has two entries:

- **`filesystem`, stdio wrap.** Everything after `--` is the original server command:
  `npx -y mcp-toolguard-cli run -- npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir`.
  Replace `/path/to/allowed/dir` with a real directory.
- **`remote-http`, HTTP wrap.** mcp-toolguard connects to a remote Streamable HTTP server and still talks
  stdio to the client: `npx -y mcp-toolguard-cli run --transport http --url https://example.com/mcp`.
  The client entry stays a stdio entry; only mcp-toolguard speaks HTTP.

## Choosing a policy

Add `--policy <file>` right after `run` to use one of the presets in [`../presets`](../presets):

```json
"args": ["-y", "mcp-toolguard-cli", "run", "--policy", "/abs/path/balanced.yaml", "--",
         "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/dir"]
```

| Preset | Effect |
|---|---|
| `strict.yaml` | Write/edit/move/delete/create tools are blocked. |
| `balanced.yaml` | Those tools need one-time human approval: `mcp-toolguard approvals list`, then `mcp-toolguard approve <id>`. |
| `permissive.yaml` | Monitor mode: nothing is blocked, would-be blocks are logged. |

Use absolute paths in client configs: clients do not always start servers in your project directory.
Without `--policy`, mcp-toolguard looks for `./toolguard.yaml` in the server's working directory and
otherwise uses its built-in defaults.

## Notes

- Restart (or reload MCP servers in) the client after editing its config.
- stdout of `mcp-toolguard run` is the MCP channel. Warnings go to stderr, which the client shows in its
  MCP server logs. The full record is the audit log, `~/.mcp-toolguard/audit.jsonl`
  (`mcp-toolguard verify-log ~/.mcp-toolguard/audit.jsonl` checks it has not been tampered with).
- Set `MCP_TOOLGUARD_HOME` in the entry's `env` to keep pins, approvals and the audit log somewhere else.

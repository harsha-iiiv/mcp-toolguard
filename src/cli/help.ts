import { TOOLGUARD_VERSION } from '../contracts.js';

export const USAGE = `mcp-toolguard ${TOOLGUARD_VERSION}: local security proxy for MCP servers (stdio)

Usage:
  mcp-toolguard run [--policy <file>] [--audit <file>] [--pins <file>] [--server-id <id>] [--monitor] [--learning] [--plugins <dir>] [--transport stdio|http|sse] [--url <url>] [--header "Name: value"]... [-- <command> [args...]]
  mcp-toolguard scan [--policy <file>] [--pins <file>] [--server-id <id>] [--json] -- <command> [args...]
  mcp-toolguard init [--force]
  mcp-toolguard check-policy <file>
  mcp-toolguard verify-log <file>
  mcp-toolguard pins list|reset [--pins <file>] [--server-id <id>] [--tool <name>] [--json]
  mcp-toolguard approve <id> [--policy <file>]
  mcp-toolguard deny <id> [--policy <file>]
  mcp-toolguard approvals list [--policy <file>] [--status pending|approved|denied|used|expired] [--json]
  mcp-toolguard --version | --help

Commands:
  run           Start the server command behind the toolguard proxy. Use this as the "command"
                in your MCP client config. stdout carries the MCP protocol; messages go to stderr.
  scan          Connect to a server once, list its tools and report what would be warned or blocked.
                Exit 0 = clean, 2 = at least one tool would be blocked, 1 = error.
  init          Write ./toolguard.yaml, a commented policy with every default (--force overwrites).
  check-policy  Validate a policy file. Exit 0 = valid, 1 = invalid.
  verify-log    Verify the hash chain of an audit log. Exit 0 = intact, 1 = broken.
  pins          List or reset pinned tool fingerprints (re-approve a tool after a legitimate change).
  approve       Approve a pending call to a tool listed in approval.tools. The identical call
                (same server, tool and arguments) may then run exactly once.
  deny          Deny a pending approval request.
  approvals     List approval requests (pending requests expire after 24h).

Options:
  --policy <file>     Policy file (default: ./toolguard.yaml|.yml|.json, else built-in defaults)
  --audit <file>      Audit log path (overrides audit.file)
  --pins <file>       Pin store path (overrides pins.file). scan without --pins uses a throwaway store.
  --server-id <id>    Stable id for the upstream server (default: derived from the package/script, e.g. server-filesystem). Pins are per id.
  --monitor           Never block; log and warn on what would have been blocked.
  --status <s>        Filter approvals list: pending, approved, denied, used or expired.
  --json              Machine-readable output (scan, pins list, approvals list).
  -h, --help          Show this help.
  -v, --version       Print the version.

Environment:
  MCP_TOOLGUARD_HOME   State directory for default pins, approvals and audit files (default ~/.mcp-toolguard).
`;

export const COMMAND_USAGE: Record<string, string> = {
  run: 'mcp-toolguard run [--policy <file>] [--audit <file>] [--pins <file>] [--server-id <id>] [--monitor] [--learning] [--plugins <dir>] [--transport stdio|http|sse] [--url <url>] [--header "Name: value"]... [-- <command> [args...]]',
  scan: 'mcp-toolguard scan [--policy <file>] [--pins <file>] [--server-id <id>] [--json] -- <command> [args...]',
  init: 'mcp-toolguard init [--force]',
  'check-policy': 'mcp-toolguard check-policy <file>',
  'verify-log': 'mcp-toolguard verify-log <file>',
  pins: 'mcp-toolguard pins list|reset [--pins <file>] [--server-id <id>] [--tool <name>] [--json]',
  approve: 'mcp-toolguard approve <id> [--policy <file>]',
  deny: 'mcp-toolguard deny <id> [--policy <file>]',
  approvals: 'mcp-toolguard approvals list [--policy <file>] [--status pending|approved|denied|used|expired] [--json]',
};

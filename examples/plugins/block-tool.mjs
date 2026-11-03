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

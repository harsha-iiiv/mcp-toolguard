// mcp-toolguard example rule plugin: warn when a tool result is larger than N characters.
//
// Configure with MCP_TOOLGUARD_MAX_RESULT_CHARS (default 50000). A warn verdict forwards the result unchanged
// but writes an audit event and a stderr warning. Plain JavaScript, no imports.
//
// SECURITY: plugins run inside the mcp-toolguard process with your full user permissions. Only load code you trust.

const parsed = Number.parseInt(process.env.MCP_TOOLGUARD_MAX_RESULT_CHARS ?? '', 10);
const maxChars = Number.isFinite(parsed) && parsed > 0 ? parsed : 50000;

function resultLength(result) {
  const content = Array.isArray(result.content) ? result.content : [];
  let n = 0;
  for (const part of content) {
    if (part && typeof part.text === 'string') n += part.text.length;
  }
  if (result.structuredContent !== undefined) n += JSON.stringify(result.structuredContent).length;
  return n;
}

/** @type {import('mcp-toolguard-cli').RulePlugin} */
export const plugin = {
  id: 'warn-large-result',
  check(call, result) {
    if (result === undefined) return null; // only look at results
    const n = resultLength(result.result);
    if (n <= maxChars) return null;
    return {
      action: 'warn',
      ruleId: 'warn-large-result',
      reason: `result of '${call.toolName}' is ${n} chars (limit ${maxChars})`,
    };
  },
};

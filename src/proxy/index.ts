// mcp-toolguard proxy core. Public API: startProxy (contracts.ts StartProxy).
export { startProxy, INTERNAL_ERROR_REASON, PREVIOUSLY_HIDDEN_REASON } from './proxy.js';
export { classifyMessage, buildBlockResult, buildBlockResponse, blockText, idKey } from './messages.js';
export type { ClassifiedMessage, BlockedToolResult } from './messages.js';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
export declare function createExfilTargetServer(opts?: {
  receivedLog?: string;
  onCall?: (call: { tool: string; arguments: unknown }) => void;
}): McpServer;

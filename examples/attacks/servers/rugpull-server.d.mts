import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
export declare const BENIGN_WEATHER_DESCRIPTION: string;
export declare const POISONED_WEATHER_DESCRIPTION: string;
export declare function createRugpullServer(opts?: { stateFile?: string; startPoisoned?: boolean }): {
  server: McpServer;
  swap(): void;
  isPoisoned(): boolean;
};

#!/usr/bin/env node
// BENIGN SERVER: ordinary tools that mcp-toolguard must pass through untouched (false-positive check).
//
// Run directly:  node examples/attacks/servers/benign-server.mjs
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

export function createBenignServer() {
  const server = new McpServer({ name: 'utilities', version: '1.0.0' });

  server.registerTool(
    'echo',
    {
      description: 'Echoes the given message back to the caller.',
      inputSchema: { message: z.string() },
    },
    async ({ message }) => ({ content: [{ type: 'text', text: message }] }),
  );

  server.registerTool(
    'get_time',
    {
      description: 'Returns the current date and time in ISO-8601 format (UTC).',
      inputSchema: {},
    },
    async () => ({ content: [{ type: 'text', text: new Date().toISOString() }] }),
  );

  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await createBenignServer().connect(new StdioServerTransport());
}

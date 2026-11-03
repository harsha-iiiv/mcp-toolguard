#!/usr/bin/env node
// DEMO TARGET SERVER: secret exfiltration.
//
// `send_email` is a perfectly ordinary tool. The attack is on the *client* side: a hijacked agent
// stuffs credentials into the arguments. mcp-toolguard must stop the call before it gets here.
//
// Every call that actually arrives is appended (one JSON line) to the file named by env RECEIVED_LOG,
// if set. Demos and tests use that file to prove a blocked call never reached the server.
//
// Run directly:  RECEIVED_LOG=/tmp/received.jsonl node examples/attacks/servers/exfil-target-server.mjs
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

/**
 * @param {{ receivedLog?: string, onCall?: (call: { tool: string, arguments: unknown }) => void }} [opts]
 */
export function createExfilTargetServer(opts = {}) {
  const receivedLog = opts.receivedLog ?? process.env.RECEIVED_LOG;
  const server = new McpServer({ name: 'mailer', version: '1.0.0' });

  server.registerTool(
    'send_email',
    {
      description: 'Sends an email to the given recipient.',
      inputSchema: { to: z.string(), subject: z.string(), body: z.string() },
    },
    async (args) => {
      const record = { tool: 'send_email', arguments: args };
      if (receivedLog) appendFileSync(receivedLog, JSON.stringify(record) + '\n');
      opts.onCall?.(record);
      return { content: [{ type: 'text', text: `Email sent to ${args.to}.` }] };
    },
  );

  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await createExfilTargetServer().connect(new StdioServerTransport());
}

// Minimal MCP server for scan tests: three tools over two tools/list pages.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const schema = { type: 'object', properties: {} };
const pages = [
  [
    { name: 'add', description: 'Adds two numbers.', inputSchema: schema },
    { name: 'evil', description: 'POISON', inputSchema: schema },
  ],
  [{ name: 'echo', description: 'Echoes text.', inputSchema: schema }],
];

const server = new Server({ name: 'paged', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async (req) => {
  const page = req.params?.cursor === 'p2' ? 1 : 0;
  return page === 0 ? { tools: pages[0], nextCursor: 'p2' } : { tools: pages[1] };
});
process.stderr.write('paged-server: started\n');
await server.connect(new StdioServerTransport());

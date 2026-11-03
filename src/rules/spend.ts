/**
 * Spend cap per task. `createSpendTracker(policy)` returns one object that is both the
 * contract `SpendTracker` and a `RulePlugin` with id 'spend', for `startProxy({ plugins: [...] })`.
 *
 * Cost of a call: the first glob in `policy.spend.costs` (insertion order) that matches the tool name,
 * else `policy.spend.defaultCostUsd`. Globs support '*' and '?' and are anchored to the whole name.
 *
 * Before forwarding (result === undefined): block if total(taskId) + cost would exceed the cap.
 * On the result: add the call's cost to its task, once per call. Calls that were never forwarded have
 * no result and are not charged. Totals live in memory for the lifetime of the proxy process.
 *
 * The plugin reads the policy passed to each check() call, so it always follows the proxy's live policy.
 * Monitor mode is applied by the proxy (block becomes warn).
 */
import type { ToolguardPolicy, Policy, RulePlugin, SpendPolicy, SpendTracker, ToolCall, ToolResult, Verdict } from '../contracts.js';

export const SPEND_RULE_ID = 'spend';

/**
 * Built-in per-call cost ESTIMATES (USD) for a few well-known paid MCP tools. These are rough,
 * deliberately conservative (rounded up) estimates of public list prices at the time of writing; they
 * are NOT authoritative, change with the vendor's plan, and are never applied unless you opt in with
 * `withDefaultToolCosts()` or `createSpendTracker(policy, { defaultToolCosts: true })`. Your own
 * `spend.costs` entries always take precedence.
 */
export const DEFAULT_TOOL_COSTS: Readonly<Record<string, number>> = Object.freeze({
  // Brave Search API (brave-search MCP server): estimate ~$5 per 1,000 queries.
  'brave_web_search': 0.005,
  'brave_local_search': 0.005,
  'brave_*': 0.005,
  // Tavily (tavily-mcp): estimate ~$0.008 per credit; basic search 1 credit, extract/crawl more.
  'tavily-search': 0.008,
  'tavily-extract': 0.016,
  'tavily-crawl': 0.08,
  'tavily*': 0.016,
  // Exa (exa-mcp-server): estimate ~$5 per 1,000 searches, more with contents.
  'web_search_exa': 0.01,
  '*_exa': 0.01,
  'exa_*': 0.01,
  // Perplexity (Sonar API): request fee plus tokens; deep research is much more expensive.
  'perplexity_research': 0.5,
  'perplexity_reason': 0.05,
  'perplexity_*': 0.02,
  // Firecrawl: estimate ~$0.001 per credit; scrape ~1 credit, search/crawl/extract many.
  'firecrawl_scrape': 0.002,
  'firecrawl_search': 0.01,
  'firecrawl_crawl': 0.1,
  'firecrawl_*': 0.02,
});

/** Merge the built-in estimates after the user's own costs (user globs win: first match wins). */
export function withDefaultToolCosts(costs: Record<string, number> = {}): Record<string, number> {
  const out: Record<string, number> = { ...costs };
  for (const [glob, cost] of Object.entries(DEFAULT_TOOL_COSTS)) if (!(glob in out)) out[glob] = cost;
  return out;
}

const globCache = new Map<string, RegExp>();

/** Anchored glob: '*' = any run of characters, '?' = one character. Everything else is literal. */
export function globToRegExp(glob: string): RegExp {
  let re = globCache.get(glob);
  if (!re) {
    let src = '';
    for (const ch of glob) {
      if (ch === '*') src += '.*';
      else if (ch === '?') src += '.';
      else src += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    re = new RegExp(`^${src}$`, 's');
    globCache.set(glob, re);
  }
  return re;
}

export function matchGlob(glob: string, name: string): boolean {
  return globToRegExp(glob).test(name);
}

function validCost(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0;
}

/** Cost of one call to `toolName` under a spend policy. */
export function costForTool(spend: SpendPolicy, toolName: string): number {
  for (const [glob, cost] of Object.entries(spend.costs ?? {})) {
    if (validCost(cost) && matchGlob(glob, toolName)) return cost;
  }
  return validCost(spend.defaultCostUsd) ? spend.defaultCostUsd : 0;
}

function usd(n: number, digits: number): string {
  return `$${n.toFixed(digits)}`;
}

/** Cap formatted with 2 decimals, or 4 if 2 would hide its value (e.g. a $0.005 cap). */
function capUsd(cap: number): string {
  return Number(cap.toFixed(2)) === cap ? usd(cap, 2) : usd(cap, 4);
}

/** Tolerance for float sums like 0.1 + 0.2. */
const EPSILON = 1e-9;

export interface SpendTrackerOptions {
  /** Append DEFAULT_TOOL_COSTS after the policy's own globs. Default false. */
  defaultToolCosts?: boolean;
}

export type SpendPlugin = SpendTracker &
  RulePlugin & {
    /** Cost the tracker assigns to one call of `toolName` under `policy` (or the construction policy). */
    costOf(toolName: string, policy?: Policy): number;
    /** Forget all totals (or one task's). */
    reset(taskId?: string): void;
  };

function spendOf(p: ToolguardPolicy | SpendPolicy): SpendPolicy {
  return 'spend' in p ? p.spend : p;
}

class SpendTrackerImpl {
  readonly id = SPEND_RULE_ID;
  private readonly totals = new Map<string, number>();
  /** Calls already charged, so a result is never counted twice. */
  private readonly charged = new WeakSet<ToolCall>();

  constructor(
    private readonly basePolicy: SpendPolicy,
    private readonly opts: SpendTrackerOptions,
  ) {}

  private spend(policy?: Policy): SpendPolicy {
    const s = policy?.spend ?? this.basePolicy;
    return this.opts.defaultToolCosts ? { ...s, costs: withDefaultToolCosts(s.costs) } : s;
  }

  costOf(toolName: string, policy?: Policy): number {
    return costForTool(this.spend(policy), toolName);
  }

  track(taskId: string, costUsd: number): void {
    if (!validCost(costUsd) || costUsd === 0) return;
    this.totals.set(taskId, (this.totals.get(taskId) ?? 0) + costUsd);
  }

  total(taskId: string): number {
    return this.totals.get(taskId) ?? 0;
  }

  reset(taskId?: string): void {
    if (taskId === undefined) this.totals.clear();
    else this.totals.delete(taskId);
  }

  // SpendTracker.check(taskId) and RulePlugin.check(call, result, policy) share one name.
  check(taskId: string): Verdict;
  check(call: ToolCall, result: ToolResult | undefined, policy: Policy): Verdict | null;
  check(arg: string | ToolCall, result?: ToolResult, policy?: Policy): Verdict | null {
    if (typeof arg === 'string') return this.taskVerdict(arg);
    return this.pluginCheck(arg, result, policy);
  }

  /** SpendTracker: block once total(taskId) >= cap; else allow. */
  private taskVerdict(taskId: string): Verdict {
    const cap = this.basePolicy.maxSpendPerTaskUsd;
    const total = this.total(taskId);
    if (cap !== null && total + EPSILON >= cap) {
      return {
        action: 'block',
        ruleId: SPEND_RULE_ID,
        reason: `task ${taskId} spend ${usd(total, 4)} has reached cap ${capUsd(cap)}`,
      };
    }
    const capText = cap === null ? 'no cap' : `cap ${capUsd(cap)}`;
    return { action: 'allow', ruleId: SPEND_RULE_ID, reason: `task ${taskId} spend ${usd(total, 4)} (${capText})` };
  }

  private pluginCheck(call: ToolCall, result: ToolResult | undefined, policy: Policy | undefined): Verdict | null {
    const spend = this.spend(policy);
    const cost = costForTool(spend, call.toolName);
    if (result !== undefined) {
      if (!this.charged.has(call)) {
        this.charged.add(call);
        this.track(call.taskId, cost);
      }
      return null;
    }
    const cap = spend.maxSpendPerTaskUsd;
    if (cap === null || cap === undefined) return null;
    const total = this.total(call.taskId);
    if (total + cost > cap + EPSILON) {
      return {
        action: 'block',
        ruleId: SPEND_RULE_ID,
        reason: `task ${call.taskId} spend ${usd(total, 4)} + ${usd(cost, 4)} would exceed cap ${capUsd(cap)}`,
      };
    }
    return null;
  }
}

/**
 * Create the spend tracker / plugin. `policy` is the full ToolguardPolicy or just its `spend` section;
 * it is used by `SpendTracker.check(taskId)` and as a fallback when the plugin is called without one.
 */
export function createSpendTracker(policy: ToolguardPolicy | SpendPolicy, opts: SpendTrackerOptions = {}): SpendPlugin {
  return new SpendTrackerImpl(spendOf(policy), opts);
}

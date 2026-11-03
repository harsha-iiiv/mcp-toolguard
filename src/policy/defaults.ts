import type { ToolguardPolicy } from '../contracts.js';
import { joinHome } from './paths.js';

/** Built-in policy. Paths are NOT '~'-expanded here; validatePolicy() expands them. Fresh object each call. */
export function defaultPolicy(): ToolguardPolicy {
  return {
    version: 1,
    mode: 'enforce',
    tools: { allow: [], deny: [], unlisted: 'block', unknown: 'warn' },
    severityActions: { low: 'allow', medium: 'warn', high: 'block', critical: 'block' },
    rules: {},
    arguments: [],
    pins: { file: joinHome('pins.json') },
    spend: { maxSpendPerTaskUsd: null, costs: {}, defaultCostUsd: 0 },
    approval: { tools: [], file: joinHome('approvals.json') },
    learning: { enabled: false, file: joinHome('baseline.json'), minSamples: 50 },
    plugins: { enabled: false, dir: './toolguard-plugins' },
    audit: { file: joinHome('audit.jsonl'), redact: true, logAllowed: true },
  };
}

/**
 * rug-pull — a tool's definition changed after it was first trusted.
 *
 * Trust-on-first-use, exactly per contracts.ts "Rug-pull semantics":
 *   first sight → pin, no finding; same hash → no finding;
 *   different hash → critical finding, pin NOT updated (user re-approves via `pins reset`).
 *
 * The pin keeps the original description but only a hash of the schema, so we can tell which
 * part changed by re-hashing {name, pinned description, current schema}: if that matches the
 * pinned hash, only the description changed.
 */
import { RULE_IDS, type DetectionRule, type ToolDescriptor } from '../../contracts.js';
import { hashTool } from '../pins.js';
import { clamp, oneLine } from '../helpers/text.js';

/** "…common prefix «old» → «new» common suffix…" style hint, bounded to 200 chars. */
export function diffHint(before: string, after: string): string {
  const a = oneLine(before);
  const b = oneLine(after);
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const removed = a.slice(pre, a.length - suf);
  const added = b.slice(pre, b.length - suf);
  const ctx = a.slice(Math.max(0, pre - 20), pre);
  const budget = 70;
  const cut = (s: string) => (s.length > budget ? `${s.slice(0, budget - 1)}…` : s);
  return clamp(`description: …${ctx}[-${cut(removed)}-]{+${cut(added)}+}`);
}

export const rugPullRule: DetectionRule = {
  id: RULE_IDS.RUG_PULL,
  description: "A tool's description or input schema changed since it was first seen (trust-on-first-use pin).",
  defaultSeverity: 'critical',
  appliesTo: ['tool_definition'],
  detect(target, ctx) {
    if (target.kind !== 'tool_definition') return [];
    const tool: ToolDescriptor = target.tool;
    const hash = hashTool(tool);
    const pin = ctx.pins.get(ctx.serverId, tool.name);
    if (!pin) {
      ctx.pins.set({
        serverId: ctx.serverId,
        toolName: tool.name,
        hash,
        description: tool.description ?? '',
        firstSeen: new Date().toISOString(),
      });
      return [];
    }
    if (pin.hash === hash) return [];

    const description = tool.description ?? '';
    const descChanged = pin.description !== description;
    const schemaUnchangedIfDescReverted =
      hashTool({ name: tool.name, description: pin.description, inputSchema: tool.inputSchema }) === pin.hash;
    const schemaChanged = !descChanged || !schemaUnchangedIfDescReverted;
    const changed = [descChanged ? 'description' : '', schemaChanged ? 'inputSchema' : ''].filter(Boolean);

    const hints: string[] = [];
    if (descChanged) hints.push(diffHint(pin.description, description));
    if (schemaChanged) hints.push(`inputSchema: sha256 ${pin.hash.slice(0, 8)}… → ${hash.slice(0, 8)}…`);

    return [
      {
        ruleId: RULE_IDS.RUG_PULL,
        severity: 'critical',
        message: `Tool definition changed since first pinned on ${pin.firstSeen}: ${changed.join(' and ')} modified. Run \`mcp-toolguard pins reset\` to re-approve.`,
        evidence: clamp(hints.join(' | ')),
        location: changed[0],
      },
    ];
  },
};

/**
 * tool-poisoning — hidden or manipulative instructions inside a tool definition.
 *
 * The model reads the full description and every string in inputSchema; the user usually sees a
 * one-line summary. Attackers use that gap (Invariant Labs, "MCP Security Notification: Tool
 * Poisoning Attacks", 2025). We score signal categories across all text of the tool:
 *
 *   marker / secrecy / side-channel  → high
 *   …plus any sensitive target       → critical
 *   coercion + file target           → critical
 *   coercion alone                   → medium (legitimate servers do say "always call X first")
 *   sensitive target alone           → no finding ("reads credentials from ~/.aws" is documentation)
 */
import { withHiddenText } from '../helpers/unicode.js';
import { RULE_IDS, type DetectionRule, type Finding, type Severity } from '../../contracts.js';
import {
  COERCION_PATTERNS,
  EXFIL_TARGET_PATTERNS,
  MARKER_PATTERNS,
  SECRECY_PATTERNS,
  SIDE_CHANNEL_PATTERNS,
  WEAK_TARGET_PATTERNS,
} from '../helpers/instructions.js';
import { clamp, matchAll, oneLine, toolDefinitionStrings, type LabelledMatch, type LabelledPattern } from '../helpers/text.js';

interface Located extends LabelledMatch {
  path: string;
}

function collect(hits: { path: string; value: string }[], patterns: readonly LabelledPattern[]): Located[] {
  const out: Located[] = [];
  for (const h of hits) for (const m of matchAll(h.value, patterns)) out.push({ ...m, path: h.path });
  return out;
}

export const toolPoisoningRule: DetectionRule = {
  id: RULE_IDS.TOOL_POISONING,
  description: 'Hidden or manipulative instructions (markers, secrecy, coercion, side-channel parameters) in a tool description or schema.',
  defaultSeverity: 'high',
  appliesTo: ['tool_definition'],
  detect(target) {
    if (target.kind !== 'tool_definition') return [];
    const hits = withHiddenText(toolDefinitionStrings(target.tool));
    if (hits.length === 0) return [];

    const marker = collect(hits, MARKER_PATTERNS);
    const secrecy = collect(hits, SECRECY_PATTERNS);
    const side = collect(hits, SIDE_CHANNEL_PATTERNS);
    const coercion = collect(hits, COERCION_PATTERNS);
    const strongTargets = collect(hits, EXFIL_TARGET_PATTERNS);
    const weakTargets = collect(hits, WEAK_TARGET_PATTERNS);

    const strongInstruction = marker.length + secrecy.length + side.length > 0;
    const anyTarget = strongTargets.length + weakTargets.length > 0;
    let severity: Severity | undefined;
    if ((strongInstruction && anyTarget) || (coercion.length > 0 && strongTargets.length > 0)) severity = 'critical';
    else if (strongInstruction) severity = 'high';
    else if (coercion.length > 0) severity = 'medium';
    if (!severity) return [];

    const instructions = [...marker, ...secrecy, ...side, ...coercion];
    const targets = severity === 'critical' ? [...strongTargets, ...weakTargets] : [];
    const kinds = [
      marker.length ? 'hidden-instruction marker' : '',
      secrecy.length ? 'secrecy toward the user' : '',
      side.length ? 'side-channel parameter' : '',
      coercion.length ? 'coercive workflow' : '',
    ].filter(Boolean);
    const targetLabels = [...new Set(targets.map((t) => t.label))];
    const message =
      `Tool description contains ${kinds.join(', ')}` +
      (targetLabels.length ? ` referencing sensitive data (${targetLabels.join(', ')})` : '');

    const evidence = clamp(
      [...instructions, ...targets]
        .map((m) => `"${oneLine(m.match)}"`)
        .filter((v, i, a) => a.indexOf(v) === i)
        .join(' · '),
    );
    const finding: Finding = {
      ruleId: RULE_IDS.TOOL_POISONING,
      severity,
      message,
      evidence,
      location: instructions[0]!.path,
    };
    return [finding];
  },
};

/**
 * hidden-unicode — invisible, bidi-override and Unicode tag characters.
 *
 * Applies to every target kind: tool names, descriptions and schemas (including property names),
 * tool-call arguments (keys and values) and tool results. Tag characters (U+E0000–U+E007F) are
 * decoded back to ASCII in the evidence so "ASCII smuggled" instructions become readable.
 */
import { RULE_IDS, type DetectionRule, type Finding, type InspectionTarget } from '../../contracts.js';
import { revealHidden, scanHidden } from '../helpers/unicode.js';
import { clamp, oneLine, toolDefinitionStrings, toolResultStrings, walkStrings, type StringHit } from '../helpers/text.js';

function stringsOf(target: InspectionTarget): StringHit[] {
  switch (target.kind) {
    case 'tool_definition':
      return [{ path: 'name', value: target.tool.name }, ...toolDefinitionStrings(target.tool, { includeKeys: true })];
    case 'tool_call':
      return [{ path: 'name', value: target.toolName }, ...walkStrings(target.arguments, 'arguments', { includeKeys: true })];
    case 'tool_result':
      return toolResultStrings(target.result);
  }
}

const MAX_FINDINGS = 20;

export const hiddenUnicodeRule: DetectionRule = {
  id: RULE_IDS.HIDDEN_UNICODE,
  description: 'Zero-width, bidirectional-override or Unicode tag characters that hide text from humans but not from the model.',
  defaultSeverity: 'high',
  appliesTo: ['tool_definition', 'tool_call', 'tool_result'],
  detect(target) {
    const findings: Finding[] = [];
    for (const hit of stringsOf(target)) {
      const scan = scanHidden(hit.value);
      if (!scan) continue;
      const parts: string[] = [];
      if (scan.counts.tag) parts.push(`${scan.counts.tag} Unicode tag char(s)`);
      if (scan.counts['zero-width']) parts.push(`${scan.counts['zero-width']} zero-width char(s)`);
      if (scan.counts.bidi) parts.push(`${scan.counts.bidi} bidi control char(s)`);
      const where = hit.isKey ? `property name ${hit.path}` : hit.path;

      let evidence: string;
      if (scan.decodedTags) {
        evidence = `hidden text: "${oneLine(scan.decodedTags)}"`;
      } else {
        const start = Math.max(0, scan.firstIndex - 30);
        const shown = revealHidden(hit.value.slice(start, scan.firstIndex + 90));
        evidence = `${scan.codepoints.join(' ')} in "${start > 0 ? '…' : ''}${oneLine(shown)}"`;
      }
      findings.push({
        ruleId: RULE_IDS.HIDDEN_UNICODE,
        severity: 'high',
        message: `Invisible characters in ${where}: ${parts.join(', ')}${scan.decodedTags ? ' (decoded below)' : ''}`,
        evidence: clamp(evidence),
        location: hit.path,
      });
      if (findings.length >= MAX_FINDINGS) break;
    }
    return findings;
  },
};

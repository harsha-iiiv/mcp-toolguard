/**
 * tool-shadowing — a tool description that tries to change how OTHER tools behave
 * (Invariant Labs "shadowing" / WhatsApp MCP exfiltration). The malicious tool never needs to be
 * called: its description alone rewires calls to a trusted tool from another server.
 *
 * Patterns are anchored on references to another tool or on redirection of recipients, so
 * everyday words like "override" or "instead of" in normal documentation do not fire. References
 * to the tool's own name are ignored.
 */
import { withHiddenText } from '../helpers/unicode.js';
import { RULE_IDS, type DetectionRule, type Finding } from '../../contracts.js';
import { clamp, snippet, toolDefinitionStrings } from '../helpers/text.js';

interface ShadowPattern {
  label: string;
  re: RegExp;
  /** Capture group holding the referenced tool name, if any. */
  toolGroup?: number;
}

const NOT_A_TOOL_NAME = /^(?:this|that|the|a|an|any|each|every|same|current)$/i;

const PATTERNS: readonly ShadowPattern[] = [
  {
    label: 'conditions on another tool',
    re: /\bwhen(?:ever)?\s+(?:you\s+)?(?:use|using|call|calling|invoke|invoking|run|running)\s+(?:the\s+)?[`'"]?([\w.:/-]+)[`'"]?\s+(?:tool|function)\b/i,
    toolGroup: 1,
  },
  {
    label: 'conditions on another tool',
    re: /\bwhen(?:ever)?\s+(?:the\s+)?(?:\([\w.-]+\)\s*)?[`'"]?([\w.:/-]+)[`'"]?\s+(?:tool\s+|function\s+)?is\s+(?:invoked|called|used|run|executed)\b/i,
    toolGroup: 1,
  },
  {
    label: 'replaces another tool',
    re: /\binstead\s+of\s+(?:using|calling|invoking)\s+(?:the\s+)?[`'"]?([\w.:/-]+)[`'"]?/i,
    toolGroup: 1,
  },
  {
    label: 'replaces another tool',
    re: /\binstead\s+of\s+(?:the\s+)?[`'"]?([\w.:/-]+)[`'"]?\s+(?:tool|function)\b/i,
    toolGroup: 1,
  },
  {
    label: 'redirects messages',
    re: /\ball\s+(?:e-?mails?|messages?|requests?|payments?|transfers?|transactions?)\s+(?:must|should|shall|are\s+to|need\s+to)\s+(?:also\s+)?(?:be\s+)?(?:sent|forwarded|redirected|routed|copied|cc['’]?d|bcc['’]?d)\s+to\b/i,
  },
  {
    label: 'redirects messages',
    re: /\b(?:change|set|replace|switch|update)\s+the\s+(?:recipient|receiver|destination|to[\s-]address|email\s+address|phone\s+number|account\s+number|iban|wallet\s+address)\s+(?:to|with)\b/i,
  },
  {
    label: 'overrides other tools',
    re: /\b(?:override|overrides|overriding|supersede|supersedes|takes?\s+precedence\s+over)\s+(?:the\s+)?(?:behaviou?r\s+of\s+|instructions?\s+(?:of|for)\s+|rules\s+(?:of|for)\s+)?(?:(?:all|any)\s+)?(?:other|previous|existing)\s+(?:tools?|instructions?|servers?)\b/i,
  },
  {
    label: 'overrides other tools',
    re: /\b(?:override|overrides|overriding)\s+(?:the\s+)?(?:behaviou?r\s+of\s+)?(?:the\s+)?[`'"]?([\w.:/-]+)[`'"]?\s+tool\b/i,
    toolGroup: 1,
  },
  {
    label: 'side effect on another tool',
    re: /\bside[\s-]effects?\s+on\s+(?:the\s+)?(?:also\s+(?:present|available)\s+)?[`'"]?([\w.:/-]+)[`'"]?\s+tool\b/i,
    toolGroup: 1,
  },
];

export const toolShadowingRule: DetectionRule = {
  id: RULE_IDS.TOOL_SHADOWING,
  description: 'A tool description that tries to change how other tools are used (redirecting recipients, overriding behaviour).',
  defaultSeverity: 'medium',
  appliesTo: ['tool_definition'],
  detect(target) {
    if (target.kind !== 'tool_definition') return [];
    const own = target.tool.name.toLowerCase();
    const matches: { label: string; path: string; ev: string; ref?: string }[] = [];
    for (const hit of withHiddenText(toolDefinitionStrings(target.tool))) {
      for (const p of PATTERNS) {
        const m = p.re.exec(hit.value);
        if (!m) continue;
        const ref = p.toolGroup ? m[p.toolGroup] : undefined;
        if (ref !== undefined) {
          const bare = ref.replace(/^.*[.:/]/, '').toLowerCase();
          if (NOT_A_TOOL_NAME.test(ref) || bare === own || ref.toLowerCase() === own) continue;
        }
        matches.push({ label: p.label, path: hit.path, ev: snippet(hit.value, m.index, m[0].length, 25), ref });
      }
    }
    if (matches.length === 0) return [];
    const labels = [...new Set(matches.map((m) => m.label))];
    const refs = [...new Set(matches.map((m) => m.ref).filter((r): r is string => !!r))];
    const finding: Finding = {
      ruleId: RULE_IDS.TOOL_SHADOWING,
      severity: 'medium',
      message: `Tool description tries to alter other tools' behaviour (${labels.join(', ')})${refs.length ? `; references: ${refs.join(', ')}` : ''}`,
      evidence: clamp(matches.map((m) => m.ev).join(' · ')),
      location: matches[0]!.path,
    };
    return [finding];
  },
};

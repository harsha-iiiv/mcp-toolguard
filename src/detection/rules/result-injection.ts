/**
 * result-injection — prompt-injection phrasing in a tool result (indirect prompt injection).
 *
 * Tool results often carry attacker-controlled text (web pages, issues, emails). We look for text
 * that addresses the model rather than informing it: instruction markers, "ignore previous
 * instructions", persona switches, secrecy, and directives to call tools or ship data to a URL.
 * Phrases are contextual: "you are now logged in" or an article that discusses "system prompts"
 * does not fire.
 */
import { normalizeForMatching, scanHidden } from '../helpers/unicode.js';
import { RULE_IDS, type DetectionRule, type Finding, type Severity } from '../../contracts.js';
import { MARKER_PATTERNS, SECRECY_PATTERNS } from '../helpers/instructions.js';
import { matchAll, snippet, toolResultStrings, type LabelledPattern } from '../helpers/text.js';

const RESULT_PATTERNS: readonly LabelledPattern[] = [
  ...MARKER_PATTERNS,
  ...SECRECY_PATTERNS.filter((p) => p.label !== 'keep secret'),
  {
    label: 'persona switch',
    re: /\byou\s+are\s+now\s+(?:(?:a|an|the|my)\s+(?:[\w-]+\s+){0,3}?(?:assistant|ai|agent|model|bot|hacker|admin(?:istrator)?|root|jailbroken|unrestricted|dan)\b|in\s+(?:developer|god|jailbreak|jailbroken|unrestricted|admin|debug|maintenance)\s+mode\b|dan\b)/i,
  },
  { label: 'new instructions', re: /\b(?:new|updated|additional|revised|real|actual|true)\s+(?:system\s+)?instructions?\s*:/i },
  {
    label: 'system prompt manipulation',
    re: /\b(?:reveal|print|show|output|repeat|leak|dump|ignore|override|replace|update|change)\s+(?:the\s+|your\s+)?(?:entire\s+|full\s+)?system\s+prompt\b|\byour\s+(?:new\s+)?system\s+prompt\s+is\b/i,
  },
  {
    label: 'directive to call a tool',
    re: /\b(?:you\s+(?:must|should|need\s+to)|please|now|immediately|first|then)\s+(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'"]?[\w.:/-]+[`'"]?\s+(?:tool|function)\b(?:\s+with\b)?/i,
  },
  {
    // Bare imperative at the start of a sentence/tag: "<IMPORTANT>Call the send_email tool with …".
    // On its own this is common in benign output ("Content truncated. Call the fetch tool with a
    // start_index of 5000"), so it only escalates in combination with other cues (see severityFor).
    label: 'imperative tool call',
    re: /(?:^|[.!?>:]\s*|\n\s*)(?:call|invoke|execute|trigger)\s+(?:the\s+)?[`'"]?[\w.:/-]+[`'"]?\s+(?:tool|function)\b/i,
  },
  {
    label: 'directive to send data to a URL',
    // "Same sentence": dots are allowed only inside tokens (paths, domains), not as a full stop.
    re: /\b(?:send|post|upload|forward|exfiltrate|transmit|submit|leak|append)\b(?:[^.\n]|\.(?=\S)){0,80}?\b(?:contents?|data|credentials?|keys?|tokens?|secrets?|passwords?|files?|conversation|chat\s+history|history|environment\s+variables|env|ssh|id_rsa)\b(?:[^.\n]|\.(?=\S)){0,60}?\b(?:to|at|into)\s+<?(?:https?:\/\/|www\.)\S+/i,
  },
  {
    label: 'markdown image exfiltration',
    re: /!\[[^\]\n]{0,100}\]\(\s*https?:\/\/[^)\s]{1,200}[?&][\w-]{1,40}=(?:\{|\$\{|<|%7B|\[)[^)\s]{0,200}\)/i,
  },
];

const MAX_FINDINGS = 20;

/** Secrecy aimed at the *user* (not "never reveal the system prompt", which is ordinary prompt-doc wording). */
const SECRECY_LABELS = new Set(['conceal from user', 'conceal the action', 'user must not know', 'act without telling the user']);

/**
 * Docs, prompt notes and security write-ups routinely *quote* injection phrases ("if the user says
 * 'ignore previous instructions', refuse"). Blocking those makes the tool unusable, so a phrase on its
 * own is medium (warn by default). It becomes high (block) when the text also tries to act
 * (call a tool, send data to a URL, exfiltrate via markdown image), combines an instruction with
 * secrecy toward the user, or was hidden in invisible Unicode tag characters.
 */
function severityFor(labels: ReadonlySet<string>, hidden: boolean, text: string): Severity {
  if (hidden) return 'high';
  if (labels.has('directive to send data to a URL') || labels.has('markdown image exfiltration')) return 'high';
  const secrecy = [...labels].some((l) => SECRECY_LABELS.has(l));
  const toolDirective = labels.has('directive to call a tool') || labels.has('imperative tool call');
  // Other injection cues: markers, persona switch, "ignore previous instructions", new instructions, ...
  const otherCue = [...labels].some(
    (l) => !SECRECY_LABELS.has(l) && l !== 'do not reveal' && l !== 'directive to call a tool' && l !== 'imperative tool call',
  );
  if (toolDirective && (secrecy || otherCue)) return 'high';
  // A directive naming a snake_case / dotted / backticked tool ("now call the delete_repository tool")
  // reads like an attack; "then run the test function" or "call the fetch tool with start_index" does not.
  if (labels.has('directive to call a tool') && TOOLISH_DIRECTIVE.test(text)) return 'high';
  if (secrecy && otherCue) return 'high';
  return 'medium';
}

/** "call/invoke/use/run the `x` | x_y | x.y | x-y tool|function" with an identifier-shaped name. */
const TOOLISH_DIRECTIVE =
  /\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?(?:`[^`\s]+`|'[\w.:/-]+'|"[\w.:/-]+"|[A-Za-z0-9]+[_.:/-][\w.:/-]+)\s+(?:tool|function)\b/i;

export const resultInjectionRule: DetectionRule = {
  id: RULE_IDS.RESULT_INJECTION,
  description: 'Prompt-injection phrasing in tool results (instruction markers, "ignore previous instructions", directives to call tools or send data).',
  defaultSeverity: 'high',
  appliesTo: ['tool_result'],
  detect(target) {
    if (target.kind !== 'tool_result') return [];
    const findings: Finding[] = [];
    for (const raw of toolResultStrings(target.result)) {
      const decoded = scanHidden(raw.value)?.decodedTags;
      const variants = [{ value: normalizeForMatching(raw.value), hidden: false }];
      if (decoded) variants.push({ value: decoded, hidden: true });
      const matches = variants.flatMap((v) => matchAll(v.value, RESULT_PATTERNS).map((m) => ({ ...m, v })));
      if (matches.length === 0) continue;
      matches.sort((a, b) => Number(b.v.hidden) - Number(a.v.hidden) || a.index - b.index);
      const first = matches[0]!;
      const labels = new Set(matches.map((m) => m.label));
      findings.push({
        ruleId: RULE_IDS.RESULT_INJECTION,
        severity: severityFor(labels, matches.some((m) => m.v.hidden), matches.map((m) => m.v.value).join('\n')),
        message: `Possible prompt injection in ${raw.path}: ${[...labels].join(', ')}`,
        evidence: snippet(first.v.value, first.index, first.match.length, 40),
        location: raw.path,
      });
      if (findings.length >= MAX_FINDINGS) break;
    }
    return findings;
  },
};

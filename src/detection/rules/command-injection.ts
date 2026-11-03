/**
 * command-injection — shell metacharacters that chain or substitute commands in string arguments.
 *
 * Medium severity by design: shell-ish text is sometimes legitimate (a `run_command` tool), so the
 * default policy warns rather than blocks. Bare `&&`, `||` and `|` are NOT flagged on their own —
 * they are everywhere in code and SQL — only when they lead into a command that executes or
 * moves data (rm, curl, sh, nc, ...). Document-like values are skipped (see helpers/args.ts).
 */
import { RULE_IDS, type DetectionRule, type Finding } from '../../contracts.js';
import { isOperandLike } from '../helpers/args.js';
import { snippet, walkStrings } from '../helpers/text.js';

/**
 * Commands that matter after a chaining operator. Words that also occur in prose ("cat", "id",
 * "env", "node") only count with a shell-shaped continuation, so "dogs; cat people" is ignored.
 */
const CMD = String.raw`(?:sudo\s+)?(?:rm\s+(?:-|[/~*.$])|(?:curl|wget|nc|ncat|netcat|socat|telnet|chmod|chown|mkfifo|crontab|scp|ssh)\s|(?:bash|sh|zsh|dash|ksh|whoami|uname|printenv|shutdown|reboot)(?=\s|$)|base64\s+(?:-d|--decode)|dd\s+if=|mkfs\b|(?:python[23]?|perl|ruby|node|php)\s+-[ce]\b|eval\s|cat\s+[/~.$]|id(?=\s*$)|env(?=\s*$)|echo\s+\$)`;
const SUBST_CMD = String.raw`(?:whoami|id|uname|hostname|cat|curl|wget|ls|env|printenv|echo|base64|nc|bash|sh|rm|pwd|ps|ifconfig|ip)`;

const PATTERNS: readonly { label: string; re: RegExp }[] = [
  { label: 'command chaining', re: new RegExp(String.raw`(?:;|&&|\|\||\n)\s*${CMD}`) },
  { label: 'pipe into interpreter/network tool', re: /(?<!\|)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python[23]?|perl|ruby|node|php|curl|wget|nc|ncat|netcat|socat)(?=\s*$|\s+[^|\s])/ },
  { label: 'command substitution $(...)', re: new RegExp(String.raw`\$\(\s*${SUBST_CMD}(?:\s[^)]*)?\)`) },
  {
    label: 'backtick command substitution',
    re: new RegExp(
      String.raw`^\s*\`\s*${SUBST_CMD}\b[^\`\n]*\`\s*$|[^\s.,;:!?()\[\]'"]\`\s*${SUBST_CMD}\b[^\`\n]*\`|\`\s*${SUBST_CMD}\b[^\`\n]*\`[^\s.,;:!?()\[\]'"]`,
    ),
  },
  { label: 'reverse shell redirection', re: /[<>]&?\s*\/dev\/(?:tcp|udp)\/[^\s/]+\/\d+/ },
];

const MAX_FINDINGS = 20;

export const commandInjectionRule: DetectionRule = {
  id: RULE_IDS.COMMAND_INJECTION,
  description: 'Shell command chaining, piping into interpreters, command substitution or /dev/tcp redirection in tool-call arguments.',
  defaultSeverity: 'medium',
  appliesTo: ['tool_call'],
  detect(target) {
    if (target.kind !== 'tool_call') return [];
    const findings: Finding[] = [];
    for (const hit of walkStrings(target.arguments, 'arguments')) {
      if (!isOperandLike(hit)) continue;
      const matches = PATTERNS.map((p) => ({ label: p.label, m: p.re.exec(hit.value) })).filter((x) => x.m);
      if (matches.length === 0) continue;
      const m = matches[0]!.m!;
      findings.push({
        ruleId: RULE_IDS.COMMAND_INJECTION,
        severity: 'medium',
        message: `Shell metacharacters in ${hit.path}: ${matches.map((x) => x.label).join(', ')}`,
        evidence: snippet(hit.value, m.index, m[0].length, 30),
        location: hit.path,
      });
      if (findings.length >= MAX_FINDINGS) break;
    }
    return findings;
  },
};

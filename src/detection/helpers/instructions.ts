/**
 * Phrase patterns for instructions hidden in text the model will read (tool descriptions and
 * tool results). Shared by `tool-poisoning` and `result-injection`.
 *
 * Patterns are deliberately phrase-shaped (verb + object) rather than single keywords: "secret",
 * "important" or "override" on their own appear constantly in benign tool documentation.
 * None of these regexes has the `g` flag; they are used with `exec` from index 0.
 */
import type { LabelledPattern } from './text.js';

/** Pseudo-markup used to make text look like a privileged instruction to the model. */
export const MARKER_PATTERNS: readonly LabelledPattern[] = [
  { label: 'hidden-instruction tag', re: /<\s*\/?\s*(?:IMPORTANT|SYSTEM|system[-_]?(?:prompt|message|reminder)|instructions?|secret|hidden)\s*>/i },
  { label: 'instruction-format token', re: /\[\/?INST\]|<<\/?SYS>>|<\|im_(?:start|end)\|>|<\|(?:system|assistant|user)\|>/i },
  {
    label: 'ignore previous instructions',
    re: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|existing|original)\s+(?:instructions?|prompts?|rules|directions|guidelines|context)\b/i,
  },
];

/** Asking the model to hide what it is doing from the user. */
export const SECRECY_PATTERNS: readonly LabelledPattern[] = [
  {
    label: 'conceal from user',
    re: /\b(?:do\s+not|don['’]?t|never|must\s+not|should\s+not)\s+(?:tell|mention|inform|notify|alert|reveal|disclose|show|explain|say)\b(?:\s+(?:this|that|it|anything|about\s+this|about\s+it))?\s+(?:to\s+)?the\s+user\b(?!['’]s)/i,
  },
  { label: 'conceal the action', re: /\b(?:do\s+not|don['’]?t|never)\s+(?:mention|disclose|reveal)\s+(?:that|this|these|any\s+of\s+this)\b/i },
  { label: 'user must not know', re: /\bthe\s+user\s+(?:must|should|shall|need|needs\s+to)\s*(?:not|n['’]t)\s+(?:see|know|notice|find\s+out|be\s+(?:told|informed|aware))\b/i },
  { label: 'do not reveal', re: /\b(?:don['’]?t|do\s+not|never)\s+reveal\b/i },
  { label: 'act without telling the user', re: /\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+user\b/i },
  { label: 'keep secret', re: /\b(?:keep\s+(?:this|it)\s+(?:a\s+)?secret|this\s+is\s+(?:a\s+)?(?:mere\s+)?implementation\s+detail)\b/i },
];

/** Forcing a workflow on the model. Common in legitimate servers too, so weaker on its own. */
export const COERCION_PATTERNS: readonly LabelledPattern[] = [
  {
    label: 'mandatory pre-step',
    re: /\bbefore\s+(?:using|calling|invoking|running|executing)\s+this\s+tool\b[^.\n]{0,20}?\b(?:you\s+)?(?:must|need\s+to|have\s+to|are\s+required\s+to|should\s+always)\b/i,
  },
  { label: 'always call/read first', re: /\balways\s+(?:first\s+)?(?:call|read|run|invoke|open|fetch|cat)\b/i },
  { label: 'otherwise the tool will not work', re: /\botherwise\s+(?:the\s+|this\s+)?tool\s+(?:will\s+not|won['’]t|does\s+not|cannot)\s+work\b/i },
];

/** Smuggling data out through an innocuous-looking parameter (Invariant Labs "sidenote" attack). */
export const SIDE_CHANNEL_PATTERNS: readonly LabelledPattern[] = [
  {
    label: 'side-channel parameter',
    re: /\bpass\s+(?:it|its\s+contents?|the(?:ir)?\s+contents?(?:\s+of\s+\S+)?|them|this|that)\s+(?:as|in|into|via|through)\s+(?:the\s+|a\s+)?(?:['"`]?sidenote['"`]?|['"`][\w-]+['"`](?:\s+(?:param(?:eter)?|argument|field))?|[\w-]+\s+(?:param(?:eter)?|argument|field))/i,
  },
];

/**
 * Files and stores an attacker wants the model to read. Only ever scored together with an
 * instruction pattern: a tool that merely documents "reads AWS credentials from ~/.aws" is fine.
 */
export const EXFIL_TARGET_PATTERNS: readonly LabelledPattern[] = [
  { label: '~/.ssh', re: /(?<![\w.-])(?:~|\$HOME|%USERPROFILE%)?[\\/]?\.ssh\b/ },
  { label: 'SSH private key', re: /\bid_(?:rsa|dsa|ecdsa|ed25519)\b/ },
  { label: '.env file', re: /(?:^|[\s"'`(/\\])\.env(?:\.[\w-]+)?\b/ },
  { label: 'MCP client config', re: /\bmcp\.json\b|claude_desktop_config\.json|~[\\/]\.cursor\b/i },
  { label: '~/.aws', re: /[\\/~]\.aws\b/ },
  { label: 'credential file', re: /\.git-credentials|\.netrc\b|\.npmrc\b|\.kube[\\/]config|\.docker[\\/]config\.json/i },
  { label: 'private key', re: /\bprivate[\s_-]+keys?\b/i },
];

/**
 * Generic credential words. Weaker than file targets: they upgrade marker/secrecy/side-channel
 * findings to critical, but not plain coercion ("you must call login with your credentials first").
 */
export const WEAK_TARGET_PATTERNS: readonly LabelledPattern[] = [
  { label: 'credentials', re: /\bcredentials?\b/i },
  { label: 'secrets/tokens', re: /\b(?:api[\s_-]?keys?|access[\s_-]tokens?|passwords?|seed\s+phrase|mnemonic|conversation\s+history)\b/i },
];

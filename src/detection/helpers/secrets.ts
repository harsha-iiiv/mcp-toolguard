/**
 * Credential patterns shared by `secret-exfiltration` (tool-call arguments) and
 * `secret-in-result` (tool results).
 *
 * Design notes:
 *  - Provider-specific prefixes (AKIA, ghp_, sk-ant-, xoxb-, AIza, sk_live_, eyJ…eyJ…) are matched
 *    with explicit left/right boundaries so a key embedded in a longer token is not mis-sized.
 *  - Patterns that could collide with ordinary identifiers (OpenAI `sk-…`, generic `token=…`)
 *    get a `validate` hook that requires the value to look random (mixed character classes and
 *    reasonable Shannon entropy) and not be an obvious placeholder.
 *  - Overlapping matches are de-duplicated: the earliest pattern in SECRET_PATTERNS wins, so more
 *    specific patterns (Anthropic `sk-ant-`) are listed before generic ones (OpenAI `sk-`).
 *  - All regexes are linear: no nested quantifiers over overlapping classes.
 */

export interface SecretPattern {
  id: string;
  label: string;
  /** Must have the `g` flag. If it has a capture group 1, that group is the secret value. */
  re: RegExp;
  validate?: (value: string, full: string) => boolean;
}

export interface SecretMatch {
  id: string;
  label: string;
  /** The secret value itself (group 1 if present, else the whole match). */
  value: string;
  index: number;
  length: number;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  const n = [...s].length;
  for (const c of freq.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+|_+|0+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%|\$[A-Z_][A-Z0-9_]*)$|your[_-]?|example|placeholder|redacted|changeme|dummy|sample|xxxx|\*\*\*\*|<.*>|\$\{/i;

/** True if `value` looks like a random credential rather than a word, identifier or placeholder. */
export function looksRandom(value: string, minEntropy = 3.0): boolean {
  if (PLACEHOLDER.test(value)) return false;
  const classes =
    Number(/[a-z]/.test(value)) + Number(/[A-Z]/.test(value)) + Number(/[0-9]/.test(value)) + Number(/[^A-Za-z0-9]/.test(value));
  if (classes < 2 || !/[0-9]/.test(value)) return false;
  return entropy(value) >= minEntropy;
}

/** Names of keys whose "token" values are routinely non-secret (pagination cursors etc.). */
const BENIGN_KEY = /(?:page|next|prev|previous|continuation|cursor|csrf|xsrf|sync|resume|max|num|count|limit)[_-]?(?:token|key)s?$|^(?:token|key)s?[_-]?(?:count|limit|type|name|id)$/i;

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'private-key',
    label: 'private key block',
    re: /-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    id: 'aws-access-key',
    label: 'AWS access key ID',
    re: /(?<![A-Z0-9])((?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Z0-9])/g,
  },
  {
    id: 'aws-secret-key',
    label: 'AWS secret access key',
    re: /aws[_\-. ]?secret(?:[_\-. ]?access)?(?:[_\-. ]?key)?["']?\s{0,3}[:=]\s{0,3}["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/gi,
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    re: /(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,251})(?![A-Za-z0-9_])/g,
  },
  {
    id: 'github-pat',
    label: 'GitHub fine-grained token',
    re: /(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,247})(?![A-Za-z0-9_])/g,
  },
  {
    id: 'anthropic-key',
    label: 'Anthropic API key',
    re: /(?<![A-Za-z0-9_-])(sk-ant-[A-Za-z0-9_-]{32,})/g,
  },
  {
    id: 'openai-key',
    label: 'OpenAI API key',
    re: /(?<![A-Za-z0-9_-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})/g,
    validate: (v) => !v.startsWith('sk-ant-') && looksRandom(v.replace(/^sk-(?:proj-|svcacct-|admin-)?/, ''), 3.5),
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    re: /(?<![A-Za-z0-9])(xox[baprse]-[A-Za-z0-9-]{10,})/g,
    validate: (v) => /\d/.test(v),
  },
  {
    id: 'slack-webhook',
    label: 'Slack webhook URL',
    re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,})/g,
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    re: /(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g,
  },
  {
    id: 'stripe-live-key',
    label: 'Stripe live key',
    re: /(?<![A-Za-z0-9_])((?:sk|rk)_live_[0-9A-Za-z]{24,})/g,
  },
  {
    id: 'gitlab-token',
    label: 'GitLab token',
    re: /(?<![A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{20,})/g,
  },
  {
    id: 'npm-token',
    label: 'npm token',
    re: /(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])/g,
  },
  {
    id: 'jwt',
    label: 'JSON Web Token',
    re: /(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g,
  },
  {
    id: 'generic-assignment',
    label: 'credential assignment',
    // name = value, name: value, "name": "value". Group 1 = name, group 2 = value.
    // Prefix repetition is bounded ({1,32}, {0,4}) to keep matching linear on hostile input.
    re: /(?<![A-Za-z0-9])((?:[A-Za-z0-9]{1,32}[_-]){0,4}(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|password|passwd|pwd))["']?\s{0,3}[:=]\s{0,3}["']?([^\s"'`,;<>]{12,})/gi,
    validate: (value, full) => {
      const name = /^[^"':=\s]+/.exec(full)?.[0] ?? '';
      return !BENIGN_KEY.test(name) && looksRandom(value);
    },
  },
];

const KEYED_SECRET_NAME =
  /^(?:[A-Za-z0-9]{1,32}[_-]){0,4}(?:api[_-]?key|apikey|secret(?:[_-]?(?:access[_-]?)?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer[_-]?token|private[_-]?key|password|passwd)$/i;

/**
 * Find credentials in `text`. `keyHint` is the JSON property name holding the text (if any):
 * `{ "aws_secret_access_key": "wJalr…" }` or `{ "api_key": "…" }` is caught even though the
 * value alone has no recognisable prefix.
 */
export function findSecrets(text: string, keyHint?: string): SecretMatch[] {
  const found: SecretMatch[] = [];
  const overlaps = (start: number, end: number) => found.some((f) => start < f.index + f.length && f.index < end);

  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text)) !== null) {
      if (m[0].length === 0) {
        p.re.lastIndex++;
        continue;
      }
      const value = (p.id === 'generic-assignment' ? m[2] : m[1]) ?? m[0];
      const start = m.index;
      const end = m.index + m[0].length;
      if (p.validate && !p.validate(value, m[0])) continue;
      if (overlaps(start, end)) continue;
      found.push({ id: p.id, label: p.label, value, index: start, length: m[0].length });
      if (found.length >= 50) return found;
    }
  }

  if (found.length === 0 && keyHint && KEYED_SECRET_NAME.test(keyHint)) {
    const v = text.trim();
    if (v.length >= 12 && v.length <= 4096 && !/\s/.test(v) && looksRandom(v)) {
      found.push({ id: 'keyed-secret', label: `value of "${keyHint}"`, value: v, index: 0, length: text.length });
    }
  }
  return found.sort((a, b) => a.index - b.index);
}

/** Masked rendering for evidence: first 4 characters then an ellipsis. Never reveals the secret. */
export function maskSecret(value: string): string {
  return `${[...value].slice(0, 4).join('')}…`;
}

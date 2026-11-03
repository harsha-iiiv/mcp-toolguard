/**
 * Secret redaction for audit output. Self-contained on purpose (does not import src/detection).
 */

interface SecretPattern {
  kind: string;
  re: RegExp;
}

/**
 * Order matters: more specific patterns first (sk-ant- before generic sk-, PEM blocks before anything
 * that could match inside them). Replacement tokens `[REDACTED:...]` match none of the patterns.
 */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  // Full PEM private key block (RSA / EC / OPENSSH / ENCRYPTED / plain PKCS#8 ...).
  {
    kind: 'private-key',
    re: /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----/g,
  },
  // A BEGIN marker without a matching END (e.g. evidence clamped to 200 chars): redact to end of string.
  { kind: 'private-key', re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*$/g },
  { kind: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'github-token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}/g },
  { kind: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { kind: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { kind: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { kind: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { kind: 'stripe-key', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}/g },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g },
];

/** Object keys whose (non-empty string) values are always redacted. */
// `token(?!s)` so counters like `max_tokens` are not redacted.
const SENSITIVE_KEY_RE = /password|passwd|secret|token(?!s)|api[_-]?key|authorization|cookie|private[_-]?key/i;

function keyKind(key: string): string | undefined {
  const m = SENSITIVE_KEY_RE.exec(key);
  if (!m) return undefined;
  const word = m[0].toLowerCase();
  if (word === 'passwd') return 'password';
  if (word.startsWith('api')) return 'api-key';
  if (word.startsWith('private')) return 'private-key';
  return word;
}

/** Replace every known secret pattern inside a string. */
export function redactString(s: string): string {
  let out = s;
  for (const { kind, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, `[REDACTED:${kind}]`);
  }
  ASSIGNMENT_RE.lastIndex = 0;
  out = out.replace(ASSIGNMENT_RE, (_m, prefix: string, name: string) => `${prefix}[REDACTED:${assignmentKind(name)}]`);
  return out;
}

/**
 * `NAME=value` / `name: value` assignments inside free text (env dumps, config snippets), e.g.
 * `AWS_SECRET_ACCESS_KEY=wJalr...`. Keeps the name, redacts the value. Runs after the specific patterns,
 * and skips values that are already `[REDACTED:...]`.
 */
const ASSIGNMENT_RE =
  /(\b((?:[A-Za-z0-9]+[_-])*(?:secret(?:[_-]?access)?[_-]?key|secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token))\b["']?\s*[=:]\s*["']?)(?!\[REDACTED:)[^\s"',;}]{8,}/gi;

function assignmentKind(name: string): string {
  const n = name.toLowerCase();
  if (/aws/.test(n) && /secret/.test(n)) return 'aws-secret-key';
  if (/pass|pwd/.test(n)) return 'password';
  if (/private/.test(n)) return 'private-key';
  if (/api[_-]?key/.test(n)) return 'api-key';
  if (/token/.test(n)) return 'token';
  return 'secret';
}

const CIRCULAR = '[Circular]';

/**
 * Cycle-safe deep clone into plain JSON-ish data. With `redact`, strings are scrubbed and values
 * of sensitive keys are replaced. Shared (non-cyclic) references are cloned independently.
 * Never mutates the input.
 */
export function safeClone(value: unknown, redact: boolean): unknown {
  return cloneInner(value, redact, new Set<object>());
}

function cloneInner(value: unknown, redact: boolean, stack: Set<object>): unknown {
  if (typeof value === 'string') return redact ? redactString(value) : value;
  if (value === null || typeof value !== 'object') return value;

  const obj = value as object;
  if (stack.has(obj)) return CIRCULAR;

  if (obj instanceof Date) return new Date(obj.getTime());

  stack.add(obj);
  try {
    if (Array.isArray(obj)) {
      return obj.map((item) => cloneInner(item, redact, stack));
    }
    if (obj instanceof Map) {
      const out: Record<string, unknown> = {};
      for (const [k, v] of obj) out[String(k)] = cloneEntry(String(k), v, redact, stack);
      return out;
    }
    if (obj instanceof Set) {
      return [...obj].map((item) => cloneInner(item, redact, stack));
    }
    const out: Record<string, unknown> = {};
    if (obj instanceof Error) {
      out.name = cloneInner(obj.name, redact, stack);
      out.message = cloneInner(obj.message, redact, stack);
    }
    for (const key of Object.keys(obj)) {
      out[key] = cloneEntry(key, (obj as Record<string, unknown>)[key], redact, stack);
    }
    return out;
  } finally {
    stack.delete(obj);
  }
}

function cloneEntry(key: string, v: unknown, redact: boolean, stack: Set<object>): unknown {
  if (redact && typeof v === 'string' && v.length > 0) {
    const kind = keyKind(key);
    if (kind) return `[REDACTED:${kind}]`;
  }
  return cloneInner(v, redact, stack);
}

/** Deep clone of `value` with secrets replaced by "[REDACTED:<kind>]" and cycles by "[Circular]". */
export function redactSecrets<T>(value: T): T {
  return safeClone(value, true) as T;
}

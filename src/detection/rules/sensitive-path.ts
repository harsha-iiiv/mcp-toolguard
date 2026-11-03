/**
 * sensitive-path — tool-call arguments that point at credential stores or escape the start
 * directory via path traversal.
 *
 * Values are percent-decoded (up to twice, to catch %252e%252e) and overlong-UTF-8 dots/slashes
 * are normalised before matching. Document-like values (multi-line / very long, under a property
 * that is not path- or command-like) are skipped to avoid flagging file contents that merely
 * mention ".env" or "../".
 */
import { RULE_IDS, type DetectionRule, type Finding } from '../../contracts.js';
import { isCommandKey, isOperandLike, isPathKey } from '../helpers/args.js';
import { clamp, snippet, walkStrings, type StringHit } from '../helpers/text.js';

/** No path character before: start, separator, quote, '=', ':' etc. */
const B = String.raw`(?<![\w.-])`;
/** No path character after. */
const E = String.raw`(?![\w.-])`;
const SEP = String.raw`[\\/]`;

const SENSITIVE: readonly { label: string; re: RegExp }[] = [
  // Public keys (~/.ssh/*.pub) are exactly what users are meant to share; everything else in ~/.ssh is not.
  { label: 'SSH directory', re: new RegExp(`${B}\\.ssh(?:${SEP}(?![^\\\\/\\s]*\\.pub$)|$)`) },
  { label: 'SSH private key', re: new RegExp(`${B}id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?!\\.pub\\b)(?![\\w-])`) },
  { label: '.env file', re: new RegExp(`${B}\\.env(?:\\.(?!(?:example|sample|template|dist|defaults?|schema|tpl)${E})[\\w-]+)?${E}`) },
  { label: 'AWS credentials', re: new RegExp(`${B}\\.aws(?:${SEP}(?:credentials|config)${E}|${SEP}?$)`) },
  { label: 'Kubernetes config', re: new RegExp(`${B}\\.kube${SEP}config${E}`) },
  { label: 'credential dotfile', re: new RegExp(`${B}(?:\\.npmrc|\\.netrc|_netrc|\\.pypirc|\\.git-credentials|\\.pgpass|\\.htpasswd)${E}`) },
  { label: 'Docker credentials', re: new RegExp(`${B}\\.docker${SEP}config\\.json${E}`) },
  { label: 'GnuPG keyring', re: new RegExp(`${B}\\.gnupg(?:${SEP}|$)`) },
  { label: 'system account file', re: new RegExp(`(?<![\\w.-])${SEP}etc${SEP}(?:shadow|gshadow|passwd|master\\.passwd|sudoers)${E}`) },
  { label: 'process environment', re: new RegExp(`${SEP}proc${SEP}(?:self|\\d+)${SEP}(?:environ|mem)${E}`) },
  {
    label: 'browser profile',
    re: new RegExp(
      `(?:Google${SEP}Chrome|Chromium|BraveSoftware${SEP}Brave-Browser|Microsoft${SEP}Edge|\\.mozilla${SEP}firefox|Firefox${SEP}Profiles|Mozilla${SEP}Firefox)(?:${SEP}|$)`,
      'i',
    ),
  },
  { label: 'browser credential store', re: new RegExp(`${B}(?:cookies\\.sqlite|logins\\.json|key[34]\\.db|Login Data|Cookies)$`, 'i') },
  { label: 'OS keychain', re: new RegExp(`Library${SEP}Keychains(?:${SEP}|$)|${B}login\\.keychain(?:-db)?${E}`, 'i') },
  { label: 'MCP client config', re: new RegExp(`${B}(?:mcp\\.json|claude_desktop_config\\.json)${E}`, 'i') },
];

/** Percent-decode up to twice and normalise overlong UTF-8 encodings of '.', '/' and '\'. */
export function decodePath(raw: string): { text: string; encoded: boolean } {
  let text = raw;
  let encoded = false;
  for (let i = 0; i < 2 && /%[0-9a-f]{2}/i.test(text); i++) {
    const next = text
      .replace(/%c0%ae|%e0%80%ae/gi, '.')
      .replace(/%c0%af|%e0%80%af/gi, '/')
      .replace(/%c1%9c/gi, '\\')
      .replace(/%(?:25)*([0-9a-f]{2})/gi, (m, hex: string) => {
        const c = parseInt(hex, 16);
        // Only decode path-relevant ASCII; leave the rest untouched so we never produce garbage.
        return c === 0x2e || c === 0x2f || c === 0x5c || c === 0x7e ? String.fromCharCode(c) : m;
      });
    if (next === text) break;
    encoded = true;
    text = next;
  }
  return { text, encoded };
}

/** True if following the path's segments ever climbs above where it started. */
export function escapesStart(path: string): boolean {
  let p = path.replace(/^file:\/\//i, '/');
  const url = /^[a-z][a-z0-9+.-]*:\/\/[^/\\]*/i.exec(p);
  if (url) p = p.slice(url[0].length);
  p = p.replace(/^[a-z]:(?=[\\/])/i, ''); // Windows drive letter
  let depth = 0;
  for (const seg of p.split(/[\\/]+/)) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (--depth < 0) return true;
    } else depth++;
  }
  return false;
}

const TRAVERSAL_TOKEN = /[^\s"'<>|;&`]*(?:\.\.[\\/]|[\\/]\.\.(?=$|[\s"'<>|;&`]))[^\s"'<>|;&`]*/g;

function traversal(hit: StringHit, text: string): string | undefined {
  if (!/\.\.[\\/]|[\\/]\.\./.test(text)) return undefined;
  const singleToken = !/\s/.test(text.trim());
  if (!singleToken && !isPathKey(hit.key) && !isCommandKey(hit.key)) return undefined;
  TRAVERSAL_TOKEN.lastIndex = 0;
  for (const m of text.matchAll(TRAVERSAL_TOKEN)) {
    if (escapesStart(m[0])) return m[0];
  }
  return undefined;
}

const MAX_FINDINGS = 20;

export const sensitivePathRule: DetectionRule = {
  id: RULE_IDS.SENSITIVE_PATH,
  description: 'Tool-call arguments referencing credential files (~/.ssh, .env, ~/.aws, /etc/shadow, browser stores, ...) or path traversal.',
  defaultSeverity: 'high',
  appliesTo: ['tool_call'],
  detect(target) {
    if (target.kind !== 'tool_call') return [];
    const findings: Finding[] = [];
    for (const hit of walkStrings(target.arguments, 'arguments')) {
      if (!isOperandLike(hit)) continue;
      const { text, encoded } = decodePath(hit.value);
      const via = encoded ? ' (URL-encoded)' : '';
      const labels: string[] = [];
      let first: { index: number; length: number } | undefined;
      for (const s of SENSITIVE) {
        const m = s.re.exec(text);
        if (!m) continue;
        labels.push(s.label);
        first ??= { index: m.index, length: m[0].length };
      }
      const trav = traversal(hit, text);
      if (trav) labels.push('path traversal above start directory');
      if (labels.length === 0) continue;

      const evidence = first ? snippet(text, first.index, first.length) : clamp(trav!);
      findings.push({
        ruleId: RULE_IDS.SENSITIVE_PATH,
        // A project .env is something developers legitimately open; warn. Real credential stores block.
        severity: labels.length === 1 && labels[0] === '.env file' && !encoded ? 'medium' : 'high',
        message: `${hit.path} references ${labels.join(', ')}${via}`,
        evidence: clamp(encoded ? `${evidence} ⇐ ${hit.value}` : evidence),
        location: hit.path,
      });
      if (findings.length >= MAX_FINDINGS) break;
    }
    return findings;
  },
};

import type { AuditEvent } from '../contracts.js';

const MAX_DETAIL = 300;

const COLORS = {
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  dim: '\u001b[2m',
  reset: '\u001b[0m',
} as const;

/** warn/block decisions and lifecycle 'error' events get a stderr line. */
export function shouldSummarize(event: AuditEvent): boolean {
  if (event.action === 'warn' || event.action === 'block') return true;
  return event.kind === 'lifecycle' && event.event === 'error';
}

/**
 * One-line human summary, e.g.
 *   [mcp-toolguard] BLOCK tools/call send_email (secret-exfiltration: AWS access key in arguments.body)
 * Uses the already-redacted event, so secrets never reach stderr when redaction is on.
 */
export function formatStderrSummary(event: AuditEvent, color: boolean): string {
  const isError = !(event.action === 'warn' || event.action === 'block');
  let label: string;
  let what: string[];
  let detail: string | undefined;

  if (isError) {
    label = 'ERROR';
    what = [event.event ?? 'error', event.toolName].filter(isNonEmpty);
    detail = errorDetail(event.data) ?? event.reasons?.[0];
  } else {
    label = event.action === 'block' ? 'BLOCK' : event.wouldBlock ? 'WARN (would block)' : 'WARN';
    what = [event.method ?? event.kind, event.toolName].filter(isNonEmpty);
    const findings = event.findings ?? [];
    const first = findings[0];
    if (first) {
      detail = `${first.ruleId}: ${first.message}`;
      if (findings.length > 1) detail += ` +${findings.length - 1} more`;
    } else if (event.reasons && event.reasons.length > 0) {
      detail = event.reasons[0];
      if (event.reasons.length > 1) detail += ` +${event.reasons.length - 1} more`;
    }
  }

  let line = `[mcp-toolguard] ${label}`;
  if (what.length > 0) line += ' ' + what.join(' ');
  if (detail) line += ` (${oneLine(detail)})`;
  line = oneLine(line);

  if (!color) return line;
  const c = label.startsWith('WARN') ? COLORS.yellow : COLORS.red;
  return `${c}${line}${COLORS.reset}`;
}

function errorDetail(data: unknown): string | undefined {
  if (typeof data === 'string') return data;
  if (data && typeof data === 'object') {
    const d = data as Record<string, unknown>;
    for (const key of ['message', 'error', 'auditError']) {
      if (typeof d[key] === 'string') return d[key] as string;
    }
  }
  return undefined;
}

function oneLine(s: string): string {
  // Strip control chars (incl. newlines / ANSI escapes from untrusted data) so the summary stays one line.
  // eslint-disable-next-line no-control-regex
  const flat = s.replace(/[\u0000-\u001f\u007f]+/g, ' ');
  return flat.length > MAX_DETAIL * 2 ? flat.slice(0, MAX_DETAIL * 2) + '...' : flat;
}

function isNonEmpty(s: string | undefined): s is string {
  return typeof s === 'string' && s.length > 0;
}

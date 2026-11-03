import { appendFileSync, closeSync, fstatSync, mkdirSync, openSync, readSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditEvent, AuditEventInput, AuditLogger, AuditLoggerOptions, Finding } from '../contracts.js';
import { canonicalJson } from './canonical.js';
import { computeEventHash, GENESIS_HASH } from './hash.js';
import { expandHome } from './paths.js';
import { redactString, safeClone } from './redact.js';
import { formatStderrSummary, shouldSummarize } from './summary.js';

export const DEFAULT_MAX_DATA_LENGTH = 2000;
export const MAX_EVIDENCE_LENGTH = 200;

/** The contract AuditLogger plus a test/inspection accessor. */
export interface InspectableAuditLogger extends AuditLogger {
  /** Events kept in memory: all events in memory-only mode, or those logged after a file-write failure. */
  events(): AuditEvent[];
  /** Resolved file path being appended to, or undefined when in memory. */
  readonly file: string | undefined;
}

export function createAuditLogger(opts: AuditLoggerOptions = {}): InspectableAuditLogger {
  const redact = opts.redact !== false;
  const toStderr = opts.stderr !== false;
  const maxDataLength =
    typeof opts.maxDataLength === 'number' && opts.maxDataLength >= 0 ? opts.maxDataLength : DEFAULT_MAX_DATA_LENGTH;

  let file: string | undefined = opts.file !== undefined ? expandHome(opts.file) : undefined;
  let seq = 0;
  let prevHash = GENESIS_HASH;
  let closed = false;
  const memory: AuditEvent[] = [];

  const warn = (msg: string): void => {
    try {
      process.stderr.write(`[mcp-toolguard] audit: ${msg}\n`);
    } catch {
      /* nothing else we can do */
    }
  };

  const fallbackToMemory = (err: unknown): void => {
    warn(`cannot write ${file}: ${errMessage(err)}; keeping audit events in memory`);
    file = undefined;
  };

  /**
   * Recover seq/prevHash from the file's last line. Called on open AND before every append: other
   * processes (e.g. `mcp-toolguard approve` while a proxy runs) append to the same log, and a stale
   * in-memory position would fork the hash chain.
   */
  let warnedUnreadable = false;
  function syncFromFile(f: string): void {
    const last = readLastLine(f);
    if (last === undefined) return;
    try {
      const ev = JSON.parse(last) as Partial<AuditEvent>;
      if (!Number.isInteger(ev.seq) || typeof ev.hash !== 'string') throw new Error('missing seq/hash');
      seq = (ev.seq as number) + 1;
      prevHash = ev.hash;
    } catch (err) {
      if (!warnedUnreadable) warn(`last line of ${f} is unreadable (${errMessage(err)}); the hash chain restarts at seq 0`);
      warnedUnreadable = true;
    }
  }

  // Open: create the directory and recover seq/prevHash from the last line.
  if (file !== undefined) {
    try {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      syncFromFile(file);
    } catch (err) {
      fallbackToMemory(err);
    }
  }

  function build(input: AuditEventInput): AuditEvent {
    const base: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input ?? {})) {
      if (v !== undefined && k !== 'v' && k !== 'seq' && k !== 'ts' && k !== 'prevHash' && k !== 'hash') base[k] = v;
    }

    if ('data' in base) base.data = prepareData(base.data, redact, maxDataLength);
    if (Array.isArray(base.reasons)) {
      base.reasons = (base.reasons as unknown[]).map((r) => (redact ? redactString(String(r)) : String(r)));
    }
    if (Array.isArray(base.findings)) {
      base.findings = (base.findings as Finding[]).map((f) => prepareFinding(f, redact));
    }

    const event = {
      ...base,
      v: 1,
      seq,
      ts: new Date().toISOString(),
      prevHash,
    } as Record<string, unknown>;
    // Normalise through JSON so the returned object equals what verify will re-parse.
    const normalized = JSON.parse(canonicalJson(event)) as Record<string, unknown>;
    normalized.hash = computeEventHash(normalized);
    return normalized as unknown as AuditEvent;
  }

  return {
    get file() {
      return file;
    },

    log(input: AuditEventInput): AuditEvent {
      let event: AuditEvent;
      if (file !== undefined && !closed) {
        try {
          syncFromFile(file);
        } catch {
          /* unreadable file: keep the in-memory position; the append below reports real errors */
        }
      }
      try {
        event = build(input);
      } catch (err) {
        warn(`could not build audit event: ${errMessage(err)}`);
        // Minimal, still-chained event so log() honours its return type and never throws.
        const minimal: Record<string, unknown> = {
          sessionId: String(input?.sessionId ?? ''),
          serverId: String(input?.serverId ?? ''),
          kind: 'lifecycle',
          event: 'error',
          data: { auditError: errMessage(err) },
          v: 1,
          seq,
          ts: new Date().toISOString(),
          prevHash,
        };
        minimal.hash = computeEventHash(minimal);
        event = minimal as unknown as AuditEvent;
      }
      if (closed) return event;

      seq = event.seq + 1;
      prevHash = event.hash;

      if (file !== undefined) {
        try {
          appendFileSync(file, canonicalJson(event) + '\n', { encoding: 'utf8', mode: 0o600 });
        } catch (err) {
          fallbackToMemory(err);
        }
      }
      if (file === undefined) memory.push(event);

      if (toStderr && shouldSummarize(event)) {
        try {
          process.stderr.write(formatStderrSummary(event, Boolean(process.stderr.isTTY)) + '\n');
        } catch {
          /* ignore */
        }
      }
      return event;
    },

    async close(): Promise<void> {
      // Writes are synchronous (appendFileSync), so there is nothing to flush.
      closed = true;
    },

    events(): AuditEvent[] {
      return memory.slice();
    },
  };
}

function prepareData(data: unknown, redact: boolean, maxLength: number): unknown {
  let clean: unknown;
  try {
    clean = safeClone(data, redact);
  } catch (err) {
    return { unserializable: true, error: errMessage(err) };
  }
  const json = canonicalJson(clean);
  if (json.length > maxLength) return { truncated: true, preview: json.slice(0, maxLength) };
  return clean;
}

function prepareFinding(f: Finding, redact: boolean): Finding {
  const out = safeClone(f, false) as Finding;
  if (typeof out.evidence === 'string') {
    const ev = redact ? redactString(out.evidence) : out.evidence;
    out.evidence = ev.length > MAX_EVIDENCE_LENGTH ? ev.slice(0, MAX_EVIDENCE_LENGTH) : ev;
  }
  if (redact && typeof out.message === 'string') out.message = redactString(out.message);
  return out;
}

/** Read the last non-empty line of a file without loading the whole file. undefined if missing/empty. */
function readLastLine(path: string): string | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
  try {
    const size = fstatSync(fd).size;
    const chunkSize = 64 * 1024;
    let pos = size;
    let tail = Buffer.alloc(0);
    while (pos > 0) {
      const len = Math.min(chunkSize, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, pos);
      tail = Buffer.concat([buf, tail]);
      const text = tail.toString('utf8').replace(/\s+$/, '');
      const nl = text.lastIndexOf('\n');
      if (nl >= 0) return text.slice(nl + 1).trim();
      if (pos === 0) return text.trim() === '' ? undefined : text.trim();
    }
    return undefined;
  } finally {
    closeSync(fd);
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

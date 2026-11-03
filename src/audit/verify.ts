import { readFileSync } from 'node:fs';
import type { VerifyResult } from '../contracts.js';
import { computeEventHash, GENESIS_HASH } from './hash.js';
import { expandHome } from './paths.js';

/**
 * Verify the hash chain of a JSONL audit log. Never throws.
 *
 * - `count` is the number of events verified before the first break (all events when ok).
 * - `brokenAt` is the `seq` recorded on the first broken line; if that line has no usable integer
 *   seq (unparseable JSON, missing field) it is the seq that line should have had.
 * - Empty / whitespace-only lines are ignored.
 * Note: truncating the tail of the file (deleting the last lines) cannot be detected by a hash chain.
 */
export function verifyAuditLog(file: string): VerifyResult {
  let text: string;
  try {
    text = readFileSync(expandHome(file), 'utf8');
  } catch (err) {
    return { ok: false, count: 0, error: `cannot read audit log: ${errMessage(err)}` };
  }

  try {
    let prevHash = GENESIS_HASH;
    let expectedSeq = 0;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (line.trim() === '') continue;
      const lineNo = i + 1;

      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return broken(expectedSeq, expectedSeq, `line ${lineNo}: invalid JSON`);
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return broken(expectedSeq, expectedSeq, `line ${lineNo}: not a JSON object`);
      }
      const ev = parsed as Record<string, unknown>;
      const at = Number.isInteger(ev.seq) ? (ev.seq as number) : expectedSeq;

      if (ev.seq !== expectedSeq) {
        return broken(expectedSeq, at, `line ${lineNo}: expected seq ${expectedSeq}, found ${String(ev.seq)}`);
      }
      if (ev.prevHash !== prevHash) {
        return broken(expectedSeq, at, `line ${lineNo}: prevHash does not match previous event hash`);
      }
      if (typeof ev.hash !== 'string' || ev.hash !== computeEventHash(ev)) {
        return broken(expectedSeq, at, `line ${lineNo}: hash mismatch (event was modified)`);
      }
      prevHash = ev.hash;
      expectedSeq++;
    }
    return { ok: true, count: expectedSeq };
  } catch (err) {
    return { ok: false, count: 0, error: `verification failed: ${errMessage(err)}` };
  }
}

function broken(count: number, brokenAt: number, error: string): VerifyResult {
  return { ok: false, count, brokenAt, error };
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createAuditLogger, verifyAuditLog } from '../../../src/audit/index.js';

let dir: string;
let file: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcpg-verify-'));
  file = join(dir, 'audit.jsonl');
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function writeLog(n: number): string[] {
  const log = createAuditLogger({ file, stderr: false });
  for (let i = 0; i < n; i++) {
    log.log({ sessionId: 's', serverId: 'srv', kind: 'tool_call', toolName: `t${i}`, action: 'allow', data: { i } });
  }
  return readFileSync(file, 'utf8').split('\n').filter((l) => l !== '');
}

function save(lines: string[], trailing = '\n'): void {
  writeFileSync(file, lines.join('\n') + trailing);
}

describe('verifyAuditLog', () => {
  it('accepts an intact chain of N events', () => {
    writeLog(25);
    expect(verifyAuditLog(file)).toEqual({ ok: true, count: 25 });
  });

  it('accepts an empty file, blank lines, CRLF and no trailing newline', () => {
    writeFileSync(file, '');
    expect(verifyAuditLog(file)).toEqual({ ok: true, count: 0 });
    const lines = writeLog(3);
    writeFileSync(file, '\n' + lines.join('\r\n\n  \n'));
    expect(verifyAuditLog(file)).toEqual({ ok: true, count: 3 });
  });

  it('reports a missing file without throwing', () => {
    const r = verifyAuditLog(join(dir, 'nope.jsonl'));
    expect(r.ok).toBe(false);
    expect(r.count).toBe(0);
    expect(r.error).toMatch(/cannot read/);
  });

  it('detects an edited field', () => {
    const lines = writeLog(6);
    const ev = JSON.parse(lines[4]!) as Record<string, unknown>;
    ev.action = 'block';
    lines[4] = JSON.stringify(ev);
    save(lines);
    const r = verifyAuditLog(file);
    expect(r).toMatchObject({ ok: false, brokenAt: 4, count: 4 });
    expect(r.error).toMatch(/hash mismatch/);
  });

  it('detects an edited field even when the hash is recomputed (chain breaks at next line)', async () => {
    const lines = writeLog(5);
    const { computeEventHash } = await import('../../../src/audit/hash.js');
    const ev = JSON.parse(lines[2]!) as Record<string, unknown>;
    ev.toolName = 'forged';
    ev.hash = computeEventHash(ev);
    lines[2] = JSON.stringify(ev);
    save(lines);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 3 });
  });

  it('detects a deleted line', () => {
    const lines = writeLog(6);
    lines.splice(2, 1);
    save(lines);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 3, count: 2 });
  });

  it('detects deletion of the first line', () => {
    const lines = writeLog(3);
    save(lines.slice(1));
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 1, count: 0 });
  });

  it('detects reordered lines', () => {
    const lines = writeLog(6);
    [lines[3], lines[4]] = [lines[4]!, lines[3]!];
    save(lines);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 4, count: 3 });
  });

  it('detects a renumbered seq', () => {
    const lines = writeLog(3);
    const ev = JSON.parse(lines[1]!) as Record<string, unknown>;
    ev.seq = 7;
    lines[1] = JSON.stringify(ev);
    save(lines);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 7, count: 1 });
  });

  it('detects garbage lines', () => {
    const lines = writeLog(3);
    lines.splice(1, 0, '{not json');
    save(lines);
    const r = verifyAuditLog(file);
    expect(r).toMatchObject({ ok: false, brokenAt: 1, count: 1 });
    expect(r.error).toMatch(/invalid JSON/);
    save(['[1,2]']);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 0 });
  });

  it('detects a wrong first prevHash', () => {
    const lines = writeLog(2);
    const ev = JSON.parse(lines[0]!) as Record<string, unknown>;
    ev.prevHash = 'f'.repeat(64);
    lines[0] = JSON.stringify(ev);
    save(lines);
    expect(verifyAuditLog(file)).toMatchObject({ ok: false, brokenAt: 0, error: expect.stringMatching(/prevHash/) });
  });
});

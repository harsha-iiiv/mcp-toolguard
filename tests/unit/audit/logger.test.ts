import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import type { AuditEventInput } from '../../../src/contracts.js';
import { canonicalJson, createAuditLogger, verifyAuditLog } from '../../../src/audit/index.js';

const ZERO = '0'.repeat(64);
const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

const base: AuditEventInput = { sessionId: 's1', serverId: 'srv', kind: 'tool_call', method: 'tools/call' };

let dir: string;
type WriteSpy = MockInstance<typeof process.stdout.write>;
let stdoutSpy: WriteSpy;
let stderrSpy: WriteSpy;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcpg-audit-'));
  stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  // The no-stdout guarantee holds for every test in this file.
  expect(stdoutSpy).not.toHaveBeenCalled();
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

function stderrLines(): string[] {
  return stderrSpy.mock.calls.map((c) => String(c[0]));
}

function readEvents(file: string): Array<Record<string, unknown>> {
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe('createAuditLogger: in memory', () => {
  it('builds chained events with v, seq, ts, prevHash and hash', () => {
    const log = createAuditLogger({ stderr: false });
    const evs = Array.from({ length: 5 }, (_, i) => log.log({ ...base, toolName: `t${i}`, action: 'allow' }));
    expect(log.events()).toEqual(evs);
    evs.forEach((ev, i) => {
      expect(ev.v).toBe(1);
      expect(ev.seq).toBe(i);
      expect(ev.prevHash).toBe(i === 0 ? ZERO : evs[i - 1]!.hash);
      expect(Number.isNaN(Date.parse(ev.ts))).toBe(false);
      const { hash, ...rest } = ev;
      expect(hash).toBe(createHash('sha256').update(canonicalJson(rest)).digest('hex'));
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  it('does not mutate the input', () => {
    const input: AuditEventInput = {
      ...base,
      data: { body: AWS },
      reasons: [`found ${AWS}`],
      findings: [{ ruleId: 'secret-exfiltration', severity: 'critical', message: 'm', evidence: AWS }],
    };
    const snapshot = structuredClone(input);
    createAuditLogger({ stderr: false }).log(input);
    expect(input).toEqual(snapshot);
  });

  it('redacts data, reasons and findings[].evidence by default', () => {
    const log = createAuditLogger({ stderr: false });
    const ev = log.log({
      ...base,
      data: { arguments: { body: `key=${AWS}`, password: 'hunter2' } },
      reasons: [`secret-exfiltration: ${AWS}`],
      findings: [
        { ruleId: 'secret-exfiltration', severity: 'critical', message: 'AWS key', evidence: AWS, location: 'arguments.body' },
      ],
    });
    const text = JSON.stringify(ev);
    expect(text).not.toContain(AWS);
    expect(text).not.toContain('hunter2');
    expect(ev.data).toEqual({ arguments: { body: 'key=[REDACTED:aws-access-key]', password: '[REDACTED:password]' } });
    expect(ev.reasons).toEqual(['secret-exfiltration: [REDACTED:aws-access-key]']);
    expect(ev.findings?.[0]?.evidence).toBe('[REDACTED:aws-access-key]');
    expect(ev.findings?.[0]?.location).toBe('arguments.body');
  });

  it('keeps secrets when redact is false', () => {
    const ev = createAuditLogger({ stderr: false, redact: false }).log({ ...base, data: { body: AWS } });
    expect(ev.data).toEqual({ body: AWS });
  });

  it('clamps evidence to 200 chars', () => {
    const ev = createAuditLogger({ stderr: false }).log({
      ...base,
      findings: [{ ruleId: 'r', severity: 'low', message: 'm', evidence: 'e'.repeat(500) }],
    });
    expect(ev.findings?.[0]?.evidence).toBe('e'.repeat(200));
  });

  it('truncates large data', () => {
    const log = createAuditLogger({ stderr: false });
    const big = { text: 'x'.repeat(5000) };
    const ev = log.log({ ...base, data: big });
    expect(ev.data).toEqual({ truncated: true, preview: canonicalJson(big).slice(0, 2000) });

    const small = createAuditLogger({ stderr: false, maxDataLength: 10 }).log({ ...base, data: { a: 'abcdefghijk' } });
    expect(small.data).toEqual({ truncated: true, preview: '{"a":"abcd' });

    const fits = log.log({ ...base, data: { a: 1 } });
    expect(fits.data).toEqual({ a: 1 });
  });

  it('handles cyclic data without throwing', () => {
    const d: Record<string, unknown> = { a: 1 };
    d.self = d;
    const log = createAuditLogger({ stderr: false });
    expect(log.log({ ...base, data: d }).data).toEqual({ a: 1, self: '[Circular]' });
    const raw = createAuditLogger({ stderr: false, redact: false });
    expect(raw.log({ ...base, data: d }).data).toEqual({ a: 1, self: '[Circular]' });
  });

  it('close() makes later log() calls no-ops', async () => {
    const log = createAuditLogger({ stderr: false });
    log.log(base);
    await log.close();
    log.log(base);
    expect(log.events()).toHaveLength(1);
  });

  it('never throws, even on garbage input', () => {
    const log = createAuditLogger({ stderr: false });
    expect(() => log.log(null as unknown as AuditEventInput)).not.toThrow();
    expect(() => log.log({ ...base, data: { n: 10n, f: () => 1, s: Symbol('x') } })).not.toThrow();
  });
});

describe('createAuditLogger: file', () => {
  it('appends JSONL with mode 0600, creates directories, and verifies', () => {
    const file = join(dir, 'nested', 'deeper', 'audit.jsonl');
    const log = createAuditLogger({ file, stderr: false });
    for (let i = 0; i < 10; i++) log.log({ ...base, toolName: `t${i}` });
    const evs = readEvents(file);
    expect(evs).toHaveLength(10);
    expect(evs.map((e) => e.seq)).toEqual([...Array(10).keys()]);
    expect(log.events()).toEqual([]);
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(verifyAuditLog(file)).toEqual({ ok: true, count: 10 });
  });

  it('resumes seq and prevHash after reopening', async () => {
    const file = join(dir, 'audit.jsonl');
    const first = createAuditLogger({ file, stderr: false });
    first.log(base);
    const last = first.log(base);
    await first.close();

    const second = createAuditLogger({ file, stderr: false });
    const next = second.log(base);
    expect(next.seq).toBe(2);
    expect(next.prevHash).toBe(last.hash);
    second.log(base);
    expect(verifyAuditLog(file)).toEqual({ ok: true, count: 4 });
  });

  it('resumes when the file has trailing blank lines', () => {
    const file = join(dir, 'audit.jsonl');
    const a = createAuditLogger({ file, stderr: false }).log(base);
    writeFileSync(file, readFileSync(file, 'utf8') + '\n\n', { flag: 'w' });
    const b = createAuditLogger({ file, stderr: false }).log(base);
    expect(b.seq).toBe(1);
    expect(b.prevHash).toBe(a.hash);
    expect(verifyAuditLog(file).ok).toBe(true);
  });

  it('expands a leading ~', () => {
    const log = createAuditLogger({ file: '~/x/audit.jsonl', stderr: false });
    expect(log.file).not.toContain('~');
    expect(log.file?.endsWith(join('x', 'audit.jsonl'))).toBe(true);
    // Not writing: we only check the resolved path (avoid touching the real home directory).
  });

  it('falls back to memory with one stderr line when the file cannot be written', () => {
    const blocker = join(dir, 'not-a-dir');
    writeFileSync(blocker, 'x');
    const log = createAuditLogger({ file: join(blocker, 'audit.jsonl') });
    expect(() => {
      log.log(base);
      log.log(base);
    }).not.toThrow();
    expect(log.events()).toHaveLength(2);
    expect(log.events()[1]!.seq).toBe(1);
    const lines = stderrLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^\[mcp-toolguard\] audit: cannot write .*keeping audit events in memory\n$/);
  });
});

describe('stderr summaries', () => {
  const finding = {
    ruleId: 'secret-exfiltration',
    severity: 'critical' as const,
    message: 'AWS access key in arguments.body',
    evidence: AWS,
  };

  it('prints the BLOCK summary format (no colour when not a TTY)', () => {
    const tty = process.stderr.isTTY;
    Object.defineProperty(process.stderr, 'isTTY', { value: false, configurable: true });
    try {
      const log = createAuditLogger({});
      log.log({ ...base, toolName: 'send_email', action: 'block', findings: [finding] });
      expect(stderrLines()).toEqual([
        '[mcp-toolguard] BLOCK tools/call send_email (secret-exfiltration: AWS access key in arguments.body)\n',
      ]);
    } finally {
      Object.defineProperty(process.stderr, 'isTTY', { value: tty, configurable: true });
    }
  });

  it('uses ANSI colour only on a TTY', () => {
    const tty = process.stderr.isTTY;
    Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
    try {
      createAuditLogger({}).log({ ...base, toolName: 'send_email', action: 'block', findings: [finding] });
      expect(stderrLines()[0]).toMatch(/^\u001b\[31m\[mcp-toolguard\] BLOCK tools\/call send_email .*\u001b\[0m\n$/);
    } finally {
      Object.defineProperty(process.stderr, 'isTTY', { value: tty, configurable: true });
    }
  });

  it('summarises warn, would-block, reasons-only and lifecycle errors; skips allow and other lifecycle', () => {
    const tty = process.stderr.isTTY;
    Object.defineProperty(process.stderr, 'isTTY', { value: false, configurable: true });
    try {
      const log = createAuditLogger({});
      log.log({ ...base, toolName: 'a', action: 'allow' });
      log.log({ ...base, kind: 'lifecycle', event: 'start' });
      log.log({
        sessionId: 's',
        serverId: 'srv',
        kind: 'tool_definition',
        method: 'tools/list',
        toolName: 'evil',
        action: 'warn',
        wouldBlock: true,
        findings: [finding, { ruleId: 'tool-poisoning', severity: 'high', message: 'x' }],
      });
      log.log({ ...base, toolName: 'rm', action: 'block', reasons: [`tool "rm" is denied ${AWS}`] });
      log.log({ sessionId: 's', serverId: 'srv', kind: 'lifecycle', event: 'error', data: { message: 'spawn ENOENT\nboom' } });
      expect(stderrLines()).toEqual([
        '[mcp-toolguard] WARN (would block) tools/list evil (secret-exfiltration: AWS access key in arguments.body +1 more)\n',
        '[mcp-toolguard] BLOCK tools/call rm (tool "rm" is denied [REDACTED:aws-access-key])\n',
        '[mcp-toolguard] ERROR error (spawn ENOENT boom)\n',
      ]);
    } finally {
      Object.defineProperty(process.stderr, 'isTTY', { value: tty, configurable: true });
    }
  });

  it('prints nothing when stderr is false', () => {
    createAuditLogger({ stderr: false }).log({ ...base, action: 'block', findings: [finding] });
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it('never writes to stdout, in memory or file mode, for any event type', () => {
    const log = createAuditLogger({ file: join(dir, 'a.jsonl') });
    for (const action of ['allow', 'warn', 'block'] as const) log.log({ ...base, action, findings: [finding] });
    log.log({ sessionId: 's', serverId: 'srv', kind: 'lifecycle', event: 'error', data: 'x' });
    createAuditLogger({}).log({ ...base, action: 'block' });
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});

describe('multiple writers on one file (proxy + approve CLI)', () => {
  it('keeps one valid chain when two loggers interleave (proxy + `approve` CLI)', async () => {
    const d = mkdtempSync(join(tmpdir(), 'mcpg-audit-multi-'));
    try {
      const file = join(d, 'audit.jsonl');
      const proxy = createAuditLogger({ file, stderr: false });
      const cli = createAuditLogger({ file, stderr: false });
      const ev = (n: string): AuditEventInput => ({ sessionId: n, serverId: 's', kind: 'lifecycle', event: n });
      proxy.log(ev('p1'));
      proxy.log(ev('p2'));
      cli.log(ev('approval_granted'));
      proxy.log(ev('p3'));
      cli.log(ev('approval_denied'));
      proxy.log(ev('p4'));
      await proxy.close();
      await cli.close();
      const res = verifyAuditLog(file);
      expect(res).toMatchObject({ ok: true, count: 6 });
      const seqs = readFileSync(file, 'utf8').trim().split('\n').map((l) => (JSON.parse(l) as { seq: number }).seq);
      expect(seqs).toEqual([0, 1, 2, 3, 4, 5]);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});

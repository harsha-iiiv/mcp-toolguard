// CLI surface of the built binary: scan, check-policy, verify-log, and stdout purity in run mode.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { TOOLGUARD_VERSION } from '../../src/contracts.js';
import { CLI, FIXTURES, connectGuarded, makeSandbox, runCli, server, type Sandbox } from './helpers.js';

let sb: Sandbox;
beforeEach(() => {
  sb = makeSandbox();
});
afterEach(() => {
  sb.cleanup();
});

const policyFixture = (name: string) => join(FIXTURES, 'policies', name);

describe('e2e: --version', () => {
  it('prints the version', () => {
    const r = runCli(sb, ['--version']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(TOOLGUARD_VERSION);
  });
});

describe('e2e: scan', () => {
  it('exits 2 for the poisoned server', () => {
    const r = runCli(sb, ['scan', '--pins', sb.pins, '--', process.execPath, server('poisoned-server.mjs')]);
    expect(r.status, r.stderr).toBe(2);
    expect(r.stdout).toContain('add');
  });

  it('exits 0 for the benign server', () => {
    const r = runCli(sb, ['scan', '--pins', sb.pins, '--', process.execPath, server('benign-server.mjs')]);
    expect(r.status, r.stdout + r.stderr).toBe(0);
  });

  it('--json prints a single JSON document', () => {
    const r = runCli(sb, ['scan', '--json', '--pins', sb.pins, '--', process.execPath, server('poisoned-server.mjs')]);
    expect(r.status, r.stderr).toBe(2);
    expect(() => JSON.parse(r.stdout)).not.toThrow();
    expect(r.stdout).toContain('tool-poisoning');
  });

  it('exits 1 when the server command cannot start', () => {
    const r = runCli(sb, ['scan', '--pins', sb.pins, '--', join(sb.dir, 'does-not-exist')]);
    expect(r.status).toBe(1);
  });
});

describe('e2e: check-policy', () => {
  it.each(['valid.yaml', 'minimal.yaml', 'monitor.yaml', 'valid.json'])('accepts %s', (f) => {
    const r = runCli(sb, ['check-policy', policyFixture(f)]);
    expect(r.status, r.stdout + r.stderr).toBe(0);
  });

  it.each(['invalid-mode.yaml', 'invalid-action.yaml', 'invalid-version.yaml', 'invalid-syntax.yaml'])(
    'rejects %s',
    (f) => {
      const r = runCli(sb, ['check-policy', policyFixture(f)]);
      expect(r.status, r.stdout + r.stderr).toBe(1);
    },
  );

  it('rejects a missing file', () => {
    expect(runCli(sb, ['check-policy', join(sb.dir, 'nope.yaml')]).status).toBe(1);
  });
});

describe('e2e: verify-log', () => {
  async function produceLog(): Promise<void> {
    const g = await connectGuarded(sb, server('poisoned-server.mjs'));
    await g.listToolNames();
    await g.call('multiply', { a: 3, b: 4 });
    await g.call('add', { a: 3, b: 4 });
    await g.close();
  }

  it('exits 0 on an untouched log and 1 on a tampered one', async () => {
    await produceLog();
    expect(runCli(sb, ['verify-log', sb.audit]).status).toBe(0);

    const lines = readFileSync(sb.audit, 'utf8').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    const idx = lines.findIndex((l) => (JSON.parse(l) as { action?: string }).action === 'block');
    const target = idx >= 0 ? idx : 1;
    const ev = JSON.parse(lines[target]!) as { action?: string };
    ev.action = ev.action === 'block' ? 'allow' : 'block'; // attacker hides the block
    lines[target] = JSON.stringify(ev);
    writeFileSync(sb.audit, lines.join('\n') + '\n');

    const r = runCli(sb, ['verify-log', sb.audit]);
    expect(r.status).toBe(1);
  });

  it('exits 1 when a line is removed', async () => {
    await produceLog();
    const lines = readFileSync(sb.audit, 'utf8').split('\n').filter(Boolean);
    lines.splice(1, 1);
    writeFileSync(sb.audit, lines.join('\n') + '\n');
    expect(runCli(sb, ['verify-log', sb.audit]).status).toBe(1);
  });
});

describe('e2e: run mode stdout carries only JSON-RPC', () => {
  it('every stdout line is a JSON-RPC 2.0 message', async () => {
    const child = spawn(
      process.execPath,
      [CLI, 'run', '--audit', sb.audit, '--pins', sb.pins, '--', process.execPath, server('poisoned-server.mjs')],
      { cwd: sb.dir, env: sb.env, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => (stdout += c.toString()));
    child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
    const exited = new Promise<number | null>((r) => child.on('exit', (code) => r(code)));

    const send = (m: unknown) => child.stdin.write(JSON.stringify(m) + '\n');
    const responses = () =>
      stdout
        .split('\n')
        .filter((l) => l.trim())
        .map((l) => {
          try {
            return JSON.parse(l) as { id?: unknown };
          } catch {
            return { id: undefined };
          }
        });
    const waitForId = async (id: number) => {
      const start = Date.now();
      while (!responses().some((r) => r.id === id)) {
        if (Date.now() - start > 10_000) throw new Error(`no response for id ${id}; stderr: ${stderr}`);
        await new Promise((r) => setTimeout(r, 20));
      }
    };

    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '0' } },
    });
    await waitForId(1);
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    await waitForId(2);
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'add', arguments: { a: 1, b: 2 } } });
    await waitForId(3);
    send({ jsonrpc: '2.0', id: 4, method: 'ping' });
    await waitForId(4);
    child.stdin.end();
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
    if (child.exitCode === null) child.kill('SIGKILL');

    const lines = stdout.split('\n').filter((l) => l.length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(4);
    for (const line of lines) {
      let msg: Record<string, unknown>;
      expect(() => (msg = JSON.parse(line) as Record<string, unknown>), `non-JSON stdout line: ${line}`).not.toThrow();
      expect(msg!.jsonrpc, line).toBe('2.0');
    }
    const byId = new Map(lines.map((l) => JSON.parse(l) as { id?: number; result?: any }).map((m) => [m.id, m]));
    const tools = (byId.get(2)?.result?.tools ?? []) as Array<{ name: string }>;
    expect(tools.map((t) => t.name)).toEqual(['multiply']);
    expect(byId.get(3)?.result?.isError).toBe(true);
    expect(String(byId.get(3)?.result?.content?.[0]?.text)).toMatch(/^\[mcp-toolguard\] BLOCKED: /);
  });
});

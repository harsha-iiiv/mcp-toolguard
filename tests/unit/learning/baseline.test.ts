import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { ToolCall, Verdict } from '../../../src/contracts.js';
import { defaultPolicy } from '../../../src/policy/index.js';
import {
  BASELINE_LIMITS,
  classifyString,
  createBaselinePlugin,
  generateDay,
  generateDays,
  injectOutliers,
  shapeOf,
  type BaselinePlugin,
  type SyntheticCall,
} from '../../../src/learning/index.js';

const policy = defaultPolicy();
const DAY = new Date(2026, 10, 3, 12); // 2026-11-03 local

/** Feed calls through the plugin with a controllable clock; return non-null verdicts. */
function feed(plugin: BaselinePlugin, clock: { t: Date }, calls: SyntheticCall[]): { call: SyntheticCall; v: Verdict }[] {
  const out: { call: SyntheticCall; v: Verdict }[] = [];
  for (const c of calls) {
    clock.t = c.at;
    const v = plugin.check(c.call, undefined, policy);
    if (v) out.push({ call: c, v });
  }
  return out;
}

function setup(opts: { minSamples?: number; file?: string } = {}) {
  const clock = { t: DAY };
  const plugin = createBaselinePlugin({ minSamples: opts.minSamples ?? 50, file: opts.file, now: () => clock.t, flushDelayMs: 0 });
  return { clock, plugin };
}

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'toolguard-learning-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('shapes', () => {
  it('classifies common argument values without keeping them', () => {
    expect(classifyString('/home/alice/projects/webapp/src/index.ts')).toBe('path');
    expect(classifyString('src/index.ts')).toBe('path');
    expect(classifyString('README.md')).toBe('path');
    expect(classifyString('https://example.com/a?b=c')).toBe('url');
    expect(classifyString('alice@example.com')).toBe('email');
    expect(classifyString('42')).toBe('number');
    expect(classifyString('QUtJQVlFWEFNUExFS0VZMTIzNDU2Nzg5MGFiY2RlZg==')).toBe('base64');
    expect(classifyString('deadbeefdeadbeefdeadbeef')).toBe('hex');
    expect(classifyString('hello there world')).toBe('text');
    expect(classifyString('a\nb')).toBe('multiline');
    expect(classifyString('main')).toBe('word');
    expect(classifyString('hi​there')).toBe('control');
    expect(shapeOf('/etc/hosts')).toBe('path:9-32');
    expect(shapeOf(3)).toBe('number');
    expect(shapeOf([1])).toBe('array');
    expect(shapeOf(null)).toBe('null');
  });
});

describe('baseline learning plugin', () => {
  it('has id learning and returns null on results', () => {
    const { plugin } = setup();
    expect(plugin.id).toBe('learning');
    const call: ToolCall = { kind: 'tool_call', requestId: 1, toolName: 'read_file', arguments: { path: '/x' }, serverId: 's', taskId: 't' };
    expect(plugin.check(call, { kind: 'tool_result', requestId: 1, toolName: 'read_file', result: { content: [] } }, policy)).toBeNull();
    expect(plugin.snapshot().servers).toEqual({}); // results are not recorded
  });

  it('only records below minSamples: even outliers produce no warnings', () => {
    const { clock, plugin } = setup({ minSamples: 50 });
    const day = generateDay({ date: DAY, calls: 40, seed: 7 });
    // 40 calls split over 3 tools: every tool is below 50
    expect(feed(plugin, clock, day)).toEqual([]);
    const outliers = injectOutliers(DAY);
    expect(feed(plugin, clock, outliers)).toEqual([]);
    const snap = plugin.snapshot();
    const total = Object.values(snap.servers['filesystem']!.tools).reduce(
      (s, t) => s + Object.values(t.days).reduce((a, b) => a + b.count, 0),
      0,
    );
    expect(total).toBe(40 + outliers.length);
  });

  it('a normal day after a week of training produces few or no warnings', () => {
    const { clock, plugin } = setup({ minSamples: 50 });
    const training = generateDays(new Date(2026, 10, 2, 12), 6, 120, 3);
    feed(plugin, clock, training);
    const today = generateDay({ date: DAY, calls: 120, seed: 999 });
    const warns = feed(plugin, clock, today);
    expect(warns.length / today.length).toBeLessThanOrEqual(0.02);
  });

  it('injected outliers warn, with the documented reason format', () => {
    const { clock, plugin } = setup({ minSamples: 50 });
    feed(plugin, clock, generateDays(new Date(2026, 10, 2, 12), 6, 120, 3));
    for (const o of injectOutliers(DAY)) {
      clock.t = o.at;
      const v = plugin.check(o.call, undefined, policy);
      expect(v, o.label).not.toBeNull();
      expect(v!.action).toBe('warn');
      expect(v!.ruleId).toBe('learning');
      expect(v!.severity).toBe('medium');
      expect(v!.reason).toMatch(new RegExp(`^unusual .+ for ${o.call.toolName} \\(score (0\\.[7-9]\\d|1\\.00)\\)$`));
    }
  });

  it('never blocks or requires approval, whatever the traffic', () => {
    const { clock, plugin } = setup({ minSamples: 5 });
    const calls = [
      ...generateDays(new Date(2026, 10, 2, 12), 3, 60, 11),
      ...injectOutliers(DAY),
      ...injectOutliers(new Date(2026, 10, 4, 12), 'other-server'),
    ];
    // Hostile shapes too: odd types, huge keys, many keys.
    const weird: SyntheticCall[] = [];
    for (let i = 0; i < 200; i++) {
      const args: Record<string, unknown> = { [`k${i}`.repeat(50)]: i % 2 ? [i] : { a: i }, path: 'x'.repeat(i * 20) };
      weird.push({ at: new Date(2026, 10, 3, i % 24), call: { kind: 'tool_call', requestId: i, toolName: `t${i % 300}`, arguments: args, serverId: 'filesystem', taskId: 't' } });
    }
    const verdicts = feed(plugin, clock, [...calls, ...weird]);
    expect(verdicts.length).toBeGreaterThan(0);
    for (const { v } of verdicts) expect(v.action).toBe('warn');
  });

  it('flags a rare hour and a never-seen tool explicitly', () => {
    const { clock, plugin } = setup({ minSamples: 50 });
    feed(plugin, clock, generateDays(new Date(2026, 10, 2, 12), 6, 120, 3));
    const [newTool, , , , rareHour] = injectOutliers(DAY);
    clock.t = newTool!.at;
    expect(plugin.check(newTool!.call, undefined, policy)!.reason).toContain('unusual tool (first call on server filesystem) for execute_command');
    clock.t = rareHour!.at;
    expect(plugin.check(rareHour!.call, undefined, policy)!.reason).toContain('hour 03:00');
  });

  it('persists to a 0600 JSON file and round-trips', () => {
    const file = join(tmp(), 'nested', 'baseline.json');
    const a = setup({ file });
    feed(a.plugin, a.clock, generateDays(new Date(2026, 10, 2, 12), 6, 120, 3));
    a.plugin.flush();
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const b = setup({ file });
    expect(b.plugin.snapshot()).toEqual(a.plugin.snapshot());
    // The reloaded baseline is already trained: an outlier warns straight away.
    const o = injectOutliers(DAY)[2]!;
    b.clock.t = o.at;
    expect(b.plugin.check(o.call, undefined, policy)?.action).toBe('warn');
  });

  it('saves every flushEvery calls without an explicit flush', () => {
    const file = join(tmp(), 'b.json');
    const clock = { t: DAY };
    const plugin = createBaselinePlugin({ minSamples: 50, file, now: () => clock.t, flushEvery: 10, flushDelayMs: 0 });
    feed(plugin, clock, generateDay({ date: DAY, calls: 10, seed: 1 }));
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    expect(saved.version).toBe(1);
  });

  it('never stores raw argument values', () => {
    const file = join(tmp(), 'b.json');
    const { clock, plugin } = setup({ file });
    const secret = 'AKIAIOSFODNN7EXAMPLE-very-secret-value';
    plugin.check({ kind: 'tool_call', requestId: 1, toolName: 'write_file', arguments: { path: '/home/alice/secret-plans.txt', content: secret }, serverId: 'fs', taskId: 't' }, undefined, policy);
    void clock;
    plugin.flush();
    const raw = readFileSync(file, 'utf8');
    expect(raw).not.toContain('secret-plans');
    expect(raw).not.toContain('AKIA');
    expect(raw).toContain('"path"');
    expect(raw).toContain('content');
  });

  it('expands ~ in the file path', () => {
    const home = tmp();
    const prev = process.env['HOME'];
    process.env['HOME'] = home;
    try {
      const { plugin } = setup({ file: '~/.mcp-toolguard/baseline.json' });
      plugin.check({ kind: 'tool_call', requestId: 1, toolName: 'x', arguments: {}, serverId: 's', taskId: 't' }, undefined, policy);
      plugin.flush();
      expect(statSync(join(home, '.mcp-toolguard', 'baseline.json')).isFile()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env['HOME'];
      else process.env['HOME'] = prev;
    }
  });

  it('ignores a corrupt baseline file instead of throwing', () => {
    const file = join(tmp(), 'b.json');
    writeFileSync(file, '{not json');
    const { plugin } = setup({ file });
    expect(plugin.snapshot().servers).toEqual({});
  });

  it('keeps a 7-day rolling window and drops older days', () => {
    const { clock, plugin } = setup({ minSamples: 50 });
    const oldDay = new Date(2026, 10, 1, 12);
    feed(plugin, clock, generateDay({ date: oldDay, calls: 300, seed: 5 }));
    expect(Object.keys(plugin.snapshot().servers['filesystem']!.tools['read_file']!.days)).toEqual(['2026-11-01']);

    clock.t = new Date(2026, 10, 7, 12); // day 7 of the window that started 11-01: still kept
    expect(plugin.snapshot().servers['filesystem']).toBeDefined();

    clock.t = new Date(2026, 10, 8, 12); // 11-01 is now 8 days ago: dropped
    expect(plugin.snapshot().servers).toEqual({});

    // With the old data gone the tool is back under minSamples: an outlier only records.
    const o = injectOutliers(new Date(2026, 10, 8, 12))[2]!;
    clock.t = o.at;
    expect(plugin.check(o.call, undefined, policy)).toBeNull();
  });

  it('bounds stored key sets per tool', () => {
    const { clock, plugin } = setup({ minSamples: 1000 });
    const calls: SyntheticCall[] = [];
    for (let i = 0; i < 500; i++) {
      calls.push({ at: DAY, call: { kind: 'tool_call', requestId: i, toolName: 'x', arguments: { [`key_${i}`]: 'v' }, serverId: 's', taskId: 't' } });
    }
    feed(plugin, clock, calls);
    const bucket = plugin.snapshot().servers['s']!.tools['x']!.days['2026-11-03']!;
    expect(Object.keys(bucket.keySets).length).toBeLessThanOrEqual(BASELINE_LIMITS.keySetsPerTool);
    expect(Object.keys(bucket.shapes).length).toBeLessThanOrEqual(BASELINE_LIMITS.keysPerTool);
    expect(bucket.count).toBe(500);
  });
});

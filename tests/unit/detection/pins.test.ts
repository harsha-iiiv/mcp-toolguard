import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ToolPin } from '../../../src/contracts.js';
import { createPinStore } from '../../../src/detection/index.js';

const pin = (serverId: string, toolName: string, hash = 'a'.repeat(64)): ToolPin => ({
  serverId,
  toolName,
  hash,
  description: `desc of ${toolName}`,
  firstSeen: '2026-01-01T00:00:00.000Z',
});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'toolguard-pins-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('in-memory pin store', () => {
  it('gets, sets, lists, resets', () => {
    const s = createPinStore();
    expect(s.get('a', 'x')).toBeUndefined();
    s.set(pin('a', 'x'));
    s.set(pin('a', 'y'));
    s.set(pin('b', 'x'));
    s.set({ ...pin('a', 'x'), hash: 'b'.repeat(64) }); // overwrite
    expect(s.get('a', 'x')!.hash).toBe('b'.repeat(64));
    expect(s.list()).toHaveLength(3);
    expect(s.list('a').map((p) => p.toolName).sort()).toEqual(['x', 'y']);
    expect(s.reset('a', 'y')).toBe(1);
    expect(s.reset('a', 'nope')).toBe(0);
    expect(s.reset('b')).toBe(1);
    expect(s.list()).toEqual([pin('a', 'x', 'b'.repeat(64))]);
  });

  it('returns copies, so callers cannot mutate stored pins', () => {
    const s = createPinStore();
    s.set(pin('a', 'x'));
    s.get('a', 'x')!.hash = 'mutated';
    expect(s.get('a', 'x')!.hash).toBe('a'.repeat(64));
  });

  it('does not confuse server/tool pairs that concatenate the same way', () => {
    const s = createPinStore();
    s.set(pin('ab', 'c'));
    expect(s.get('a', 'bc')).toBeUndefined();
  });
});

describe('file-backed pin store', () => {
  it('persists across instances in {version:1, pins} format with mode 0600, creating parent dirs', () => {
    const file = join(dir, 'nested', 'deeper', 'pins.json');
    const s1 = createPinStore(file);
    s1.set(pin('srv', 'read_file'));
    s1.set(pin('srv', 'write_file'));

    const raw = JSON.parse(readFileSync(file, 'utf8'));
    expect(raw.version).toBe(1);
    expect(raw.pins).toHaveLength(2);
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(join(dir, 'nested', 'deeper'))).toEqual(['pins.json']); // no tmp files left behind

    const s2 = createPinStore(file);
    expect(s2.get('srv', 'read_file')).toEqual(pin('srv', 'read_file'));
    expect(s2.reset('srv')).toBe(2);
    expect(createPinStore(file).list()).toEqual([]);
  });

  it('loads lazily: creating a store touches nothing on disk', () => {
    const file = join(dir, 'lazy', 'pins.json');
    const s = createPinStore(file);
    expect(readdirSync(dir)).toEqual([]);
    expect(s.list()).toEqual([]);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('expands a leading ~ to the home directory', () => {
    const prev = process.env['HOME'];
    process.env['HOME'] = dir;
    try {
      createPinStore('~/.mcp-toolguard/pins.json').set(pin('s', 't'));
      expect(JSON.parse(readFileSync(join(dir, '.mcp-toolguard', 'pins.json'), 'utf8')).pins[0].toolName).toBe('t');
    } finally {
      if (prev === undefined) delete process.env['HOME'];
      else process.env['HOME'] = prev;
    }
  });

  it.each([
    ['not json', '{oops'],
    ['wrong version', JSON.stringify({ version: 2, pins: [] })],
    ['pins not array', JSON.stringify({ version: 1, pins: {} })],
    ['invalid pin', JSON.stringify({ version: 1, pins: [{ serverId: 's' }] })],
  ])('throws a clear error for a corrupt file (%s)', (_label, body) => {
    const file = join(dir, 'pins.json');
    writeFileSync(file, body);
    const s = createPinStore(file);
    expect(() => s.list()).toThrow(/Pin file .*pins\.json is corrupt/);
  });
});

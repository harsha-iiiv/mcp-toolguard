import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PolicyError, loadPolicy } from '../../../src/policy/index.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpg-policy-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(name: string, text: string): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, text);
  return p;
}

function catchErr(fn: () => unknown): PolicyError {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(PolicyError);
    return err as PolicyError;
  }
  throw new Error('expected PolicyError');
}

describe('loadPolicy with explicit file', () => {
  it('loads YAML (.yaml and .yml)', () => {
    for (const name of ['p.yaml', 'p.yml']) {
      const file = write(name, 'mode: monitor\ntools:\n  deny: ["rm_*"]\n');
      const { policy, source } = loadPolicy(file);
      expect(source).toBe(file);
      expect(policy.mode).toBe('monitor');
      expect(policy.tools.deny).toEqual(['rm_*']);
      expect(policy.tools.unlisted).toBe('block');
    }
  });

  it('loads JSON', () => {
    const file = write('p.json', JSON.stringify({ tools: { allow: ['read_*'] } }));
    const { policy, source } = loadPolicy(file);
    expect(source).toBe(file);
    expect(policy.tools.allow).toEqual(['read_*']);
  });

  it('tries JSON then YAML for other extensions', () => {
    expect(loadPolicy(write('p.conf', '{"mode":"monitor"}')).policy.mode).toBe('monitor');
    expect(loadPolicy(write('p.txt', 'mode: monitor\n')).policy.mode).toBe('monitor');
    expect(loadPolicy(write('noext', 'mode: monitor\n')).policy.mode).toBe('monitor');
  });

  it('resolves relative paths against cwd and returns an absolute source', () => {
    write('rel.yaml', 'mode: monitor\n');
    const { policy, source } = loadPolicy('rel.yaml', dir);
    expect(source).toBe(path.join(dir, 'rel.yaml'));
    expect(path.isAbsolute(source)).toBe(true);
    expect(policy.mode).toBe('monitor');
  });

  it('empty YAML file gives defaults', () => {
    expect(loadPolicy(write('empty.yaml', '')).policy.mode).toBe('enforce');
  });

  it('missing explicit file throws PolicyError', () => {
    const err = catchErr(() => loadPolicy(path.join(dir, 'nope.yaml')));
    expect(err.message).toMatch(/not found/);
  });

  it('YAML parse errors include the location', () => {
    const file = write('bad.yaml', 'mode: monitor\ntools:\n  deny: [unclosed\n');
    const err = catchErr(() => loadPolicy(file));
    expect(err.message).toMatch(/YAML/);
    expect(err.issues.join('\n')).toMatch(/line \d+, column \d+/);
  });

  it('JSON parse errors throw PolicyError', () => {
    const file = write('bad.json', '{"mode": ');
    const err = catchErr(() => loadPolicy(file));
    expect(err.message).toMatch(/JSON/);
    expect(err.issues.length).toBe(1);
  });

  it('duplicate YAML keys are a parse error', () => {
    const err = catchErr(() => loadPolicy(write('dup.yaml', 'mode: monitor\nmode: enforce\n')));
    expect(err.issues.length).toBeGreaterThan(0);
  });

  it('validation errors carry the issues and the file path', () => {
    const file = write('invalid.yaml', 'version: 2\ntools:\n  deny: [1]\n');
    const err = catchErr(() => loadPolicy(file));
    expect(err.message).toContain(file);
    expect(err.issues).toEqual(['version: expected 1, got 2', 'tools.deny[0]: expected string, got number']);
  });
});

describe('loadPolicy cwd lookup', () => {
  it('falls back to builtin', () => {
    const { policy, source } = loadPolicy(undefined, dir);
    expect(source).toBe('builtin');
    expect(policy.mode).toBe('enforce');
    expect(path.isAbsolute(policy.pins.file)).toBe(true);
  });

  it('finds toolguard.json', () => {
    write('toolguard.json', '{"mode":"monitor"}');
    expect(loadPolicy(undefined, dir)).toMatchObject({ source: path.join(dir, 'toolguard.json') });
  });

  it('prefers toolguard.yml over toolguard.json', () => {
    write('toolguard.json', '{"mode":"enforce"}');
    write('toolguard.yml', 'mode: monitor\n');
    const { policy, source } = loadPolicy(undefined, dir);
    expect(source).toBe(path.join(dir, 'toolguard.yml'));
    expect(policy.mode).toBe('monitor');
  });

  it('prefers toolguard.yaml over toolguard.yml', () => {
    write('toolguard.yml', 'mode: enforce\n');
    write('toolguard.yaml', 'mode: monitor\n');
    expect(loadPolicy(undefined, dir).source).toBe(path.join(dir, 'toolguard.yaml'));
  });

  it('an invalid discovered file still throws', () => {
    write('toolguard.yaml', 'nonsense: true\n');
    expect(() => loadPolicy(undefined, dir)).toThrow(PolicyError);
  });
});

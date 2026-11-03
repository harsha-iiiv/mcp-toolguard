import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli } from '../../../src/cli/run-cli.js';
import { POLICY_TEMPLATE } from '../../../src/cli/template.js';
import { makeIo } from './helpers.js';

const ROOT = path.resolve(import.meta.dirname, '../../..');

describe('mcp-toolguard init', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpg-init-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('embedded template is identical to toolguard.example.yaml', () => {
    expect(POLICY_TEMPLATE).toBe(fs.readFileSync(path.join(ROOT, 'toolguard.example.yaml'), 'utf8'));
  });

  it('writes toolguard.yaml in cwd', async () => {
    const io = makeIo(dir);
    expect(await runCli(['init'], io)).toBe(0);
    expect(fs.readFileSync(path.join(dir, 'toolguard.yaml'), 'utf8')).toBe(POLICY_TEMPLATE);
    expect(io.out()).toContain('toolguard.yaml');
  });

  it('refuses to overwrite without --force', async () => {
    fs.writeFileSync(path.join(dir, 'toolguard.yaml'), 'mine: true\n');
    const io = makeIo(dir);
    expect(await runCli(['init'], io)).toBe(1);
    expect(io.err()).toMatch(/already exists.*--force/);
    expect(fs.readFileSync(path.join(dir, 'toolguard.yaml'), 'utf8')).toBe('mine: true\n');
  });

  it('overwrites with --force', async () => {
    fs.writeFileSync(path.join(dir, 'toolguard.yaml'), 'mine: true\n');
    expect(await runCli(['init', '--force'], makeIo(dir))).toBe(0);
    expect(fs.readFileSync(path.join(dir, 'toolguard.yaml'), 'utf8')).toBe(POLICY_TEMPLATE);
  });

  it('rejects stray arguments', async () => {
    const io = makeIo(dir);
    expect(await runCli(['init', 'foo'], io)).toBe(1);
    expect(io.err()).toContain('Usage: mcp-toolguard init');
    expect(fs.existsSync(path.join(dir, 'toolguard.yaml'))).toBe(false);
  });
});

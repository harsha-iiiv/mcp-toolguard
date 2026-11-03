// Guards the published package shape: a duplicated or invalid bin entry made npm drop the CLI at publish time.
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const raw = fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8');
const pkg = JSON.parse(raw) as { name: string; bin: Record<string, string>; files: string[] };

describe('package.json', () => {
  it('has exactly one bin entry, mcp-toolguard, pointing at the built CLI', () => {
    expect(pkg.name).toBe('mcp-toolguard-cli');
    expect(pkg.bin).toEqual({ 'mcp-toolguard': 'dist/cli/main.js' });
    // JSON.parse silently keeps the last of duplicate keys, so check the raw text too.
    const binBlock = /"bin":\s*\{([^}]*)\}/.exec(raw)?.[1] ?? '';
    expect(binBlock.match(/"mcp-toolguard"\s*:/g)).toHaveLength(1);
  });

  it('bin target exists after build and has a node shebang', () => {
    const main = fs.readFileSync(path.join(ROOT, pkg.bin['mcp-toolguard']!), 'utf8');
    expect(main.startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('ships the example policy it documents', () => {
    expect(pkg.files).toContain('toolguard.example.yaml');
    expect(fs.existsSync(path.join(ROOT, 'toolguard.example.yaml'))).toBe(true);
  });
});

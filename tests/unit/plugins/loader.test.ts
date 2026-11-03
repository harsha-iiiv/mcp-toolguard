// Plugin loader unit tests.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { Policy, ToolCall } from '../../../src/contracts.js';
import { defaultPolicy } from '../../../src/policy/index.js';
import { PluginError, definePlugin, loadPlugin, loadPlugins } from '../../../src/plugins/index.js';

const root = mkdtempSync(join(tmpdir(), 'mcpg-plugins-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let n = 0;
/** Write a module into a fresh directory (unique path so the ESM cache never interferes). */
function writeModule(source: string, name = 'plugin.mjs', dir?: string): string {
  const d = dir ?? join(root, `m${n++}`);
  mkdirSync(d, { recursive: true });
  const file = join(d, name);
  writeFileSync(file, source);
  return file;
}

const call: ToolCall = { kind: 'tool_call', requestId: 1, toolName: 't', arguments: {}, serverId: 's', taskId: 'x' };
const policy: Policy = defaultPolicy();

describe('loadPlugin', () => {
  it('loads a default export', async () => {
    const f = writeModule(`export default { id: 'a', check: () => ({ action: 'warn', reason: 'r', ruleId: 'a' }) };`);
    const p = await loadPlugin(f);
    expect(p.id).toBe('a');
    expect(p.check(call, undefined, policy)).toEqual({ action: 'warn', reason: 'r', ruleId: 'a' });
  });

  it('loads a named `plugin` export', async () => {
    const f = writeModule(`export const plugin = { id: 'b.c_d-1', check: () => null };`);
    const p = await loadPlugin(f);
    expect(p.id).toBe('b.c_d-1');
    expect(p.check(call, undefined, policy)).toBeNull();
  });

  it('accepts a module object or a plugin object', async () => {
    expect((await loadPlugin({ default: { id: 'x', check: () => null } })).id).toBe('x');
    expect((await loadPlugin({ plugin: { id: 'y', check: () => null } })).id).toBe('y');
    expect((await loadPlugin({ id: 'z', check: () => null })).id).toBe('z');
  });

  it.each([
    ['empty id', `export default { id: '', check() { return null; } };`, /non-empty string 'id'/],
    ['missing id', `export default { check() { return null; } };`, /non-empty string 'id'/],
    ['uppercase id', `export default { id: 'Bad', check() { return null; } };`, /plugin id 'Bad'.*invalid/],
    ['id with space', `export default { id: 'a b', check() { return null; } };`, /invalid/],
    ['leading dash', `export default { id: '-a', check() { return null; } };`, /invalid/],
  ])('rejects an invalid id (%s)', async (_name, src, msg) => {
    const f = writeModule(src);
    await expect(loadPlugin(f)).rejects.toThrow(PluginError);
    await expect(loadPlugin(f)).rejects.toThrow(msg);
  });

  it('rejects a plugin without check()', async () => {
    const f = writeModule(`export default { id: 'nocheck' };`);
    await expect(loadPlugin(f)).rejects.toThrow(/'nocheck'.*must have a 'check/);
    const g = writeModule(`export default { id: 'notfn', check: 42 };`);
    await expect(loadPlugin(g)).rejects.toThrow(/must have a 'check/);
  });

  it('rejects a module with neither default nor plugin export', async () => {
    const f = writeModule(`export const other = 1;`);
    await expect(loadPlugin(f)).rejects.toThrow(/no default export and no named 'plugin' export/);
  });

  it('reports import failures with the file path', async () => {
    const f = writeModule(`throw new Error('kaboom');`);
    await expect(loadPlugin(f)).rejects.toThrow(/failed to load plugin .*plugin\.mjs: kaboom/);
    await expect(loadPlugin(join(root, 'does-not-exist.mjs'))).rejects.toThrow(PluginError);
  });

  it('malformed verdicts throw (so the proxy fails closed); missing ruleId defaults to the plugin id', async () => {
    const asyncP = await loadPlugin({ id: 'async', check: (() => Promise.resolve(null)) as never });
    expect(() => asyncP.check(call, undefined, policy)).toThrow(/Promise/);
    const badAction = await loadPlugin({ id: 'bad', check: (() => ({ action: 'deny', reason: 'r', ruleId: 'bad' })) as never });
    expect(() => badAction.check(call, undefined, policy)).toThrow(/unknown action 'deny'/);
    const noReason = await loadPlugin({ id: 'nr', check: (() => ({ action: 'block', ruleId: 'nr' })) as never });
    expect(() => noReason.check(call, undefined, policy)).toThrow(/reason/);
    const noRule = await loadPlugin({ id: 'nrule', check: (() => ({ action: 'block', reason: 'x' })) as never });
    expect(noRule.check(call, undefined, policy)).toEqual({ action: 'block', reason: 'x', ruleId: 'nrule' });
  });

  it('keeps `this` bound to the original plugin object', async () => {
    const p = await loadPlugin({
      id: 'stateful',
      count: 0,
      check(this: { count: number }) {
        this.count++;
        return { action: 'warn', reason: `n=${this.count}`, ruleId: 'stateful' };
      },
    });
    p.check(call, undefined, policy);
    expect(p.check(call, undefined, policy)?.reason).toBe('n=2');
  });
});

describe('loadPlugins', () => {
  it('returns [] when the directory does not exist', async () => {
    expect(await loadPlugins(join(root, 'nope'))).toEqual([]);
    expect(await loadPlugins('nope', { cwd: root })).toEqual([]);
  });

  it('loads *.js and *.mjs, non-recursively, sorted by file name', async () => {
    const dir = join(root, 'dir-ok');
    writeModule(`export default { id: 'zeta', check: () => null };`, 'b.mjs', dir);
    writeModule(`export const plugin = { id: 'alpha', check: () => null };`, 'c.mjs', dir);
    writeModule(`export default { id: 'mid', check: () => null };`, 'a.mjs', dir);
    writeModule(`throw new Error('must not be loaded');`, 'ignored.ts', dir);
    writeModule(`throw new Error('must not be loaded');`, 'ignored.cjs', dir);
    writeModule(`throw new Error('must not be loaded');`, '.hidden.mjs', dir);
    writeModule(`throw new Error('must not be loaded');`, 'deep.mjs', join(dir, 'sub'));
    const plugins = await loadPlugins('dir-ok', { cwd: root });
    expect(plugins.map((p) => p.id)).toEqual(['mid', 'zeta', 'alpha']);
  });

  it('loads .js files as ESM when a package.json says type: module', async () => {
    const dir = join(root, 'dir-js');
    writeModule(`{"type":"module"}`, 'package.json', dir);
    writeModule(`export default { id: 'js-plugin', check: () => null };`, 'p.js', dir);
    expect((await loadPlugins(dir)).map((p) => p.id)).toEqual(['js-plugin']);
  });

  it('rejects duplicate ids', async () => {
    const dir = join(root, 'dir-dup');
    writeModule(`export default { id: 'same', check: () => null };`, 'one.mjs', dir);
    writeModule(`export default { id: 'same', check: () => null };`, 'two.mjs', dir);
    await expect(loadPlugins(dir)).rejects.toThrow(/duplicate plugin id 'same'/);
  });

  it('rejects a path that is a file, not a directory', async () => {
    const f = writeModule(`export default {};`);
    await expect(loadPlugins(f)).rejects.toThrow(/not a directory/);
  });

  it('propagates an invalid plugin in the directory', async () => {
    const dir = join(root, 'dir-bad');
    writeModule(`export default { id: 'ok', check: () => null };`, 'a.mjs', dir);
    writeModule(`export default { id: 'BAD', check: () => null };`, 'b.mjs', dir);
    await expect(loadPlugins(dir)).rejects.toThrow(/plugin id 'BAD'/);
  });
});

describe('definePlugin', () => {
  it('returns the same object when valid', () => {
    const p = { id: 'ok', check: () => null };
    expect(definePlugin(p)).toBe(p);
  });
  it('throws PluginError when invalid', () => {
    expect(() => definePlugin({ id: 'No', check: () => null })).toThrow(PluginError);
    expect(() => definePlugin({ id: 'ok' } as never)).toThrow(/check/);
  });
});

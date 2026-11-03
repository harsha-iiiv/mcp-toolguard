// Plugin loader.
//
// SECURITY: plugins are ordinary JavaScript modules. Loading one runs its code IN THIS PROCESS with the full
// permissions of the user running mcp-toolguard (file system, network, environment variables, child processes).
// There is no sandbox. Only load plugins you wrote or have reviewed. Loading is opt-in: nothing here is called
// unless policy.plugins.enabled is true or `mcp-toolguard run --plugins <dir>` is used.
//
// The loader never writes to stdout (stdout is the MCP channel during `run`).
import { readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { VERDICT_ORDER, type RulePlugin, type Verdict } from '../contracts.js';
import { PluginError, assertRulePlugin } from './types.js';

const PLUGIN_EXTENSIONS = ['.js', '.mjs'];

function looksLikePlugin(v: unknown): boolean {
  return v !== null && typeof v === 'object' && 'check' in v;
}

/** Pick the plugin out of an imported module namespace (or accept a plain plugin object). */
function pickPlugin(mod: unknown, source: string): unknown {
  if (mod === null || typeof mod !== 'object') {
    throw new PluginError(`plugin module ${source} is not an object`);
  }
  const m = mod as { default?: unknown; plugin?: unknown };
  if (m.default !== undefined && looksLikePlugin(m.default)) return m.default;
  if (m.plugin !== undefined) return m.plugin;
  if (m.default !== undefined) return m.default;
  if (looksLikePlugin(mod)) return mod;
  throw new PluginError(`plugin module ${source} has no default export and no named 'plugin' export`);
}

/**
 * Wrap a validated plugin so that a malformed return value (a Promise, a verdict with an unknown action, a
 * missing reason) throws. The proxy treats a throwing plugin as block ('internal error'), so a broken plugin
 * fails closed instead of silently allowing. A missing ruleId defaults to the plugin id.
 */
function guard(plugin: RulePlugin): RulePlugin {
  const { id } = plugin;
  return {
    id,
    check(call, result, policy) {
      const v: unknown = plugin.check.call(plugin, call, result, policy);
      if (v === null || v === undefined) return null;
      if (typeof v !== 'object') throw new PluginError(`plugin '${id}' returned ${typeof v}, expected Verdict | null`);
      if (typeof (v as { then?: unknown }).then === 'function') {
        throw new PluginError(`plugin '${id}' returned a Promise; check() must be synchronous`);
      }
      const verdict = v as Partial<Verdict>;
      if (!VERDICT_ORDER.includes(verdict.action as Verdict['action'])) {
        throw new PluginError(`plugin '${id}' returned unknown action '${String(verdict.action)}'`);
      }
      if (typeof verdict.reason !== 'string') {
        throw new PluginError(`plugin '${id}' returned a verdict without a string 'reason'`);
      }
      const ruleId = typeof verdict.ruleId === 'string' && verdict.ruleId ? verdict.ruleId : id;
      return { ...(verdict as Verdict), ruleId };
    },
  };
}

/**
 * Load one plugin.
 *  - string: a path to a .js/.mjs file (relative paths resolve against process.cwd()), imported with a
 *    dynamic import(). The module's default export is used, or else its named `plugin` export.
 *  - object: an already-imported module namespace (same default/`plugin` rule) or a plugin object itself.
 * Validates `id` (non-empty, /^[a-z0-9][a-z0-9._-]*$/) and `check` (a function). Throws PluginError.
 *
 * SECURITY: importing a plugin executes it in-process with your full user permissions.
 */
export async function loadPlugin(fileOrModule: string | object): Promise<RulePlugin> {
  let mod: unknown;
  let source: string;
  if (typeof fileOrModule === 'string') {
    if (fileOrModule.length === 0) throw new PluginError('plugin path is empty');
    const file = resolve(fileOrModule);
    source = file;
    try {
      mod = await import(pathToFileURL(file).href);
    } catch (err) {
      throw new PluginError(`failed to load plugin ${file}: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else if (fileOrModule !== null && typeof fileOrModule === 'object') {
    mod = fileOrModule;
    source = '<module object>';
  } else {
    throw new PluginError(`loadPlugin expects a file path or a module object, got ${fileOrModule === null ? 'null' : typeof fileOrModule}`);
  }
  const plugin = pickPlugin(mod, source);
  assertRulePlugin(plugin, source);
  return guard(plugin);
}

export interface LoadPluginsOptions {
  /** Base directory for a relative `dir`. Default process.cwd(). */
  cwd?: string;
}

/**
 * Load every *.js and *.mjs file directly inside `dir` (non-recursive; hidden files skipped), in file-name
 * order. Returns [] when `dir` does not exist. Throws PluginError if `dir` is not a directory, a file fails to
 * load or validate, or two plugins share an id.
 *
 * SECURITY: every file in the directory is executed in-process with your full user permissions.
 */
export async function loadPlugins(dir: string, opts: LoadPluginsOptions = {}): Promise<RulePlugin[]> {
  const root = resolve(opts.cwd ?? process.cwd(), dir);
  let isDir: boolean;
  try {
    isDir = statSync(root).isDirectory();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw new PluginError(`cannot read plugin directory ${root}: ${(err as Error).message}`);
  }
  if (!isDir) throw new PluginError(`plugin path ${root} is not a directory`);

  const files = readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isFile() && !e.name.startsWith('.') && PLUGIN_EXTENSIONS.some((ext) => e.name.endsWith(ext)))
    .map((e) => e.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const plugins: RulePlugin[] = [];
  const seen = new Map<string, string>();
  for (const name of files) {
    const file = join(root, name);
    const plugin = await loadPlugin(file);
    const prev = seen.get(plugin.id);
    if (prev) throw new PluginError(`duplicate plugin id '${plugin.id}' in ${prev} and ${file}`);
    seen.set(plugin.id, file);
    plugins.push(plugin);
  }
  return plugins;
}

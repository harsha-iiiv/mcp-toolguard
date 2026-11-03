// Public API of the plugins module.
// SECURITY: plugins run in-process with full user permissions; loading is opt-in. See docs/PLUGINS.md.
export { loadPlugin, loadPlugins } from './loader.js';
export type { LoadPluginsOptions } from './loader.js';
export { definePlugin, assertRulePlugin, PluginError, PLUGIN_ID_PATTERN } from './types.js';
export type { RulePlugin, Verdict, VerdictAction, ToolCall, ToolResult, Policy } from './types.js';

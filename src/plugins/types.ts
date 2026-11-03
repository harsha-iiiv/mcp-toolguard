// Plugin authoring types.
//
// The contract types in src/contracts.ts are the source of truth; this file only re-exports them and adds a
// small validating identity helper. Do not redefine RulePlugin / Verdict / ToolCall / ToolResult / Policy here.
import type { RulePlugin } from '../contracts.js';

export type { RulePlugin, Verdict, VerdictAction, ToolCall, ToolResult, Policy } from '../contracts.js';

/** Plugin ids: lowercase, start with a letter or digit, then letters, digits, '.', '_' or '-'. */
export const PLUGIN_ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

/** Thrown when a plugin (or plugin directory) cannot be loaded or is invalid. */
export class PluginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PluginError';
  }
}

/**
 * Validate that `p` satisfies the RulePlugin contract. Throws PluginError with a clear message otherwise.
 * `source` is only used to make the error message point at the offending file.
 */
export function assertRulePlugin(p: unknown, source?: string): asserts p is RulePlugin {
  const where = source ? ` (${source})` : '';
  if (p === null || typeof p !== 'object') {
    throw new PluginError(`plugin${where} must be an object with { id, check }, got ${p === null ? 'null' : typeof p}`);
  }
  const { id, check } = p as { id?: unknown; check?: unknown };
  if (typeof id !== 'string' || id.length === 0) {
    throw new PluginError(`plugin${where} must have a non-empty string 'id'`);
  }
  if (!PLUGIN_ID_PATTERN.test(id)) {
    throw new PluginError(
      `plugin id '${id}'${where} is invalid: use lowercase letters, digits, '.', '_' or '-', starting with a letter or digit`,
    );
  }
  if (typeof check !== 'function') {
    throw new PluginError(`plugin '${id}'${where} must have a 'check(call, result, policy)' function`);
  }
}

/**
 * Identity helper for plugin authors (TypeScript gets full types for `check`'s parameters).
 * Validates the plugin and returns the same object unchanged.
 *
 *   export default definePlugin({ id: 'my-rule', check(call, result, policy) { return null; } });
 */
export function definePlugin(p: RulePlugin): RulePlugin {
  assertRulePlugin(p);
  return p;
}

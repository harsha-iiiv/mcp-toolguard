// mcp-toolguard public library API (stable from v1.0).
//
// FROZEN from v1.0 — these names are permanent; only additive changes are allowed (see docs/API.md):
//   startProxy, loadPolicy, createPolicyEngine, createDetector, createPinStore,
//   createAuditLogger, verifyAuditLog, loadPlugin
// tests/unit/plugins/api.test.ts fails if any of them is renamed or removed.
export * from './contracts.js';
export { startProxy } from './proxy/index.js';
export { defaultPolicy, validatePolicy, loadPolicy, createPolicyEngine } from './policy/index.js';
export { createDetector, builtinRules, createPinStore, hashTool } from './detection/index.js';
export { createAuditLogger, verifyAuditLog, redactSecrets, canonicalJson } from './audit/index.js';
export type { InspectableAuditLogger } from './audit/index.js';
export { loadPlugin, loadPlugins, definePlugin, PluginError } from './plugins/index.js';
export type { LoadPluginsOptions } from './plugins/index.js';
export { runCli, UsageError } from './cli/run-cli.js';
export type { CliIo, CliWriter } from './cli/run-cli.js';

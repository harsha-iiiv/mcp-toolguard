/**
 * Detection module public API (see "Module export map" in src/contracts.ts).
 *
 *   createDetector  – run built-in + extra rules against tool definitions, calls and results
 *   builtinRules    – fresh array of the nine built-in rules (one per RULE_IDS entry)
 *   createPinStore  – trust-on-first-use pin store (in-memory, or JSON file written atomically)
 *   hashTool        – sha256 of canonical JSON of { name, description, inputSchema }
 */
import type { BuiltinRules } from '../contracts.js';
import { BUILTIN_RULES } from './rules/index.js';

export { createDetector } from './detector.js';
export { createPinStore, hashTool } from './pins.js';

export const builtinRules: BuiltinRules = () => [...BUILTIN_RULES];

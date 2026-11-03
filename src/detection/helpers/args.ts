/**
 * Heuristics for deciding how to treat a tool-call argument string.
 *
 * Arguments that hold documents (file contents, issue bodies, code) legitimately mention paths
 * like "../utils.js" or ".env.example" and shell snippets like "curl … | sh". Scanning them as if
 * they were paths or shell fragments is the main false-positive source for the path and
 * command-injection rules, so those rules only look at "operand-like" strings: single-line,
 * bounded length, or held in a property whose name says it is a path / command.
 */
import type { StringHit } from './text.js';

const PATH_KEY = /(?:^|[_-])(?:path|paths|file|files|filename|filepath|dir|directory|folder|src|source|dest|destination|target|uri|url|location|cwd|root|glob|pattern|repo_?path)$/i;
const COMMAND_KEY = /(?:^|[_-])(?:cmd|command|commands|script|shell|exec|executable|args|argv|program|run|bash|sh)$/i;

export const MAX_OPERAND_LENGTH = 2048;

export function isPathKey(key: string | undefined): boolean {
  return key !== undefined && (PATH_KEY.test(key) || /^(?:path|file|uri|url)/i.test(key));
}

export function isCommandKey(key: string | undefined): boolean {
  return key !== undefined && COMMAND_KEY.test(key);
}

/** Single-line, bounded strings, or anything under a path/command-like property name. */
export function isOperandLike(hit: StringHit): boolean {
  if (isPathKey(hit.key) || isCommandKey(hit.key)) return true;
  return hit.value.length <= MAX_OPERAND_LENGTH && !/[\r\n]/.test(hit.value);
}

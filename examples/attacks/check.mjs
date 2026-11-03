#!/usr/bin/env node
// Tiny assertion helper for demo.sh.
//   node examples/attacks/check.mjs <summary.json> '<js expression>'
// Exits 0 if the expression is truthy, 1 otherwise. In scope:
//   S              the summary written by client.mjs --summary
//   MARKER         BLOCK_MARKER from the built contract ('[mcp-toolguard] BLOCKED')
//   blocked(call)  true if a call's response text starts with MARKER
//   has(list, n)   true if a tools/list snapshot contains tool n
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [file, expr] = process.argv.slice(2);
if (!file || !expr) {
  process.stderr.write('usage: check.mjs <summary.json> <expression>\n');
  process.exit(64);
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { BLOCK_MARKER: MARKER } = await import(pathToFileURL(resolve(root, 'dist', 'contracts.js')).href);
const S = JSON.parse(readFileSync(file, 'utf8'));
const blocked = (call) => Boolean(call) && typeof call.text === 'string' && call.text.startsWith(MARKER);
const has = (list, name) => Array.isArray(list) && list.includes(name);

let ok = false;
try {
  ok = Boolean(new Function('S', 'MARKER', 'blocked', 'has', `return (${expr});`)(S, MARKER, blocked, has));
} catch (err) {
  process.stderr.write(`check.mjs: ${err instanceof Error ? err.message : String(err)}\n`);
}
process.exit(ok ? 0 : 1);

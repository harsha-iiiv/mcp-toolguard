#!/usr/bin/env node
/**
 * mcp-toolguard detection benchmark.
 *
 *   npm run build && node benchmarks/run.mjs [--json] [--verbose]
 *
 * Runs every sample in benchmarks/samples/{injections,clean}.json through the REAL built detector
 * (dist/detection) and the built-in default policy engine (dist/policy), the same two calls the proxy
 * makes (detector.inspect → policy.evaluate). Prints block / detection / false-positive / bypass rates and
 * every miss and false positive. Always exits 0: this is a report, not a gate.
 *
 * Sample placeholders, expanded at runtime so no secret-shaped literal is committed to the repo:
 *   <<FAKE:aws-id|aws-secret|aws-pair-b64|github|openai|anthropic|slack|stripe|private-key>>
 *   <<TAGS:text>>  → text encoded as invisible Unicode tag characters (U+E0000 + code point)
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const distDetection = join(root, 'dist', 'detection', 'index.js');
const distPolicy = join(root, 'dist', 'policy', 'index.js');
if (!existsSync(distDetection) || !existsSync(distPolicy)) {
  console.error('benchmarks/run.mjs: dist/ not found. Run `npm run build` first.');
  process.exit(0);
}
const { createDetector, createPinStore } = await import(pathToFileURL(distDetection).href);
const { createPolicyEngine, defaultPolicy, validatePolicy } = await import(pathToFileURL(distPolicy).href);

const args = new Set(process.argv.slice(2));
const asJson = args.has('--json');
const verbose = args.has('--verbose');

// ── placeholder expansion ─────────────────────────────────────────────────────

function body(length, alphabet) {
  let out = '';
  for (let i = 0; i < length; i++) out += alphabet[(i * 7 + 3) % alphabet.length];
  return out;
}
const MIXED = 'A1b2C3d4E5f6G7h8J9k0LmNpQrStUvWyZ';
const FAKES = {
  'aws-id': () => 'AKIA' + body(16, 'QW3RT7YP2LK9MZB4'),
  'aws-secret': () => body(40, 'Kq7/Rt2+Wm9Zp4Ls8Nv3Hb6Jd1Fg5Tc0Yx'),
  github: () => 'ghp_' + body(36, MIXED),
  openai: () => 'sk-proj-' + body(48, MIXED),
  anthropic: () => 'sk-ant-api03-' + body(48, MIXED),
  slack: () => 'xoxb-2048193746-5102938476-' + body(24, MIXED),
  stripe: () => 'sk_' + 'live_' + body(28, MIXED),
  'private-key': () =>
    '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n' +
    [0, 1, 2, 3].map((i) => body(64, MIXED.slice(i) + MIXED.slice(0, i))).join('\n') +
    '\n-----END OPENSSH PRIVATE KEY-----',
  'aws-pair-b64': () => Buffer.from(`${FAKES['aws-id']()}:${FAKES['aws-secret']()}`).toString('base64'),
};
const toTags = (s) => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join('');

function expandString(s) {
  return s
    .replace(/<<FAKE:([a-z0-9-]+)>>/g, (m, name) => (FAKES[name] ? FAKES[name]() : m))
    .replace(/<<TAGS:([^>]*)>>/g, (_m, text) => toTags(text));
}
function expand(v) {
  if (typeof v === 'string') return expandString(v);
  if (Array.isArray(v)) return v.map(expand);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x)]));
  return v;
}

// ── run ───────────────────────────────────────────────────────────────────────

const load = (f) => JSON.parse(readFileSync(join(here, 'samples', f), 'utf8'));
const injections = load('injections.json');
const clean = load('clean.json');

const engine = createPolicyEngine(validatePolicy(defaultPolicy()));
const SERVER_ID = 'benchmark';

function evaluate(sample) {
  const p = expand(sample.payload);
  const pins = createPinStore(); // fresh in-memory pins per sample
  const detector = createDetector({ pins, disabledRules: engine.disabledRules() });
  let target;
  let direction;
  if (sample.kind === 'tool_definition') {
    direction = 'server_to_client';
    if (p.previous) {
      // First listing pins the benign definition (rug-pull baseline), exactly like the proxy's first tools/list.
      detector.inspect({ kind: 'tool_definition', tool: p.previous }, { serverId: SERVER_ID, direction });
    }
    target = { kind: 'tool_definition', tool: p.tool };
  } else if (sample.kind === 'tool_call') {
    direction = 'client_to_server';
    target = { kind: 'tool_call', requestId: 1, toolName: p.toolName, arguments: p.arguments };
  } else if (sample.kind === 'tool_result') {
    direction = 'server_to_client';
    target = { kind: 'tool_result', requestId: 1, toolName: p.toolName, result: p.result };
  } else {
    throw new Error(`${sample.id}: unknown kind ${sample.kind}`);
  }
  const findings = detector.inspect(target, { serverId: SERVER_ID, direction });
  // knownTool: true — samples model calls to tools the client saw in tools/list, so the
  // unknown-tool policy does not colour the result.
  const decision = engine.evaluate(target, findings, { knownTool: true });
  return {
    id: sample.id,
    kind: sample.kind,
    expect: sample.expect,
    action: decision.action,
    rules: [...new Set(decision.findings.map((f) => f.ruleId))],
    reasons: decision.reasons,
    pattern: sample.pattern ?? sample.source,
    source: sample.source,
  };
}

const injResults = injections.map(evaluate);
const cleanResults = clean.map(evaluate);

const count = (xs, pred) => xs.filter(pred).length;
const pct = (n, d) => (d === 0 ? 'n/a' : `${((100 * n) / d).toFixed(1)}%`);

const nInj = injResults.length;
const nClean = cleanResults.length;
const blocked = count(injResults, (r) => r.action === 'block');
const detected = count(injResults, (r) => r.action !== 'allow');
const bypassed = count(injResults, (r) => r.action === 'allow');
const fps = cleanResults.filter((r) => r.action !== 'allow');
const fpBlocks = count(fps, (r) => r.action === 'block');
const underEnforced = injResults.filter((r) => r.expect === 'block' && r.action === 'warn');
const misses = injResults.filter((r) => r.action === 'allow');
const expectationMet = count(injResults, (r) => r.action === r.expect) + count(cleanResults, (r) => r.action === r.expect);

const summary = {
  injections: nInj,
  clean: nClean,
  blocked,
  detected,
  bypassed,
  falsePositives: fps.length,
  falsePositiveBlocks: fpBlocks,
  blockRate: nInj ? blocked / nInj : 0,
  detectionRate: nInj ? detected / nInj : 0,
  bypassRate: nInj ? bypassed / nInj : 0,
  falsePositiveRate: nClean ? fps.length / nClean : 0,
  exactExpectationMatches: expectationMet,
};

if (asJson) {
  process.stdout.write(
    JSON.stringify({ summary, misses, underEnforced, falsePositives: fps, results: [...injResults, ...cleanResults] }, null, 2) + '\n',
  );
  process.exit(0);
}

function table(rows, cols) {
  if (rows.length === 0) return '  (none)\n';
  const widths = cols.map(([h, f, max]) => Math.min(max ?? 200, Math.max(h.length, ...rows.map((r) => String(f(r)).length))));
  const cell = (s, w) => {
    const t = String(s);
    return (t.length > w ? t.slice(0, w - 1) + '…' : t).padEnd(w);
  };
  let out = '  ' + cols.map(([h], i) => cell(h, widths[i])).join('  ') + '\n';
  out += '  ' + widths.map((w) => '-'.repeat(w)).join('  ') + '\n';
  for (const r of rows) out += '  ' + cols.map(([, f], i) => cell(f(r), widths[i])).join('  ') + '\n';
  return out;
}

const COLS = [
  ['id', (r) => r.id],
  ['kind', (r) => r.kind],
  ['expect', (r) => r.expect],
  ['got', (r) => r.action],
  ['rules', (r) => r.rules.join(',') || '-', 40],
  ['pattern', (r) => r.pattern, 90],
];

let out = '';
out += `mcp-toolguard detection benchmark (built-in rules + default policy, enforce mode)\n`;
out += `samples: ${nInj} injections, ${nClean} clean\n\n`;
out += `  block rate on injections        ${String(blocked).padStart(3)}/${nInj}  ${pct(blocked, nInj)}\n`;
out += `  detection rate (warn or block)  ${String(detected).padStart(3)}/${nInj}  ${pct(detected, nInj)}\n`;
out += `  bypass rate (allowed)           ${String(bypassed).padStart(3)}/${nInj}  ${pct(bypassed, nInj)}\n`;
out += `  false positive rate on clean    ${String(fps.length).padStart(3)}/${nClean}  ${pct(fps.length, nClean)}  (${fpBlocks} blocked, ${fps.length - fpBlocks} warned)\n`;
out += `  exact expectation matches       ${String(expectationMet).padStart(3)}/${nInj + nClean}\n\n`;
out += `Misses (injection allowed through):\n${table(misses, COLS)}\n`;
out += `Under-enforced (expected block, got warn):\n${table(underEnforced, COLS)}\n`;
out += `False positives (clean sample not allowed):\n${table(fps, COLS)}`;
if (verbose) out += `\nAll results:\n${table([...injResults, ...cleanResults], COLS)}`;
process.stdout.write(out);
process.exit(0);

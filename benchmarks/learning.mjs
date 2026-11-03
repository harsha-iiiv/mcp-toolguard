#!/usr/bin/env node
/**
 * Baseline-learning eval on synthetic filesystem traffic.
 *
 *   npm run build && node benchmarks/learning.mjs [--json]
 *
 * Trains the REAL built plugin (dist/learning) on 6 days x 120 calls, then replays 5 unseen normal days
 * (different seeds) and the injected outliers. Reports warnings per normal day and outliers caught.
 * In-memory only (no baseline file is written). Always exits 0.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist', 'learning', 'index.js');
if (!existsSync(dist)) {
  console.error('benchmarks/learning.mjs: dist/ not found. Run `npm run build` first.');
  process.exit(0);
}
const { createBaselinePlugin, generateDay, generateDays, injectOutliers } = await import(pathToFileURL(dist).href);

const clock = { t: new Date() };
const plugin = createBaselinePlugin({ minSamples: 50, now: () => clock.t });
const policy = {};
const run = (c) => {
  clock.t = c.at;
  return plugin.check(c.call, undefined, policy);
};

const today = new Date(2026, 10, 3, 12);
const training = generateDays(new Date(2026, 10, 2, 12), 6, 120, 3);
const trainingWarnings = training.map(run).filter(Boolean).length;

const days = [];
const actions = new Set();
for (const seed of [101, 202, 303, 404, 505]) {
  // Fresh plugin per replayed day so days do not train each other.
  const p = createBaselinePlugin({ minSamples: 50, now: () => clock.t });
  for (const c of training) {
    clock.t = c.at;
    p.check(c.call, undefined, policy);
  }
  const calls = generateDay({ date: today, calls: 120, seed });
  const warns = [];
  for (const c of calls) {
    clock.t = c.at;
    const v = p.check(c.call, undefined, policy);
    if (v) {
      warns.push(v.reason);
      actions.add(v.action);
    }
  }
  days.push({ seed, calls: calls.length, warnings: warns.length, reasons: warns });
}

const outliers = injectOutliers(today).map((o) => {
  const v = run(o);
  if (v) actions.add(v.action);
  return { kind: o.kind, label: o.label, action: v?.action ?? 'none', reason: v?.reason ?? null };
});

const result = {
  minSamples: 50,
  trainingCalls: training.length,
  trainingWarnings,
  normalDays: days,
  normalWarningRate: days.reduce((s, d) => s + d.warnings, 0) / days.reduce((s, d) => s + d.calls, 0),
  outliersCaught: outliers.filter((o) => o.action === 'warn').length,
  outliers,
  actionsSeen: [...actions],
};

if (process.argv.includes('--json')) {
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(0);
}
let out = 'mcp-toolguard baseline learning eval (synthetic filesystem traffic, minSamples 50)\n\n';
out += `  training: ${training.length} calls over 6 days, ${trainingWarnings} warnings while learning\n`;
for (const d of days) out += `  normal day seed ${d.seed}: ${d.warnings}/${d.calls} calls warned${d.warnings ? ' (' + d.reasons.join('; ') + ')' : ''}\n`;
out += `  normal-day warning rate: ${(100 * result.normalWarningRate).toFixed(2)}%\n`;
out += `  injected outliers caught: ${result.outliersCaught}/${outliers.length}\n`;
for (const o of outliers) out += `    [${o.action}] ${o.label}: ${o.reason ?? '-'}\n`;
out += `  verdict actions seen: ${result.actionsSeen.join(', ') || '(none)'}\n`;
process.stdout.write(out);

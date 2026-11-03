/**
 * Learning module public API (opt-in via `run --learning`).
 *
 *   createBaselinePlugin – RulePlugin (id 'learning') that learns normal tools/call traffic per
 *                          (server, tool) and returns warn verdicts for outliers. Never blocks.
 *   generateDay / generateDays / injectOutliers – deterministic synthetic traffic for tests and demos.
 */
export { createBaselinePlugin, LIMITS as BASELINE_LIMITS } from './baseline.js';
export type { BaselinePlugin, BaselinePluginOptions, BaselineSnapshot, DayBucket, ToolBaseline } from './baseline.js';
export { classifyString, shapeOf } from './shape.js';
export type { ValueClass } from './shape.js';
export { generateDay, generateDays, injectOutliers, prng } from './synthetic.js';
export type { SyntheticCall, SyntheticDayOptions, SyntheticOutlier } from './synthetic.js';

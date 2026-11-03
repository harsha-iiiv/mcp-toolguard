/**
 * Baseline learning plugin (opt-in). Learns what normal tools/call traffic looks like per
 * (serverId, toolName) and emits `warn` verdicts for outliers. It NEVER blocks and never asks for approval.
 *
 * What is recorded (7-day rolling window, one bucket per local calendar day):
 *   - call count
 *   - hour-of-day histogram (local time)
 *   - frequency of each top-level argument key set (key names only)
 *   - per argument key, frequency of each value *shape* (class + length bucket, see shape.ts)
 * Raw argument values are never stored.
 *
 * Scoring (only once the tool has >= minSamples calls in the window, computed against history BEFORE the
 * current call is recorded). Component scores in 0..1 are combined with a noisy-OR:
 *   - never-seen tool on a server with >= minSamples calls          0.80
 *   - unseen argument key set                                         0.80 (0.50 if the key-set cap is full)
 *   - argument key set seen in < 1% of calls                          0.40
 *   - unseen value class for a known key                              0.75 (0.50 if the shape cap is full)
 *   - known class but unseen length bucket                            0.35
 *   - no calls in this hour or the neighbouring hours                 0.72
 *   - hour neighbourhood holds < 1% of calls                          0.30
 * score >= threshold (default 0.7) → warn.
 */
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { Policy, RulePlugin, ToolCall, ToolResult, Verdict } from '../contracts.js';
import { shapeClass, shapeOf } from './shape.js';

// ── public types ──────────────────────────────────────────────────────────────

export interface BaselinePluginOptions {
  /** JSON file to persist the baseline to. '~' expands. Undefined = memory only. */
  file?: string;
  /** Calls per (server, tool) in the window before outliers are scored. */
  minSamples: number;
  /** Clock, injectable for tests. Default () => new Date(). */
  now?: () => Date;
  /** Score at or above which a warn verdict is returned. Default 0.7. */
  threshold?: number;
  /** Persist after this many recorded calls. Default 25. */
  flushEvery?: number;
  /** Also persist this long after the first unsaved call (timer is unref'd). Default 5000 ms. 0 disables. */
  flushDelayMs?: number;
  /** Rolling window in days. Default 7. */
  windowDays?: number;
}

export interface DayBucket {
  count: number;
  /** 24 entries, local hour of day. */
  hours: number[];
  /** Sorted, comma-joined top-level key names → count. */
  keySets: Record<string, number>;
  /** Argument key → shape signature → count. */
  shapes: Record<string, Record<string, number>>;
}

export interface ToolBaseline {
  /** Local date 'YYYY-MM-DD' → bucket. */
  days: Record<string, DayBucket>;
}

export interface BaselineSnapshot {
  version: 1;
  servers: Record<string, { tools: Record<string, ToolBaseline> }>;
}

export interface BaselinePlugin extends RulePlugin {
  readonly id: 'learning';
  /** Write the baseline to disk now (no-op when memory only or nothing changed). */
  flush(): void;
  /** Deep copy of the current baseline (after pruning to the window). */
  snapshot(): BaselineSnapshot;
}

// ── limits (bounded size) ────────────────────────────────────────────────────

export const LIMITS = {
  servers: 64,
  toolsPerServer: 256,
  keySetsPerTool: 32,
  keysPerTool: 64,
  shapesPerKey: 16,
  nameLength: 64,
} as const;

const KEY_SET_SEP = ',';

// ── helpers ───────────────────────────────────────────────────────────────────

function expandHome(file: string): string {
  if (file === '~') return homedir();
  if (file.startsWith('~/') || file.startsWith('~\\')) return join(homedir(), file.slice(2));
  return file;
}

function clip(name: string): string {
  return name.length > LIMITS.nameLength ? name.slice(0, LIMITS.nameLength) : name;
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function dayKey(d: Date): string {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** Day key `n` days before `d` (local calendar). */
function dayKeyMinus(d: Date, n: number): string {
  const x = new Date(d.getFullYear(), d.getMonth(), d.getDate() - n, 12);
  return dayKey(x);
}

function emptyBucket(): DayBucket {
  return { count: 0, hours: new Array<number>(24).fill(0), keySets: {}, shapes: {} };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function numberMap(v: unknown, max: number): Record<string, number> {
  const out: Record<string, number> = {};
  if (!isRecord(v)) return out;
  let n = 0;
  for (const [k, c] of Object.entries(v)) {
    if (n >= max) break;
    if (typeof c === 'number' && Number.isFinite(c) && c > 0) {
      out[clip(k)] = Math.floor(c);
      n++;
    }
  }
  return out;
}

/** Validate/normalize a parsed file. Anything malformed is dropped rather than trusted. */
function sanitize(raw: unknown): BaselineSnapshot {
  const snap: BaselineSnapshot = { version: 1, servers: {} };
  if (!isRecord(raw) || raw['version'] !== 1 || !isRecord(raw['servers'])) return snap;
  let sCount = 0;
  for (const [serverId, s] of Object.entries(raw['servers'])) {
    if (sCount >= LIMITS.servers) break;
    if (!isRecord(s) || !isRecord(s['tools'])) continue;
    const tools: Record<string, ToolBaseline> = {};
    let tCount = 0;
    for (const [toolName, t] of Object.entries(s['tools'])) {
      if (tCount >= LIMITS.toolsPerServer) break;
      if (!isRecord(t) || !isRecord(t['days'])) continue;
      const days: Record<string, DayBucket> = {};
      for (const [day, b] of Object.entries(t['days'])) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || !isRecord(b)) continue;
        const hoursRaw = Array.isArray(b['hours']) ? b['hours'] : [];
        const hours = new Array<number>(24).fill(0).map((_, i) => {
          const h = hoursRaw[i];
          return typeof h === 'number' && Number.isFinite(h) && h > 0 ? Math.floor(h) : 0;
        });
        const shapes: Record<string, Record<string, number>> = {};
        if (isRecord(b['shapes'])) {
          let kCount = 0;
          for (const [key, m] of Object.entries(b['shapes'])) {
            if (kCount >= LIMITS.keysPerTool) break;
            shapes[clip(key)] = numberMap(m, LIMITS.shapesPerKey);
            kCount++;
          }
        }
        const count = typeof b['count'] === 'number' && Number.isFinite(b['count']) && b['count'] > 0 ? Math.floor(b['count']) : 0;
        days[day] = { count, hours, keySets: numberMap(b['keySets'], LIMITS.keySetsPerTool), shapes };
      }
      tools[clip(toolName)] = { days };
      tCount++;
    }
    snap.servers[clip(serverId)] = { tools };
    sCount++;
  }
  return snap;
}

function writeAtomic(file: string, data: string): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    writeFileSync(tmp, data, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, file);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw err;
  }
}

interface Aggregate {
  count: number;
  hours: number[];
  keySets: Map<string, number>;
  shapes: Map<string, Map<string, number>>;
}

function aggregate(tool: ToolBaseline | undefined): Aggregate {
  const agg: Aggregate = { count: 0, hours: new Array<number>(24).fill(0), keySets: new Map(), shapes: new Map() };
  if (!tool) return agg;
  for (const b of Object.values(tool.days)) {
    agg.count += b.count;
    for (let i = 0; i < 24; i++) agg.hours[i]! += b.hours[i] ?? 0;
    for (const [k, c] of Object.entries(b.keySets)) agg.keySets.set(k, (agg.keySets.get(k) ?? 0) + c);
    for (const [key, m] of Object.entries(b.shapes)) {
      let am = agg.shapes.get(key);
      if (!am) agg.shapes.set(key, (am = new Map()));
      for (const [shape, c] of Object.entries(m)) am.set(shape, (am.get(shape) ?? 0) + c);
    }
  }
  return agg;
}

function bump(map: Record<string, number>, key: string, cap: number): void {
  if (key in map) map[key]! += 1;
  else if (Object.keys(map).length < cap) map[key] = 1;
}

interface Signal {
  what: string;
  score: number;
}

// ── factory ───────────────────────────────────────────────────────────────────

export function createBaselinePlugin(opts: BaselinePluginOptions): BaselinePlugin {
  const minSamples = Math.max(1, Math.floor(opts.minSamples));
  const now = opts.now ?? (() => new Date());
  const threshold = opts.threshold ?? 0.7;
  const flushEvery = Math.max(1, opts.flushEvery ?? 25);
  const flushDelayMs = opts.flushDelayMs ?? 5000;
  const windowDays = Math.max(1, Math.floor(opts.windowDays ?? 7));
  const file = opts.file !== undefined && opts.file !== '' ? resolve(expandHome(opts.file)) : undefined;

  let state: BaselineSnapshot = { version: 1, servers: {} };
  if (file && existsSync(file)) {
    try {
      state = sanitize(JSON.parse(readFileSync(file, 'utf8')));
    } catch (err) {
      process.stderr.write(`[mcp-toolguard] learning: ignoring unreadable baseline ${file}: ${(err as Error).message}\n`);
    }
  }

  let dirty = 0;
  let timer: NodeJS.Timeout | undefined;
  let lastPrunedFor = '';

  function prune(today: Date): void {
    const cutoff = dayKeyMinus(today, windowDays - 1);
    const key = `${dayKey(today)}`;
    if (key === lastPrunedFor) return;
    lastPrunedFor = key;
    for (const [serverId, s] of Object.entries(state.servers)) {
      for (const [toolName, t] of Object.entries(s.tools)) {
        for (const day of Object.keys(t.days)) if (day < cutoff) delete t.days[day];
        if (Object.keys(t.days).length === 0) delete s.tools[toolName];
      }
      if (Object.keys(s.tools).length === 0) delete state.servers[serverId];
    }
  }

  function flush(): void {
    if (timer) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (!file || dirty === 0) return;
    try {
      prune(now());
      writeAtomic(file, JSON.stringify(state));
      dirty = 0;
    } catch (err) {
      process.stderr.write(`[mcp-toolguard] learning: could not save baseline ${file}: ${(err as Error).message}\n`);
    }
  }

  function markDirty(): void {
    if (!file) return;
    dirty++;
    if (dirty >= flushEvery) {
      flush();
      return;
    }
    if (flushDelayMs > 0 && !timer) {
      timer = setTimeout(flush, flushDelayMs);
      timer.unref?.();
    }
  }

  function score(serverId: string, toolName: string, keySet: string, shapes: [string, string][], hour: number): Signal[] {
    const server = state.servers[serverId];
    const tool = server?.tools[toolName];
    const agg = aggregate(tool);
    const signals: Signal[] = [];

    if (agg.count === 0) {
      let serverCount = 0;
      if (server) for (const t of Object.values(server.tools)) for (const b of Object.values(t.days)) serverCount += b.count;
      if (serverCount >= minSamples) signals.push({ what: `tool (first call on server ${serverId})`, score: 0.8 });
      return signals;
    }
    if (agg.count < minSamples) return signals;

    // argument key set
    const ksCount = agg.keySets.get(keySet) ?? 0;
    const label = `argument keys {${keySet}}`;
    if (ksCount === 0) signals.push({ what: label, score: agg.keySets.size >= LIMITS.keySetsPerTool ? 0.5 : 0.8 });
    else if (ksCount / agg.count < 0.01) signals.push({ what: label, score: 0.4 });

    // value shapes
    for (const [key, shape] of shapes) {
      const seen = agg.shapes.get(key);
      if (!seen || seen.size === 0) continue; // a new key is already covered by the key-set signal
      if (seen.has(shape)) continue;
      const cls = shapeClass(shape);
      const classSeen = [...seen.keys()].some((s) => shapeClass(s) === cls);
      if (!classSeen) signals.push({ what: `value shape ${cls} for '${key}'`, score: seen.size >= LIMITS.shapesPerKey ? 0.5 : 0.75 });
      else signals.push({ what: `value length for '${key}'`, score: 0.35 });
    }

    // hour of day: own hour plus neighbours
    const near = (agg.hours[(hour + 23) % 24] ?? 0) + (agg.hours[hour] ?? 0) + (agg.hours[(hour + 1) % 24] ?? 0);
    if (near === 0) signals.push({ what: `hour ${pad2(hour)}:00`, score: 0.72 });
    else if (near / agg.count < 0.01) signals.push({ what: `hour ${pad2(hour)}:00`, score: 0.3 });

    return signals;
  }

  function record(serverId: string, toolName: string, day: string, hour: number, keySet: string, shapes: [string, string][]): void {
    let server = state.servers[serverId];
    if (!server) {
      if (Object.keys(state.servers).length >= LIMITS.servers) return;
      server = state.servers[serverId] = { tools: {} };
    }
    let tool = server.tools[toolName];
    if (!tool) {
      if (Object.keys(server.tools).length >= LIMITS.toolsPerServer) return;
      tool = server.tools[toolName] = { days: {} };
    }
    let bucket = tool.days[day];
    if (!bucket) bucket = tool.days[day] = emptyBucket();
    bucket.count++;
    bucket.hours[hour] = (bucket.hours[hour] ?? 0) + 1;
    bump(bucket.keySets, keySet, LIMITS.keySetsPerTool);
    // Key cap is per tool across the window; count distinct keys already tracked in any bucket.
    const knownKeys = new Set<string>();
    for (const b of Object.values(tool.days)) for (const k of Object.keys(b.shapes)) knownKeys.add(k);
    for (const [key, shape] of shapes) {
      let m = bucket.shapes[key];
      if (!m) {
        if (!knownKeys.has(key) && knownKeys.size >= LIMITS.keysPerTool) continue;
        knownKeys.add(key);
        m = bucket.shapes[key] = {};
      }
      bump(m, shape, LIMITS.shapesPerKey);
    }
    markDirty();
  }

  function check(call: ToolCall, result: ToolResult | undefined, _policy?: Policy): Verdict | null {
    if (result !== undefined) return null;
    try {
      const at = now();
      prune(at);
      const serverId = clip(String(call.serverId));
      const toolName = clip(String(call.toolName));
      const args = isRecord(call.arguments) ? call.arguments : {};
      const keys = Object.keys(args).map(clip).sort();
      const keySet = keys.join(KEY_SET_SEP);
      const shapes: [string, string][] = Object.entries(args).map(([k, v]) => [clip(k), shapeOf(v)]);
      const hour = at.getHours();

      const signals = score(serverId, toolName, keySet, shapes, hour);
      record(serverId, toolName, dayKey(at), hour, keySet, shapes);

      if (signals.length === 0) return null;
      const total = 1 - signals.reduce((p, s) => p * (1 - s.score), 1);
      if (total < threshold) return null;
      const what = [...signals].sort((a, b) => b.score - a.score).map((s) => s.what).join(' + ');
      return {
        action: 'warn',
        ruleId: 'learning',
        severity: 'medium',
        reason: `unusual ${what} for ${toolName} (score ${total.toFixed(2)})`,
      };
    } catch (err) {
      // Never fail closed from learning: a broken baseline must not block traffic.
      process.stderr.write(`[mcp-toolguard] learning: ${(err as Error).message}\n`);
      return null;
    }
  }

  function snapshot(): BaselineSnapshot {
    prune(now());
    return JSON.parse(JSON.stringify(state)) as BaselineSnapshot;
  }

  return { id: 'learning', check, flush, snapshot };
}

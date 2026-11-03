/**
 * Trust-on-first-use pin store and tool fingerprinting.
 *
 * Detection is pure; the pin store is the only I/O it performs (contracts.ts HARD RULES).
 * File format: { "version": 1, "pins": ToolPin[] }, written atomically (tmp file + rename) with
 * mode 0600 because tool descriptions can reveal what a user has installed.
 */
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { CreatePinStore, HashTool, ToolPin, ToolPinStore } from '../contracts.js';

/** Deterministic JSON: object keys sorted recursively, `undefined` members dropped like JSON.stringify. */
export function canonicalJson(value: unknown): string {
  const seen = new Set<object>();
  const enc = (v: unknown): string | undefined => {
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') return undefined;
    if (v === null || typeof v !== 'object') {
      if (typeof v === 'bigint') return JSON.stringify(v.toString());
      if (typeof v === 'number' && !Number.isFinite(v)) return 'null';
      return JSON.stringify(v);
    }
    const toJson = (v as { toJSON?: () => unknown }).toJSON;
    if (typeof toJson === 'function') return enc(toJson.call(v));
    if (seen.has(v)) throw new TypeError('canonicalJson: circular structure');
    seen.add(v);
    let out: string;
    if (Array.isArray(v)) {
      out = `[${v.map((x) => enc(x) ?? 'null').join(',')}]`;
    } else {
      const parts: string[] = [];
      for (const k of Object.keys(v).sort()) {
        const s = enc((v as Record<string, unknown>)[k]);
        if (s !== undefined) parts.push(`${JSON.stringify(k)}:${s}`);
      }
      out = `{${parts.join(',')}}`;
    }
    seen.delete(v);
    return out;
  };
  return enc(value) ?? 'null';
}

export const hashTool: HashTool = (tool) =>
  createHash('sha256')
    .update(canonicalJson({ name: tool.name, description: tool.description ?? '', inputSchema: tool.inputSchema ?? null }))
    .digest('hex');

export function expandHome(file: string): string {
  if (file === '~') return homedir();
  if (file.startsWith('~/') || file.startsWith('~\\')) return join(homedir(), file.slice(2));
  return file;
}

const keyOf = (serverId: string, toolName: string) => `${serverId}\u0000${toolName}`;

function isPin(v: unknown): v is ToolPin {
  if (!v || typeof v !== 'object') return false;
  const p = v as Record<string, unknown>;
  return (
    typeof p['serverId'] === 'string' &&
    typeof p['toolName'] === 'string' &&
    typeof p['hash'] === 'string' &&
    /^[0-9a-f]{64}$/.test(p['hash']) &&
    typeof p['description'] === 'string' &&
    typeof p['firstSeen'] === 'string'
  );
}

function parsePinFile(path: string, raw: string): ToolPin[] {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Pin file ${path} is corrupt (invalid JSON: ${(err as Error).message}). Fix or delete it to re-pin all tools.`);
  }
  if (!data || typeof data !== 'object' || (data as Record<string, unknown>)['version'] !== 1) {
    throw new Error(`Pin file ${path} is corrupt (expected {"version": 1, "pins": [...]}). Fix or delete it to re-pin all tools.`);
  }
  const pins = (data as Record<string, unknown>)['pins'];
  if (!Array.isArray(pins)) {
    throw new Error(`Pin file ${path} is corrupt ("pins" must be an array). Fix or delete it to re-pin all tools.`);
  }
  pins.forEach((p, i) => {
    if (!isPin(p)) throw new Error(`Pin file ${path} is corrupt (pins[${i}] is not a valid pin). Fix or delete it to re-pin all tools.`);
  });
  return pins as ToolPin[];
}

export const createPinStore: CreatePinStore = (file) => {
  const path = file === undefined ? undefined : resolve(expandHome(file));
  const pins = new Map<string, ToolPin>();
  let loaded = path === undefined;

  const load = () => {
    if (loaded) return;
    if (path && existsSync(path)) {
      for (const p of parsePinFile(path, readFileSync(path, 'utf8'))) pins.set(keyOf(p.serverId, p.toolName), { ...p });
    }
    loaded = true;
  };

  const persist = () => {
    if (!path) return;
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    const body = `${JSON.stringify({ version: 1, pins: [...pins.values()] }, null, 2)}\n`;
    try {
      writeFileSync(tmp, body, { mode: 0o600 });
      renameSync(tmp, path);
      chmodSync(path, 0o600);
    } catch (err) {
      try {
        unlinkSync(tmp);
      } catch {
        /* tmp may not exist */
      }
      throw err;
    }
  };

  const store: ToolPinStore = {
    get(serverId, toolName) {
      load();
      const p = pins.get(keyOf(serverId, toolName));
      return p ? { ...p } : undefined;
    },
    set(pin) {
      load();
      pins.set(keyOf(pin.serverId, pin.toolName), { ...pin });
      persist();
    },
    list(serverId) {
      load();
      return [...pins.values()].filter((p) => serverId === undefined || p.serverId === serverId).map((p) => ({ ...p }));
    },
    reset(serverId, toolName) {
      load();
      let removed = 0;
      for (const [k, p] of pins) {
        if (p.serverId === serverId && (toolName === undefined || p.toolName === toolName)) {
          pins.delete(k);
          removed++;
        }
      }
      if (removed > 0) persist();
      return removed;
    },
  };
  return store;
};

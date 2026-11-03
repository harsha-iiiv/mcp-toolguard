/**
 * Shared text utilities for detection rules: walking JSON values for strings, building
 * JSON-path-ish locations, evidence snippets and clamping.
 *
 * Everything here is pure and bounded: walking stops at MAX_DEPTH and MAX_NODES so a hostile
 * payload cannot make the detector recurse forever or allocate without limit.
 */
import type { ToolDescriptor } from '../../contracts.js';

export const MAX_EVIDENCE = 200;
export const MAX_DEPTH = 10;
/** Upper bound on visited nodes per walk. Generous: real MCP payloads are far smaller. */
export const MAX_NODES = 50_000;

export interface StringHit {
  /** JSON-path-ish location, e.g. "arguments.options.url" or "result.content[0].text". */
  path: string;
  value: string;
  /** Property name that held this string, if it was an object value. */
  key?: string;
  /** True when `value` is an object key rather than a value. */
  isKey?: boolean;
}

const IDENT = /^[A-Za-z_$][\w$-]*$/;

export function joinPath(base: string, key: string | number): string {
  if (typeof key === 'number') return `${base}[${key}]`;
  const seg = IDENT.test(key) ? key : JSON.stringify(key);
  if (!base) return IDENT.test(key) ? key : `[${seg}]`;
  return IDENT.test(key) ? `${base}.${seg}` : `${base}[${seg}]`;
}

export interface WalkOptions {
  /** Also yield object keys (as `isKey` hits). */
  includeKeys?: boolean;
  maxDepth?: number;
}

/**
 * Yield every string inside `value` (recursively through arrays/objects), with its location.
 * Depth beyond `maxDepth` (default 10) is not descended into.
 */
export function walkStrings(value: unknown, basePath: string, opts: WalkOptions = {}): StringHit[] {
  const out: StringHit[] = [];
  const maxDepth = opts.maxDepth ?? MAX_DEPTH;
  let nodes = 0;
  const seen = new Set<object>();

  const visit = (v: unknown, path: string, depth: number, key?: string): void => {
    if (++nodes > MAX_NODES) return;
    if (typeof v === 'string') {
      out.push(key === undefined ? { path, value: v } : { path, value: v, key });
      return;
    }
    if (v === null || typeof v !== 'object' || depth >= maxDepth) return;
    if (seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      v.forEach((item, i) => visit(item, joinPath(path, i), depth + 1, key));
      return;
    }
    for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
      const childPath = joinPath(path, k);
      if (opts.includeKeys) out.push({ path: childPath, value: k, isKey: true });
      visit(child, childPath, depth + 1, k);
    }
  };

  visit(value, basePath, 0);
  return out;
}

/** Strings of a tool definition that the model reads: title, description and all inputSchema text. */
export function toolDefinitionStrings(tool: ToolDescriptor, opts: WalkOptions = {}): StringHit[] {
  const hits: StringHit[] = [];
  if (typeof tool.title === 'string') hits.push({ path: 'title', value: tool.title });
  if (typeof tool.description === 'string') hits.push({ path: 'description', value: tool.description });
  if (tool.inputSchema !== undefined) hits.push(...walkStrings(tool.inputSchema, 'inputSchema', opts));
  return hits;
}

/**
 * Strings of a tools/call result that reach the model: content[*].text, embedded resource text,
 * and every string in structuredContent. Binary payloads (image/audio `data`) are skipped.
 */
export function toolResultStrings(result: Record<string, unknown>): StringHit[] {
  const hits: StringHit[] = [];
  const content = result['content'];
  if (Array.isArray(content)) {
    content.slice(0, MAX_NODES).forEach((item, i) => {
      if (!item || typeof item !== 'object') return;
      const rec = item as Record<string, unknown>;
      const base = `result.content[${i}]`;
      if (typeof rec['text'] === 'string') hits.push({ path: `${base}.text`, value: rec['text'] });
      const resource = rec['resource'];
      if (resource && typeof resource === 'object') {
        const text = (resource as Record<string, unknown>)['text'];
        if (typeof text === 'string') hits.push({ path: `${base}.resource.text`, value: text });
      }
    });
  }
  if (result['structuredContent'] !== undefined) {
    hits.push(...walkStrings(result['structuredContent'], 'result.structuredContent'));
  }
  return hits;
}

/** Clamp to ≤ MAX_EVIDENCE UTF-16 units without splitting a surrogate pair. */
export function clamp(s: string, max = MAX_EVIDENCE): string {
  if (s.length <= max) return s;
  let cut = max - 1;
  const code = s.charCodeAt(cut - 1);
  if (code >= 0xd800 && code <= 0xdbff) cut -= 1;
  return `${s.slice(0, cut)}…`;
}

/** Collapse whitespace so multi-line descriptions produce one-line evidence. */
export function oneLine(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

/** Short excerpt around [index, index+length), with ellipses when cut. */
export function snippet(text: string, index: number, length: number, context = 40): string {
  const start = Math.max(0, index - context);
  const end = Math.min(text.length, index + length + context);
  const body = oneLine(text.slice(start, end));
  return clamp(`${start > 0 ? '…' : ''}${body}${end < text.length ? '…' : ''}`);
}

/** Run a list of labelled regexes over text; return the first match per label. */
export interface LabelledPattern<L extends string = string> {
  label: L;
  re: RegExp;
}

export interface LabelledMatch<L extends string = string> {
  label: L;
  index: number;
  match: string;
}

export function matchAll<L extends string>(text: string, patterns: readonly LabelledPattern<L>[]): LabelledMatch<L>[] {
  const out: LabelledMatch<L>[] = [];
  for (const { label, re } of patterns) {
    const m = re.exec(text);
    if (m) out.push({ label, index: m.index, match: m[0] });
  }
  return out;
}

export function toolNameOf(target: { kind: string; tool?: ToolDescriptor; toolName?: string }): string | undefined {
  if (target.kind === 'tool_definition') return target.tool?.name;
  return target.toolName;
}

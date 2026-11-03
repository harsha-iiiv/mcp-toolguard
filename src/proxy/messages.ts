/**
 * Pure helpers for the proxy: JSON-RPC message classification and the synthesized block response.
 * No I/O here.
 */
import { BLOCK_MARKER, type JsonRpcId } from '../contracts.js';

export type ClassifiedMessage =
  | { type: 'request'; id: JsonRpcId; method: string; params: Record<string, unknown> | undefined }
  | { type: 'notification'; method: string; params: Record<string, unknown> | undefined }
  | { type: 'result'; id: JsonRpcId; result: Record<string, unknown> }
  | { type: 'error'; id: JsonRpcId | null; error: unknown }
  | { type: 'invalid' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isId(value: unknown): value is JsonRpcId {
  return typeof value === 'string' || typeof value === 'number';
}

/** Classify one decoded JSON-RPC message. Never throws. */
export function classifyMessage(message: unknown): ClassifiedMessage {
  if (!isRecord(message)) return { type: 'invalid' };
  const params = isRecord(message.params) ? message.params : undefined;
  if (typeof message.method === 'string') {
    if (isId(message.id)) return { type: 'request', id: message.id, method: message.method, params };
    if (message.id === undefined) return { type: 'notification', method: message.method, params };
    return { type: 'invalid' };
  }
  if ('error' in message) {
    return { type: 'error', id: isId(message.id) ? message.id : null, error: message.error };
  }
  if ('result' in message && isId(message.id)) {
    return { type: 'result', id: message.id, result: isRecord(message.result) ? message.result : {} };
  }
  return { type: 'invalid' };
}

/** Text of a synthesized block message: `${BLOCK_MARKER}: reason1; reason2`. */
export function blockText(reasons: readonly string[]): string {
  const list = reasons.length > 0 ? reasons : ['blocked by policy'];
  return `${BLOCK_MARKER}: ${list.join('; ')}`;
}

export interface BlockedToolResult {
  [key: string]: unknown;
  content: { type: 'text'; text: string }[];
  isError: true;
}

/** The CallToolResult the client receives instead of a blocked call or result. */
export function buildBlockResult(reasons: readonly string[]): BlockedToolResult {
  return { content: [{ type: 'text', text: blockText(reasons) }], isError: true };
}

/** A full JSON-RPC response (result, not error) carrying the block result for `id`. */
export function buildBlockResponse(
  id: JsonRpcId,
  reasons: readonly string[],
): { jsonrpc: '2.0'; id: JsonRpcId; result: BlockedToolResult } {
  return { jsonrpc: '2.0', id, result: buildBlockResult(reasons) };
}

/** Map key that keeps numeric 1 and string "1" distinct. */
export function idKey(id: JsonRpcId): string {
  return `${typeof id}:${String(id)}`;
}

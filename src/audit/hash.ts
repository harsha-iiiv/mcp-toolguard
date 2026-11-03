import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';

/** prevHash of the first event in a file. */
export const GENESIS_HASH = '0'.repeat(64);

/** sha256 hex over canonicalJson(event without `hash`). */
export function computeEventHash(event: Record<string, unknown>): string {
  const { hash: _ignored, ...rest } = event;
  return createHash('sha256').update(canonicalJson(rest), 'utf8').digest('hex');
}

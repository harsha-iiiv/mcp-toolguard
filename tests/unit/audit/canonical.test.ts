import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../../src/audit/index.js';

describe('canonicalJson', () => {
  it('sorts keys recursively and has no whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } })).toBe(
      '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  it('is stable regardless of insertion order', () => {
    const a = { x: 1, y: { p: true, q: null }, z: [1, 2, 3] };
    const b = { z: [1, 2, 3], y: { q: null, p: true }, x: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });

  it('keeps array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('drops undefined like JSON.stringify', () => {
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(canonicalJson([undefined, 1])).toBe('[null,1]');
    expect(canonicalJson(undefined)).toBe('null');
  });

  it('matches JSON.stringify for primitives and escapes', () => {
    for (const v of ['he said "hi"\n', 0, -1.5, true, false, null, 'ünïcødé  ']) {
      expect(canonicalJson(v)).toBe(JSON.stringify(v));
    }
    expect(canonicalJson(NaN)).toBe('null');
    expect(canonicalJson(new Date(0))).toBe('"1970-01-01T00:00:00.000Z"');
  });

  it('round-trips through JSON.parse', () => {
    const v = { k: [1, 'two', { three: 3 }], e: {} };
    expect(canonicalJson(JSON.parse(canonicalJson(v)))).toBe(canonicalJson(v));
  });
});

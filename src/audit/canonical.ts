/**
 * Deterministic JSON serialisation used for audit hashing.
 *
 * Rules: object keys sorted (code-unit order) recursively, no whitespace, `undefined` / function /
 * symbol values dropped from objects and turned into `null` inside arrays (as JSON.stringify does),
 * array order kept, `toJSON()` honoured, non-finite numbers become `null`, bigint becomes a string.
 * A top-level value that JSON.stringify would drop (undefined, function, symbol) serialises as "null"
 * so the function always returns a string. Cyclic input throws a TypeError (like JSON.stringify).
 */
export function canonicalJson(value: unknown): string {
  return serialize(value, new Set<object>()) ?? 'null';
}

function serialize(value: unknown, stack: Set<object>): string | undefined {
  if (value !== null && typeof value === 'object' && typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    value = (value as { toJSON: () => unknown }).toJSON();
  }
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      return Number.isFinite(value) ? JSON.stringify(value) : 'null';
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'undefined':
    case 'function':
    case 'symbol':
      return undefined;
  }
  if (value === null) return 'null';

  const obj = value as object;
  if (stack.has(obj)) throw new TypeError('canonicalJson: cyclic structure');
  stack.add(obj);
  try {
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => serialize(item, stack) ?? 'null').join(',') + ']';
    }
    const parts: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const s = serialize((obj as Record<string, unknown>)[key], stack);
      if (s !== undefined) parts.push(JSON.stringify(key) + ':' + s);
    }
    return '{' + parts.join(',') + '}';
  } finally {
    stack.delete(obj);
  }
}

// Sanity check that the contract constants are stable.
import { describe, expect, it } from 'vitest';
import { ACTION_ORDER, BLOCK_MARKER, RULE_IDS, SEVERITY_ORDER } from '../src/contracts.js';

describe('contracts', () => {
  it('has stable orderings and markers', () => {
    expect(SEVERITY_ORDER).toEqual(['low', 'medium', 'high', 'critical']);
    expect(ACTION_ORDER).toEqual(['allow', 'warn', 'block']);
    expect(BLOCK_MARKER).toBe('[mcp-toolguard] BLOCKED');
    expect(RULE_IDS.RUG_PULL).toBe('rug-pull');
  });
});

import { describe, expect, it } from 'vitest';
import { BLOCK_MARKER } from '../../../src/contracts.js';
import { blockText, buildBlockResponse, buildBlockResult, classifyMessage, idKey } from '../../../src/proxy/messages.js';

describe('classifyMessage', () => {
  it('classifies requests, notifications, results and errors', () => {
    expect(classifyMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' })).toEqual({
      type: 'request',
      id: 1,
      method: 'tools/list',
      params: undefined,
    });
    expect(classifyMessage({ jsonrpc: '2.0', method: 'notifications/initialized', params: { a: 1 } })).toEqual({
      type: 'notification',
      method: 'notifications/initialized',
      params: { a: 1 },
    });
    expect(classifyMessage({ jsonrpc: '2.0', id: 'x', result: { tools: [] } })).toEqual({
      type: 'result',
      id: 'x',
      result: { tools: [] },
    });
    expect(classifyMessage({ jsonrpc: '2.0', id: 2, error: { code: -1, message: 'no' } })).toEqual({
      type: 'error',
      id: 2,
      error: { code: -1, message: 'no' },
    });
  });

  it('treats junk as invalid', () => {
    expect(classifyMessage(null)).toEqual({ type: 'invalid' });
    expect(classifyMessage('x')).toEqual({ type: 'invalid' });
    expect(classifyMessage({ jsonrpc: '2.0' })).toEqual({ type: 'invalid' });
    expect(classifyMessage({ jsonrpc: '2.0', id: {}, method: 'm' })).toEqual({ type: 'invalid' });
  });
});

describe('block builders', () => {
  it('builds the contract block shape', () => {
    expect(blockText(['a', 'b'])).toBe(`${BLOCK_MARKER}: a; b`);
    expect(blockText([])).toBe(`${BLOCK_MARKER}: blocked by policy`);
    expect(buildBlockResult(['r'])).toEqual({ content: [{ type: 'text', text: `${BLOCK_MARKER}: r` }], isError: true });
    expect(buildBlockResponse(7, ['r'])).toEqual({ jsonrpc: '2.0', id: 7, result: buildBlockResult(['r']) });
  });

  it('keeps numeric and string ids distinct', () => {
    expect(idKey(1)).not.toBe(idKey('1'));
  });
});

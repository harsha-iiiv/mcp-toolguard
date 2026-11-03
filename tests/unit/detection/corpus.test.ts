import { describe, expect, it } from 'vitest';
import type { Finding, InspectionContext } from '../../../src/contracts.js';
import { createDetector, createPinStore } from '../../../src/detection/index.js';
import { BENIGN_CALLS, BENIGN_RESULTS, BENIGN_TOOLS } from './corpus.js';

const ctx: InspectionContext = { serverId: 'benign', direction: 'server_to_client' };
const serious = (fs: Finding[]) => fs.filter((f) => f.severity === 'high' || f.severity === 'critical');

describe('benign corpus', () => {
  it('has a realistic size', () => {
    expect(BENIGN_TOOLS.length).toBeGreaterThanOrEqual(15);
    expect(BENIGN_CALLS.length).toBeGreaterThanOrEqual(15);
  });

  it.each(BENIGN_TOOLS.map((t) => [t.name, t] as const))('tool definition %s produces no findings', (_name, tool) => {
    const detector = createDetector({ pins: createPinStore() });
    const findings = detector.inspect({ kind: 'tool_definition', tool }, ctx);
    expect(serious(findings)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it.each(BENIGN_CALLS.map((t, i) => [`${i}:${t.kind === 'tool_call' ? t.toolName : ''}`, t] as const))(
    'tool call %s produces no findings',
    (_n, target) => {
      const detector = createDetector({ pins: createPinStore() });
      expect(detector.inspect(target, { ...ctx, direction: 'client_to_server' })).toEqual([]);
    },
  );

  it.each(BENIGN_RESULTS.map((t, i) => [`${i}:${t.kind === 'tool_result' ? t.toolName : ''}`, t] as const))(
    'tool result %s produces no findings',
    (_n, target) => {
      const detector = createDetector({ pins: createPinStore() });
      expect(detector.inspect(target, ctx)).toEqual([]);
    },
  );

  it('re-listing identical tools never produces a rug-pull', () => {
    const detector = createDetector({ pins: createPinStore() });
    for (let round = 0; round < 3; round++) {
      for (const tool of BENIGN_TOOLS) {
        expect(detector.inspect({ kind: 'tool_definition', tool: structuredClone(tool) }, ctx)).toEqual([]);
      }
    }
  });
});

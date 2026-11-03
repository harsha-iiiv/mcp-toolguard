/** Turns secret matches over a set of strings into findings (shared by the two secret rules). */
import type { Finding, Severity } from '../../contracts.js';
import { findSecrets, maskSecret } from './secrets.js';
import type { StringHit } from './text.js';

const MAX_FINDINGS = 20;

export function secretFindings(
  hits: readonly StringHit[],
  ruleId: string,
  severity: Severity,
  describe: (label: string, location: string) => string,
): Finding[] {
  const findings: Finding[] = [];
  const dedupe = new Set<string>();
  for (const hit of hits) {
    if (hit.isKey) continue;
    for (const s of findSecrets(hit.value, hit.key)) {
      const k = `${hit.path}\u0000${s.id}\u0000${s.value}`;
      if (dedupe.has(k)) continue;
      dedupe.add(k);
      findings.push({
        ruleId,
        // Generic `password=…`/`token=…` assignments are common in config and dev .env files and are far
        // noisier than real token formats (AKIA…, ghp_…, sk-ant-…, PEM keys), so they only warn by default.
        severity: s.id === 'generic-assignment' ? 'medium' : severity,
        message: describe(s.label, hit.path),
        evidence: `${s.label}: ${maskSecret(s.value)}`,
        location: hit.path,
      });
      if (findings.length >= MAX_FINDINGS) return findings;
    }
  }
  return findings;
}

import type { DetectionRule } from '../../contracts.js';
import { commandInjectionRule } from './command-injection.js';
import { hiddenUnicodeRule } from './hidden-unicode.js';
import { resultInjectionRule } from './result-injection.js';
import { rugPullRule } from './rug-pull.js';
import { secretExfiltrationRule } from './secret-exfiltration.js';
import { secretInResultRule } from './secret-in-result.js';
import { sensitivePathRule } from './sensitive-path.js';
import { toolPoisoningRule } from './tool-poisoning.js';
import { toolShadowingRule } from './tool-shadowing.js';

/** One rule per RULE_IDS entry, in contract order. */
export const BUILTIN_RULES: readonly DetectionRule[] = [
  toolPoisoningRule,
  hiddenUnicodeRule,
  rugPullRule,
  toolShadowingRule,
  secretExfiltrationRule,
  sensitivePathRule,
  commandInjectionRule,
  resultInjectionRule,
  secretInResultRule,
];

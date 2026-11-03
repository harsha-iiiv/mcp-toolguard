/** secret-in-result — credentials inside a tool result headed for the model (server → client). */
import { RULE_IDS, type DetectionRule } from '../../contracts.js';
import { secretFindings } from '../helpers/secret-findings.js';
import { toolResultStrings } from '../helpers/text.js';

export const secretInResultRule: DetectionRule = {
  id: RULE_IDS.SECRET_IN_RESULT,
  description: 'Credentials, API keys or private keys in a tool result returned to the model.',
  defaultSeverity: 'high',
  appliesTo: ['tool_result'],
  detect(target) {
    if (target.kind !== 'tool_result') return [];
    return secretFindings(
      toolResultStrings(target.result),
      RULE_IDS.SECRET_IN_RESULT,
      'high',
      (label, loc) => `${label} returned in ${loc}; the model (and anything it calls next) would see it`,
    );
  },
};

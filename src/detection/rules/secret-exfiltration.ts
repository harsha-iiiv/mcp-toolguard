/**
 * secret-exfiltration — credentials inside tools/call arguments (client → server).
 *
 * Arguments are walked recursively (objects and arrays, depth ≤ 10). The property name is used as
 * a hint, so `{ "aws_secret_access_key": "<40 chars>" }` is caught even without a known prefix.
 * Evidence is masked to the first four characters.
 */
import { RULE_IDS, type DetectionRule } from '../../contracts.js';
import { secretFindings } from '../helpers/secret-findings.js';
import { walkStrings } from '../helpers/text.js';

export const secretExfiltrationRule: DetectionRule = {
  id: RULE_IDS.SECRET_EXFILTRATION,
  description: 'Credentials, API keys or private keys in tool-call arguments.',
  defaultSeverity: 'critical',
  appliesTo: ['tool_call'],
  detect(target) {
    if (target.kind !== 'tool_call') return [];
    return secretFindings(
      walkStrings(target.arguments, 'arguments'),
      RULE_IDS.SECRET_EXFILTRATION,
      'critical',
      (label, loc) => `${label} found in ${loc}; sending it to the MCP server may leak it`,
    );
  },
};

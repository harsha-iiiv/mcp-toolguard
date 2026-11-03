// Audit log public API. Export names fixed by src/contracts.ts.
import type { CanonicalJson, CreateAuditLogger, RedactSecrets, VerifyAuditLog } from '../contracts.js';
import { canonicalJson as canonicalJsonImpl } from './canonical.js';
import { createAuditLogger as createAuditLoggerImpl, type InspectableAuditLogger } from './logger.js';
import { redactSecrets as redactSecretsImpl } from './redact.js';
import { verifyAuditLog as verifyAuditLogImpl } from './verify.js';

export type { InspectableAuditLogger } from './logger.js';

/**
 * Contract-compatible (assignable to CreateAuditLogger). The returned logger additionally exposes
 * `events()` (in-memory events) and `file`, for tests and diagnostics.
 */
export const createAuditLogger: (opts: Parameters<CreateAuditLogger>[0]) => InspectableAuditLogger =
  createAuditLoggerImpl;
export const verifyAuditLog: VerifyAuditLog = verifyAuditLogImpl;
export const redactSecrets: RedactSecrets = redactSecretsImpl;
export const canonicalJson: CanonicalJson = canonicalJsonImpl;

// Compile-time check that the exported factory still satisfies the contract type.
const _contractCheck: CreateAuditLogger = createAuditLogger;
void _contractCheck;

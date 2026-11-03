// Policy engine public API; see src/contracts.ts "Module export map".
import type { CreatePolicyEngine, DefaultPolicy, LoadPolicy, ValidatePolicy } from '../contracts.js';
import { defaultPolicy as defaultPolicyImpl } from './defaults.js';
import { createPolicyEngine as createPolicyEngineImpl } from './engine.js';
import { loadPolicy as loadPolicyImpl } from './load.js';
import { validatePolicy as validatePolicyImpl } from './validate.js';
export { PolicyError } from '../contracts.js';

export const defaultPolicy: DefaultPolicy = defaultPolicyImpl;
export const validatePolicy: ValidatePolicy = validatePolicyImpl;
export const loadPolicy: LoadPolicy = loadPolicyImpl;
export const createPolicyEngine: CreatePolicyEngine = createPolicyEngineImpl;

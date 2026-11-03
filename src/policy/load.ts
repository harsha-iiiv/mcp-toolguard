import fs from 'node:fs';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { PolicyError, type ToolguardPolicy } from '../contracts.js';
import { expandHome } from './paths.js';
import { validatePolicy } from './validate.js';

export const DEFAULT_POLICY_FILES = ['toolguard.yaml', 'toolguard.yml', 'toolguard.json'] as const;

function parseJson(text: string, file: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch (err) {
    throw new PolicyError(`Failed to parse JSON policy ${file}`, [(err as Error).message]);
  }
}

function parseYaml(text: string, file: string): unknown {
  const doc = parseDocument(text, { prettyErrors: true, uniqueKeys: true });
  if (doc.errors.length > 0) {
    const issues = doc.errors.map((e) => {
      const pos = e.linePos?.[0];
      const firstLine = e.message.split('\n')[0] ?? e.message;
      return pos ? `line ${pos.line}, column ${pos.col}: ${firstLine.replace(/ at line \d+, column \d+:?$/, '')}` : firstLine;
    });
    throw new PolicyError(`Failed to parse YAML policy ${file}`, issues);
  }
  return doc.toJS() as unknown;
}

function parseByExtension(text: string, file: string): unknown {
  const ext = path.extname(file).toLowerCase();
  if (ext === '.yaml' || ext === '.yml') return parseYaml(text, file);
  if (ext === '.json') return parseJson(text, file);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return parseYaml(text, file);
  }
}

function loadFile(abs: string): ToolguardPolicy {
  let text: string;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    const msg = code === 'ENOENT' ? `Policy file not found: ${abs}` : `Cannot read policy file ${abs}`;
    throw new PolicyError(msg, [(err as Error).message]);
  }
  const raw = parseByExtension(text, abs);
  try {
    return validatePolicy(raw);
  } catch (err) {
    if (err instanceof PolicyError) throw new PolicyError(`Invalid policy ${abs}`, err.issues);
    throw err;
  }
}

/**
 * Load a policy. With `file`, read exactly that file (relative to cwd, '~' expanded). Without it,
 * look for toolguard.yaml / toolguard.yml / toolguard.json in cwd, else use the built-in defaults.
 */
export function loadPolicy(file?: string, cwd: string = process.cwd()): { policy: ToolguardPolicy; source: string } {
  if (file !== undefined && file !== '') {
    const abs = path.resolve(cwd, expandHome(file));
    return { policy: loadFile(abs), source: abs };
  }
  for (const name of DEFAULT_POLICY_FILES) {
    const abs = path.resolve(cwd, name);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) return { policy: loadFile(abs), source: abs };
  }
  return { policy: validatePolicy(undefined), source: 'builtin' };
}

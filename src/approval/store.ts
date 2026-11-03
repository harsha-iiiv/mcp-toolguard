/**
 * Persistent one-time human approvals (contracts.ts ApprovalStore).
 *
 * File format: { "version": 1, "requests": ApprovalRequest[] }, written atomically (tmp file + rename)
 * with mode 0600. The file is re-read on every check/approve/deny/list because `mcp-toolguard approve`
 * runs in a different process from the proxy that created the request. No file = in-memory store.
 */
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type {
  ApprovalRequest,
  ApprovalStatus,
  ApprovalStore,
  AuditLogger,
  Policy,
  ToolCall,
  Verdict,
} from '../contracts.js';
import { canonicalJson } from '../audit/index.js';

/** Pending requests older than this are ignored by check() and shown as expired by the CLI. */
export const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
/** Finished (used/denied) and expired requests older than this are dropped on the next write. */
const RETAIN_MS = 30 * 24 * 60 * 60 * 1000;
const STATUSES: readonly ApprovalStatus[] = ['pending', 'approved', 'denied', 'used'];

export interface ApprovalStoreOptions {
  /** Store path ('~' expands). Undefined = in-memory (tests, or no persistence wanted). */
  file?: string;
  /** Lifecycle events (approval_requested/granted/denied/used) are written here when given. */
  audit?: AuditLogger;
  /** serverId used for audit events when the request itself has none. Default 'mcp-toolguard'. */
  serverIdForAudit?: string;
  /** sessionId used for audit events. Default 'approval'. */
  sessionIdForAudit?: string;
  /** Clock override for tests (ms since epoch). */
  now?: () => number;
}

export interface FileApprovalStore extends ApprovalStore {
  /** Resolved store path, or undefined when in memory. */
  readonly file: string | undefined;
  /** True if this request is pending and older than the 24h TTL. */
  isExpired(req: ApprovalRequest): boolean;
  /** Look a request up by id (undefined if unknown). */
  get(id: string): ApprovalRequest | undefined;
}

export class ApprovalError extends Error {
  constructor(
    message: string,
    public readonly code: 'not_found' | 'not_pending' | 'expired' | 'corrupt',
  ) {
    super(message);
    this.name = 'ApprovalError';
  }
}

function expandHome(file: string): string {
  if (file === '~') return homedir();
  if (file.startsWith('~/') || file.startsWith('~\\')) return join(homedir(), file.slice(2));
  return file;
}

/** '*' = any run (incl. empty), '?' = one char, everything else literal, anchored. */
export function globMatch(glob: string, name: string): boolean {
  let src = '';
  for (const ch of glob) {
    if (ch === '*') src += '.*';
    else if (ch === '?') src += '.';
    else src += ch.replace(/[.+^${}()|[\]\\/-]/g, '\\$&');
  }
  return new RegExp(`^${src}$`, 's').test(name);
}

export function hashToolCall(serverId: string, toolName: string, args: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalJson({ serverId, toolName, arguments: args })).digest('hex');
}

function corrupt(path: string, why: string): ApprovalError {
  return new ApprovalError(
    `Approval file ${path} is corrupt (${why}). Fix or delete it; pending approvals in it will be lost.`,
    'corrupt',
  );
}

function isRequest(v: unknown): v is ApprovalRequest {
  if (!v || typeof v !== 'object') return false;
  const r = v as Record<string, unknown>;
  const tc = r['toolCall'] as Record<string, unknown> | undefined;
  return (
    typeof r['id'] === 'string' &&
    typeof r['reason'] === 'string' &&
    typeof r['createdAt'] === 'string' &&
    STATUSES.includes(r['status'] as ApprovalStatus) &&
    (r['decidedAt'] === undefined || typeof r['decidedAt'] === 'string') &&
    !!tc &&
    typeof tc === 'object' &&
    typeof tc['serverId'] === 'string' &&
    typeof tc['toolName'] === 'string' &&
    typeof tc['hash'] === 'string' &&
    !!tc['arguments'] &&
    typeof tc['arguments'] === 'object' &&
    !Array.isArray(tc['arguments'])
  );
}

function parseFile(path: string, raw: string): ApprovalRequest[] {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw corrupt(path, `invalid JSON: ${(err as Error).message}`);
  }
  if (!data || typeof data !== 'object' || (data as Record<string, unknown>)['version'] !== 1) {
    throw corrupt(path, 'expected {"version": 1, "requests": [...]}');
  }
  const requests = (data as Record<string, unknown>)['requests'];
  if (!Array.isArray(requests)) throw corrupt(path, '"requests" must be an array');
  requests.forEach((r, i) => {
    if (!isRequest(r)) throw corrupt(path, `requests[${i}] is not a valid approval request`);
  });
  return requests as ApprovalRequest[];
}

export function createApprovalStore(opts: ApprovalStoreOptions = {}): FileApprovalStore {
  const path = opts.file === undefined || opts.file === '' ? undefined : resolve(expandHome(opts.file));
  const now = opts.now ?? Date.now;
  let memory: ApprovalRequest[] = [];

  const load = (): ApprovalRequest[] => {
    if (!path) return memory;
    if (!existsSync(path)) return [];
    return parseFile(path, readFileSync(path, 'utf8'));
  };

  const save = (requests: ApprovalRequest[]): void => {
    const cutoff = now() - RETAIN_MS;
    const kept = requests.filter(
      (r) => r.status === 'approved' || Date.parse(r.decidedAt ?? r.createdAt) >= cutoff || Number.isNaN(Date.parse(r.createdAt)),
    );
    if (!path) {
      memory = kept;
      return;
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      writeFileSync(tmp, `${JSON.stringify({ version: 1, requests: kept }, null, 2)}\n`, { mode: 0o600 });
      renameSync(tmp, path);
      chmodSync(path, 0o600);
    } catch (err) {
      try {
        unlinkSync(tmp);
      } catch {
        /* tmp may not exist */
      }
      throw err;
    }
  };

  const isExpired = (r: ApprovalRequest): boolean => {
    if (r.status !== 'pending') return false;
    const t = Date.parse(r.createdAt);
    return Number.isNaN(t) || now() - t > APPROVAL_TTL_MS;
  };

  const audit = (event: string, r: ApprovalRequest): void => {
    if (!opts.audit) return;
    try {
      opts.audit.log({
        sessionId: opts.sessionIdForAudit ?? 'approval',
        serverId: r.toolCall.serverId || opts.serverIdForAudit || 'mcp-toolguard',
        kind: 'lifecycle',
        event,
        toolName: r.toolCall.toolName,
        data: { id: r.id, toolName: r.toolCall.toolName },
      });
    } catch {
      /* AuditLogger.log must not throw; never let auditing break approvals */
    }
  };

  const newId = (taken: ReadonlySet<string>): string => {
    for (;;) {
      const id = randomBytes(3).toString('hex');
      if (!taken.has(id)) return id;
    }
  };

  const decide = (id: string, status: 'approved' | 'denied'): ApprovalRequest => {
    const requests = load();
    const r = requests.find((x) => x.id === id);
    if (!r) throw new ApprovalError(`no approval request with id '${id}'`, 'not_found');
    if (r.status !== 'pending') throw new ApprovalError(`approval request '${id}' is already ${r.status}`, 'not_pending');
    if (isExpired(r)) {
      throw new ApprovalError(
        `approval request '${id}' expired (older than 24h); retry the tool call to create a new request`,
        'expired',
      );
    }
    r.status = status;
    r.decidedAt = new Date(now()).toISOString();
    save(requests);
    audit(status === 'approved' ? 'approval_granted' : 'approval_denied', r);
    return { ...r };
  };

  return {
    file: path,
    isExpired,

    get(id) {
      const r = load().find((x) => x.id === id);
      return r ? { ...r } : undefined;
    },

    check(call: ToolCall, policy: Policy): Verdict | null {
      const globs = policy.approval?.tools ?? [];
      if (!globs.some((g) => globMatch(g, call.toolName))) return null;

      const hash = hashToolCall(call.serverId, call.toolName, call.arguments);
      const requests = load();
      const approved = requests.find((r) => r.toolCall.hash === hash && r.status === 'approved');
      if (approved) {
        approved.status = 'used';
        approved.decidedAt = new Date(now()).toISOString();
        save(requests);
        audit('approval_used', approved);
        return null;
      }

      let pending = requests.find((r) => r.toolCall.hash === hash && r.status === 'pending' && !isExpired(r));
      if (!pending) {
        const id = newId(new Set(requests.map((r) => r.id)));
        pending = {
          id,
          toolCall: { serverId: call.serverId, toolName: call.toolName, arguments: call.arguments, hash },
          reason: `tool '${call.toolName}' requires human approval`,
          status: 'pending',
          createdAt: new Date(now()).toISOString(),
        };
        requests.push(pending);
        save(requests);
        audit('approval_requested', pending);
      }
      return {
        action: 'require_approval',
        ruleId: 'approval',
        severity: 'medium',
        reason:
          `tool '${call.toolName}' requires human approval (request ${pending.id}). ` +
          `Ask the user to run: mcp-toolguard approve ${pending.id} (or: mcp-toolguard deny ${pending.id}), then retry the same call`,
      };
    },

    approve: (id) => decide(id, 'approved'),
    deny: (id) => decide(id, 'denied'),

    list(status) {
      return load()
        .filter((r) => status === undefined || r.status === status)
        .map((r) => ({ ...r }));
    },
  };
}

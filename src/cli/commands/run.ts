import { randomUUID } from 'node:crypto';
import { TOOLGUARD_VERSION } from '../../contracts.js';
import type { AuditLogger, ToolguardPolicy, ProxyOptions, RulePlugin } from '../../contracts.js';
import { startProxy } from '../../proxy/index.js';
import { createPolicyEngine } from '../../policy/index.js';
import { createDetector, createPinStore } from '../../detection/index.js';
import { createAuditLogger } from '../../audit/index.js';
import { createUpstreamTransport, parseUpstreamUrl, TRANSPORT_KINDS, type TransportKind } from '../../transports/index.js';
import { createSpendTracker } from '../../rules/spend.js';
import { createApprovalStore } from '../../approval/index.js';
import { createBaselinePlugin, type BaselinePlugin } from '../../learning/index.js';
import { loadPlugins } from '../../plugins/index.js';
import { bool, parseArgs, str } from '../args.js';
import { defaultServerId, loadPolicyFrom, reportError } from '../common.js';
import { UsageError, resolveUserPath, stringEnv, type CliIo } from '../io.js';

const SPEC = {
  policy: 'string',
  audit: 'string',
  pins: 'string',
  'server-id': 'string',
  monitor: 'boolean',
  learning: 'boolean',
  plugins: 'string',
  transport: 'string',
  url: 'string',
} as const;

/** Repeatable option, pulled out of argv before parseArgs (which keeps only the last value). */
const HEADER_OPTION = 'header';

/**
 * Split repeatable `--header 'Name: value'` options out of argv. Only options before the server
 * command count (stop at `--` or the first positional, like parseArgs in command mode).
 */
export function extractHeaders(argv: readonly string[]): { rest: string[]; headers: string[] } {
  const rest: string[] = [];
  const headers: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === '--' || !arg.startsWith('-') || arg === '-') {
      rest.push(...argv.slice(i));
      break;
    }
    if (arg === `--${HEADER_OPTION}`) {
      const next = argv[i + 1];
      if (next === undefined || next === '--' || next === '') {
        throw new UsageError(`option '--${HEADER_OPTION}' requires a value`, 'run');
      }
      headers.push(next);
      i++;
      continue;
    }
    if (arg.startsWith(`--${HEADER_OPTION}=`)) {
      const value = arg.slice(HEADER_OPTION.length + 3);
      if (value === '') throw new UsageError(`option '--${HEADER_OPTION}' requires a value`, 'run');
      headers.push(value);
      continue;
    }
    rest.push(arg);
    // Keep a string option's separate value with it so it is not mistaken for a positional.
    const key = arg.startsWith('--') && !arg.includes('=') ? arg.slice(2) : undefined;
    const next = argv[i + 1];
    if (key !== undefined && (SPEC as Record<string, string>)[key] === 'string' && next !== undefined && next !== '--') {
      rest.push(next);
      i++;
    }
  }
  return { rest, headers };
}

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Parse 'Name: value' strings into a header record. Usage error on malformed input. */
export function parseHeaders(raw: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of raw) {
    const colon = h.indexOf(':');
    const name = colon === -1 ? '' : h.slice(0, colon).trim();
    if (!name || !HEADER_NAME.test(name)) {
      throw new UsageError(`invalid --header '${name || h}' (expected 'Name: value')`, 'run');
    }
    const value = h.slice(colon + 1).trim();
    // eslint-disable-next-line no-control-regex
    if (/[\r\n\0]/.test(value)) throw new UsageError(`invalid --header '${name}': value contains a control character`, 'run');
    out[name] = value;
  }
  return out;
}

/** URL for display: no userinfo, no query string (either may carry credentials). */
function displayUrl(url: URL): string {
  return `${url.protocol}//${url.host}${url.pathname}${url.search ? '?…' : ''}`;
}

/**
 * `mcp-toolguard run`. During run, process stdout is the MCP protocol channel: this function never
 * writes to io.stdout. Every human message goes to io.stderr.
 *
 * The client side is always our stdio. The upstream is a child process (`--transport stdio`, default,
 * `-- <command>`) or a remote server (`--transport http|sse --url <url> [--header 'Name: value']...`).
 */
export async function runCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { rest, headers: rawHeaders } = extractHeaders(argv);
  const parsed = parseArgs(rest, SPEC, { commandMode: true, name: 'run' });
  const transportOpt = str(parsed, 'transport') ?? 'stdio';
  if (!(TRANSPORT_KINDS as readonly string[]).includes(transportOpt)) {
    throw new UsageError(`invalid --transport '${transportOpt}' (expected ${TRANSPORT_KINDS.join('|')})`, 'run');
  }
  const transport = transportOpt as TransportKind;
  const urlOpt = str(parsed, 'url');
  const [command, ...args] = parsed.command ?? [];

  let upstreamUrl: URL | undefined;
  let headers: Record<string, string> = {};
  if (transport === 'stdio') {
    if (urlOpt !== undefined) throw new UsageError('--url needs --transport http or sse', 'run');
    if (rawHeaders.length > 0) throw new UsageError('--header needs --transport http or sse', 'run');
    if (command === undefined || command === '') {
      throw new UsageError('missing server command (put it after --)', 'run');
    }
  } else {
    if (parsed.command !== undefined && parsed.command.length > 0) {
      throw new UsageError(`--transport ${transport} connects to --url; do not also pass a server command`, 'run');
    }
    if (urlOpt === undefined) throw new UsageError(`--transport ${transport} requires --url <url>`, 'run');
    try {
      upstreamUrl = parseUpstreamUrl(urlOpt);
    } catch (err) {
      throw new UsageError(`--url: ${err instanceof Error ? err.message : String(err)}`, 'run');
    }
    headers = parseHeaders(rawHeaders);
  }

  let policy: ToolguardPolicy;
  let source: string;
  try {
    ({ policy, source } = loadPolicyFrom(str(parsed, 'policy'), io));
  } catch (err) {
    reportError(io, err);
    return 1;
  }

  const auditFile = str(parsed, 'audit');
  const pinsFile = str(parsed, 'pins');
  policy = {
    ...policy,
    mode: bool(parsed, 'monitor') ? 'monitor' : policy.mode,
    audit: { ...policy.audit, file: auditFile !== undefined ? resolveUserPath(auditFile, io.cwd) : policy.audit.file },
    pins: { ...policy.pins, file: pinsFile !== undefined ? resolveUserPath(pinsFile, io.cwd) : policy.pins.file },
  };

  // Default server id: the URL host (host:port when a port is given) for http/sse, else from the command.
  const serverId = str(parsed, 'server-id') ?? (upstreamUrl ? upstreamUrl.host : defaultServerId(command as string, args));
  const sessionId = randomUUID();

  let audit: AuditLogger | undefined;
  let learning: BaselinePlugin | undefined;
  try {
    const pins = createPinStore(policy.pins.file);
    const engine = createPolicyEngine(policy);
    const detector = createDetector({ pins, disabledRules: engine.disabledRules() });
    audit = createAuditLogger({ file: policy.audit.file, redact: policy.audit.redact });

    const target = upstreamUrl ? `${transport} ${displayUrl(upstreamUrl)}` : [command, ...args].join(' ');
    const cap = policy.spend?.maxSpendPerTaskUsd ?? null;
    io.stderr.write(
      `mcp-toolguard ${TOOLGUARD_VERSION}: guarding '${serverId}' (${target})\n` +
        `  policy: ${source}\n` +
        `  mode:   ${policy.mode}\n` +
        `  audit:  ${policy.audit.file}\n` +
        `  pins:   ${policy.pins.file}\n` +
        // Header names only: values are usually credentials.
        (Object.keys(headers).length > 0 ? `  headers: ${Object.keys(headers).join(', ')}\n` : '') +
        (cap !== null ? `  spend:  cap $${cap} per task\n` : '') +
        (policy.approval.tools.length > 0
          ? `  approval: ${policy.approval.tools.join(', ')} (${policy.approval.file})\n`
          : ''),
    );

    const plugins: RulePlugin[] = [];
    if (cap !== null) plugins.push(createSpendTracker(policy));

    // Learning: off by default; warns only, never blocks.
    if (bool(parsed, 'learning') || policy.learning.enabled) {
      learning = createBaselinePlugin({ file: policy.learning.file, minSamples: policy.learning.minSamples });
      plugins.push(learning);
      io.stderr.write(`  learning: on (${policy.learning.file}, warn only)\n`);
    }

    // v1.0 third-party plugins: in-process code with your permissions, so opt-in only.
    const pluginFlag = str(parsed, 'plugins');
    const pluginDir = pluginFlag ?? (policy.plugins.enabled ? policy.plugins.dir : undefined);
    if (pluginDir !== undefined) {
      const loaded = await loadPlugins(resolveUserPath(pluginDir, io.cwd), { cwd: io.cwd });
      plugins.push(...loaded);
      io.stderr.write(`  plugins: ${loaded.length ? loaded.map((p) => p.id).join(', ') : 'none found'} (${pluginDir})\n`);
    }

    const base: ProxyOptions = { serverId, sessionId, policy: engine, detector, audit };
    const proxyOptions: ProxyOptions = upstreamUrl
      ? {
          ...base,
          transports: {
            server: createUpstreamTransport({ transport: transport as 'http' | 'sse', url: upstreamUrl, headers }),
          },
        }
      : { ...base, command: command as string, args, env: stringEnv(io.env), cwd: io.cwd };
    if (plugins.length > 0) proxyOptions.plugins = plugins;
    if (policy.approval.tools.length > 0) {
      proxyOptions.approvals = createApprovalStore({
        file: policy.approval.file,
        audit,
        serverIdForAudit: serverId,
        sessionIdForAudit: sessionId,
      });
    }

    const handle = await startProxy(proxyOptions);

    let signalled = false;
    const onSignal = (signal: NodeJS.Signals): void => {
      if (signalled) {
        // Second signal: the user wants out now.
        process.exit(signal === 'SIGINT' ? 130 : 143);
      }
      signalled = true;
      io.stderr.write(`mcp-toolguard: ${signal} received, shutting down\n`);
      handle.close().catch((err: unknown) => reportError(io, err));
    };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    try {
      return await handle.done;
    } finally {
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
    }
  } catch (err) {
    reportError(io, err);
    return 1;
  } finally {
    try {
      learning?.flush();
    } catch (err) {
      reportError(io, err, 'mcp-toolguard: failed to save learning baseline: ');
    }
    if (audit) {
      try {
        await audit.close();
      } catch (err) {
        reportError(io, err, 'mcp-toolguard: failed to close audit log: ');
      }
    }
  }
}

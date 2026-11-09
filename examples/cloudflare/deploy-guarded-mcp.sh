#!/usr/bin/env bash
# deploy-guarded-mcp.sh
#
# Interactive: OpenAPI spec -> MCP server on Cloudflare Workers (openapi-mcp-generator)
#              -> secrets -> deploy -> verify -> mcp-toolguard policy -> Claude Desktop / Cursor.
#
#   bash deploy-guarded-mcp.sh
#
# Everything is asked while it runs. Secrets are read with hidden input and go straight to
# `wrangler secret put`; they are never written into the project. macOS (bash 3.2) and Linux.

set -euo pipefail

GENERATOR_VERSION="${GENERATOR_VERSION:-5.0.1}"
TOOLGUARD_VERSION="${TOOLGUARD_VERSION:-0.2}"
DEFAULT_SPEC="https://raw.githubusercontent.com/resend/resend-openapi/main/resend.yaml"

# ── look and feel ────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; M=$'\033[35m'; N=$'\033[0m'
else
  B= D= R= G= Y= C= M= N=
fi
TOTAL_STEPS=9
STEP=0
LOG_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t guarded-mcp)"

banner() {
  printf '\n%s' "$C$B"
  printf '  ┌──────────────────────────────────────────────────────────┐\n'
  printf '  │   OpenAPI  →  MCP server on Cloudflare  →  mcp-toolguard   │\n'
  printf '  └──────────────────────────────────────────────────────────┘%s\n' "$N"
  printf '  %sGenerates, deploys, secures and connects an MCP server, one step at a time.%s\n' "$D" "$N"
}
step()  { STEP=$((STEP + 1)); printf '\n%s%s[%d/%d]%s %s%s%s\n' "$M" "$B" "$STEP" "$TOTAL_STEPS" "$N" "$B" "$1" "$N"; }
ok()    { printf '  %s✔%s %s\n' "$G" "$N" "$1"; }
info()  { printf '  %s•%s %s\n' "$C" "$N" "$1"; }
warn()  { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
fail()  { printf '\n  %s✖ %s%s\n' "$R$B" "$1" "$N" >&2; [ -n "${2:-}" ] && [ -f "$2" ] && { printf '%s' "$D" >&2; tail -n 25 "$2" >&2; printf '%s\n' "$N" >&2; }; exit 1; }
hr()    { printf '  %s──────────────────────────────────────────────────────────%s\n' "$D" "$N"; }

# Read one line from the terminal (or from stdin when there is no terminal, e.g. piped answers).
_read() {
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then IFS= read -r "$@" </dev/tty
  else local __rc=0; IFS= read -r "$@" || __rc=$?; printf '\n'; return $__rc; fi
}

# ask VAR "Question" "default"
ask() {
  local __var="$1" __q="$2" __def="${3:-}" __ans
  if [ -n "$__def" ]; then
    printf '  %s?%s %s %s[%s]%s ' "$C$B" "$N" "$__q" "$D" "$__def" "$N"
  else
    printf '  %s?%s %s ' "$C$B" "$N" "$__q"
  fi
  _read __ans || __ans=""
  [ -z "$__ans" ] && __ans="$__def"
  printf -v "$__var" '%s' "$__ans"
}

# ask_yn VAR "Question" y|n
ask_yn() {
  local __var="$1" __q="$2" __def="${3:-y}" __ans __hint
  [ "$__def" = y ] && __hint="Y/n" || __hint="y/N"
  while true; do
    printf '  %s?%s %s %s(%s)%s ' "$C$B" "$N" "$__q" "$D" "$__hint" "$N"
    _read __ans || __ans=""
    [ -z "$__ans" ] && __ans="$__def"
    case "$__ans" in
      y|Y|yes|YES) printf -v "$__var" y; return ;;
      n|N|no|NO) printf -v "$__var" n; return ;;
      *) warn "Please answer y or n." ;;
    esac
  done
}

# ask_secret VAR "Question"   (hidden input)
ask_secret() {
  local __var="$1" __q="$2" __ans
  printf '  %s🔑%s %s %s(input hidden)%s ' "$Y" "$N" "$__q" "$D" "$N"
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then IFS= read -rs __ans </dev/tty || __ans=""; else IFS= read -r __ans || __ans=""; fi
  printf '\n'
  printf -v "$__var" '%s' "$__ans"
}

# run "message" logfile command...   (spinner while it runs, log tail on failure)
run() {
  local msg="$1" log="$2"; shift 2
  "$@" >"$log" 2>&1 &
  local pid=$! i=0
  local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do
      i=$(((i + 1) % 10))
      printf '\r  %s%s%s %s' "$C" "${frames[$i]}" "$N" "$msg"
      sleep 0.1
    done
    printf '\r\033[K'
  fi
  if wait "$pid"; then ok "$msg"; else fail "$msg failed" "$log"; fi
}

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 not found. $2"; }

# ── 0. preflight ─────────────────────────────────────────────────────────────
banner
need node "Install Node.js 22+ (https://nodejs.org or: brew install node)."
need npm "It ships with Node.js."
need npx "It ships with npm."
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 22 ] || fail "Node $(node -v) is too old: openapi-mcp-generator needs Node 22.19+ (brew upgrade node / nvm install 22)."
NODE_BIN="$(command -v node)"
printf '  %sNode %s · generator %s · toolguard %s · logs in %s%s\n' "$D" "$(node -v)" "$GENERATOR_VERSION" "$TOOLGUARD_VERSION" "$LOG_DIR" "$N"

# ── 1. questions ─────────────────────────────────────────────────────────────
step "A few questions (Enter accepts the default in brackets)"
ask SPEC "OpenAPI spec (URL or file path):" "$DEFAULT_SPEC"
SPEC_BASE="$(basename "${SPEC%%\?*}")"; SPEC_BASE="${SPEC_BASE%.*}"
DEFAULT_NAME="$(printf '%s' "$SPEC_BASE" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | sed 's/--*/-/g; s/^-//; s/-$//')-mcp"
ask SERVER_NAME "Server / Worker name:" "$DEFAULT_NAME"
SERVER_NAME="$(printf '%s' "$SERVER_NAME" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | sed 's/--*/-/g; s/^-//; s/-$//')"
ask PROJECT_DIR "Project folder:" "./$SERVER_NAME"
PROJECT_DIR="${PROJECT_DIR/#\~/$HOME}"

echo
info "${B}Inbound auth${N} makes clients send a token you choose. Without it, anyone who finds"
info "the Worker URL can call every tool with ${B}your${N} API key (send email, delete data, ...)."
ask_yn INBOUND "Turn on inbound auth (--inbound-auth bearer)?" y
if [ "$INBOUND" = n ]; then
  warn "Your Worker will be callable by anyone with its URL."
  ask_yn REALLY "Continue WITHOUT inbound auth?" n
  [ "$REALLY" = y ] || INBOUND=y
fi

ask_yn DEPLOY "Deploy to Cloudflare now (you'll log in if needed)?" y

echo
info "${B}mcp-toolguard${N} runs between your MCP client and the server: only the generated tools"
info "are allowed, calls that change data wait for your approval, secrets in arguments are blocked."
ask_yn TOOLGUARD "Add mcp-toolguard?" y
TG_MODE=enforce; TG_BLOCK_DESTRUCTIVE=n; TG_DENY=""
if [ "$TOOLGUARD" = y ]; then
  ask_yn TG_MONITOR "Start in monitor mode (log and warn only, never block)?" n
  [ "$TG_MONITOR" = y ] && TG_MODE=monitor
  ask_yn TG_BLOCK_DESTRUCTIVE "Block destructive tools (DELETE/PUT/PATCH) instead of asking for approval?" n
  ask TG_DENY "Extra tools to always block (comma-separated globs, optional):" ""
fi

ADD_CLAUDE=n; ADD_CURSOR=n
case "$(uname -s)" in
  Darwin) CLAUDE_CFG="$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
  *) CLAUDE_CFG="${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json" ;;
esac
CURSOR_CFG="$HOME/.cursor/mcp.json"
if [ "$TOOLGUARD" = y ]; then
  echo
  ask_yn ADD_CLAUDE "Add the guarded server to Claude Desktop?" y
  ask_yn ADD_CURSOR "Add the guarded server to Cursor?" y
fi

echo; hr
printf '  %sSummary%s\n' "$B" "$N"
printf '  %-14s %s\n' "Spec" "$SPEC" "Name" "$SERVER_NAME" "Folder" "$PROJECT_DIR"
printf '  %-14s %s\n' "Inbound auth" "$([ "$INBOUND" = y ] && echo "${G}on${N}" || echo "${R}off${N}")"
printf '  %-14s %s\n' "Deploy" "$DEPLOY"
printf '  %-14s %s\n' "mcp-toolguard" "$([ "$TOOLGUARD" = y ] && echo "on ($TG_MODE)" || echo off)"
printf '  %-14s %s\n' "Clients" "$([ "$ADD_CLAUDE" = y ] && printf 'Claude Desktop ')$([ "$ADD_CURSOR" = y ] && printf 'Cursor')"
hr
ask_yn GO "Start?" y
[ "$GO" = y ] || { info "Nothing done."; exit 0; }

# ── 2. generate ──────────────────────────────────────────────────────────────
step "Generate the Cloudflare Worker"
if [ -e "$PROJECT_DIR" ] && [ -n "$(ls -A "$PROJECT_DIR" 2>/dev/null)" ]; then
  warn "$PROJECT_DIR already exists and is not empty."
  ask_yn OVERWRITE "Regenerate into it (--force; your src/auth.ts and secrets are kept)?" n
  [ "$OVERWRITE" = y ] || fail "Choose another project folder and run again."
  FORCE=(--force)
else
  FORCE=()
fi
GEN_ARGS=(--input "$SPEC" --output "$PROJECT_DIR" --transport cloudflare-worker --server-name "$SERVER_NAME")
[ "$INBOUND" = y ] && GEN_ARGS+=(--inbound-auth bearer)
run "openapi-mcp-generator@$GENERATOR_VERSION" "$LOG_DIR/generate.log" \
  npx -y "openapi-mcp-generator@$GENERATOR_VERSION" "${GEN_ARGS[@]}" ${FORCE[@]+"${FORCE[@]}"}
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
TOOL_COUNT="$(grep -cE '^    name: "' "$PROJECT_DIR/src/tools.ts" || true)"
ok "$TOOL_COUNT tools in $PROJECT_DIR"

# ── 3. install ───────────────────────────────────────────────────────────────
step "Install dependencies"
run "npm install" "$LOG_DIR/install.log" npm --prefix "$PROJECT_DIR" install --no-audit --no-fund
if [ "$TOOLGUARD" = y ]; then
  # A local install lets Claude Desktop / Cursor start it with an absolute node path
  # (GUI apps do not see the PATH from your shell, e.g. nvm).
  run "mcp-toolguard-cli@$TOOLGUARD_VERSION" "$LOG_DIR/install-toolguard.log" \
    npm --prefix "$PROJECT_DIR" install --no-audit --no-fund --save-dev "mcp-toolguard-cli@$TOOLGUARD_VERSION"
fi
run "typecheck" "$LOG_DIR/typecheck.log" npm --prefix "$PROJECT_DIR" run typecheck

# ── 4. cloudflare login + deploy ─────────────────────────────────────────────
step "Deploy to Cloudflare"
WORKER_URL=""
if [ "$DEPLOY" = y ]; then
  if (cd "$PROJECT_DIR" && npx wrangler whoami 2>/dev/null | grep -qi "associated with the email\|You are logged in"); then
    ok "Logged in to Cloudflare"
  else
    info "Opening the Cloudflare login in your browser..."
    (cd "$PROJECT_DIR" && npx wrangler login) || fail "Cloudflare login failed."
    ok "Logged in to Cloudflare"
  fi
  # With several Cloudflare accounts wrangler would stop and ask which one, also during the
  # piped `secret put` below, so pin it once here.
  if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    ask CLOUDFLARE_ACCOUNT_ID "Cloudflare account ID (Enter if you have only one account):" ""
  fi
  [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] && export CLOUDFLARE_ACCOUNT_ID
  info "Deploying (wrangler output below)..."
  printf '%s' "$D"
  if ! (cd "$PROJECT_DIR" && npx wrangler deploy 2>&1 | tee "$LOG_DIR/deploy.log" | sed 's/^/    /'); then
    printf '%s' "$N"; fail "wrangler deploy failed" "$LOG_DIR/deploy.log"
  fi
  printf '%s' "$N"
  grep -qiE "^✘|\[ERROR\]" "$LOG_DIR/deploy.log" && fail "wrangler deploy reported an error" "$LOG_DIR/deploy.log"
  ok "Deployed"
  WORKER_URL="$(grep -oE 'https://[A-Za-z0-9.-]+\.workers\.dev' "$LOG_DIR/deploy.log" | head -n 1 || true)"
  if [ -n "$WORKER_URL" ]; then ok "Live at ${B}$WORKER_URL${N}"; else warn "Deployed, but no workers.dev URL found in the output (custom route?)."; fi
else
  info "Skipped. Deploy later with: (cd \"$PROJECT_DIR\" && npx wrangler deploy)"
fi
if [ -z "$WORKER_URL" ]; then
  ask WORKER_URL "Worker URL, if it is already deployed (Enter to skip):" ""
  WORKER_URL="${WORKER_URL%/}"; WORKER_URL="${WORKER_URL%/mcp}"
fi
MCP_URL="${WORKER_URL:+$WORKER_URL/mcp}"

# ── 5. secrets ───────────────────────────────────────────────────────────────
step "Secrets"
# Upstream credentials the generated server reads, from .dev.vars.example (e.g. BEARERAUTH_TOKEN).
UPSTREAM_SECRETS="$(grep -oE '^# ?[A-Z][A-Z0-9_]*="\.\.\."' "$PROJECT_DIR/.dev.vars.example" 2>/dev/null \
  | sed -E 's/^# ?([A-Z0-9_]+)=.*/\1/' | grep -vE '^(MCP_AUTH_TOKEN|MCP_AUTH_TOKENS|MCP_ALLOW_MISSING_CREDENTIALS)$' || true)"
MCP_TOKEN=""
put_secret() { # name value
  printf '%s' "$2" | (cd "$PROJECT_DIR" && npx wrangler secret put "$1") >"$LOG_DIR/secret-$1.log" 2>&1 \
    && ok "$1 set" || fail "Could not set $1" "$LOG_DIR/secret-$1.log"
}
if [ "$DEPLOY" = y ]; then
  if [ -n "$UPSTREAM_SECRETS" ]; then
    info "The API needs: ${B}$(echo $UPSTREAM_SECRETS)${N} (see .dev.vars.example for what each one is)."
    for S in $UPSTREAM_SECRETS; do
      ask_secret VAL "Value for $S (Enter to skip):"
      if [ -n "$VAL" ]; then put_secret "$S" "$VAL"; else warn "$S skipped: tools that need it will return an error naming it."; fi
      VAL=""
    done
  else
    info "The spec declares no upstream credentials."
  fi
  if [ "$INBOUND" = y ]; then
    ask_yn GEN_TOKEN "Generate a random inbound token (MCP_AUTH_TOKEN)?" y
    if [ "$GEN_TOKEN" = y ]; then
      MCP_TOKEN="$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")"
    else
      ask_secret MCP_TOKEN "Your inbound token (MCP_AUTH_TOKEN):"
      [ -n "$MCP_TOKEN" ] || fail "An inbound token is required when inbound auth is on."
    fi
    put_secret MCP_AUTH_TOKEN "$MCP_TOKEN"
    TOKEN_FILE="$PROJECT_DIR/.mcp-auth-token"
    (umask 077; printf '%s\n' "$MCP_TOKEN" >"$TOKEN_FILE")
    grep -qxF ".mcp-auth-token" "$PROJECT_DIR/.gitignore" 2>/dev/null || printf '.mcp-auth-token\n' >>"$PROJECT_DIR/.gitignore"
    ok "Inbound token saved to $TOKEN_FILE (mode 600, git-ignored)"
  fi
else
  info "Skipped (needs a deployed Worker). Later: (cd \"$PROJECT_DIR\" && npx wrangler secret put <NAME>)"
  if [ "$INBOUND" = y ] && [ -f "$PROJECT_DIR/.mcp-auth-token" ]; then
    MCP_TOKEN="$(cat "$PROJECT_DIR/.mcp-auth-token")"; ok "Using the inbound token saved in .mcp-auth-token"
  elif [ "$INBOUND" = y ] && [ -n "$MCP_URL" ]; then
    ask_secret MCP_TOKEN "Inbound token the deployed Worker expects (Enter to skip):"
  fi
fi

# ── 6. verify ────────────────────────────────────────────────────────────────
step "Verify the live server"
if [ -n "$MCP_URL" ] && command -v curl >/dev/null 2>&1; then
  INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1"}}}'
  probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST "$MCP_URL" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' "$@" -d "$INIT" 2>/dev/null || true; }
  sleep 3 # give a fresh deploy / secret change a moment to propagate
  if [ "$INBOUND" = y ]; then
    CODE="$(probe)"; [ "$CODE" = 401 ] && ok "Without a token: 401 (locked)" || warn "Without a token: HTTP $CODE (expected 401)"
    if [ -n "$MCP_TOKEN" ]; then
      CODE="$(probe -H "Authorization: Bearer $MCP_TOKEN")"
      [ "$CODE" = 200 ] && ok "With your token: 200 (MCP initialize works)" || warn "With your token: HTTP $CODE (a fresh secret can take a few seconds; try again shortly)"
    fi
  else
    CODE="$(probe)"; [ "$CODE" = 200 ] && ok "initialize: 200" || warn "initialize: HTTP $CODE"
  fi
  info "Browser playground: $WORKER_URL/"
else
  info "Skipped (no Worker URL)."
fi

# ── 7. toolguard policy ──────────────────────────────────────────────────────
step "mcp-toolguard policy"
POLICY="$PROJECT_DIR/toolguard.yaml"
TG_CLI="$PROJECT_DIR/node_modules/mcp-toolguard-cli/dist/cli/main.js"
if [ "$TOOLGUARD" = y ]; then
  TG_MODE="$TG_MODE" TG_BLOCK_DESTRUCTIVE="$TG_BLOCK_DESTRUCTIVE" TG_DENY="$TG_DENY" SERVER_NAME="$SERVER_NAME" \
    node - "$PROJECT_DIR/src/tools.ts" "$POLICY" <<'NODE'
const fs = require('fs');
const [src, out] = process.argv.slice(2);
const text = fs.readFileSync(src, 'utf8');
const tools = [];
const re = /\["([^"]+)", \{[\s\S]*?annotations: (\{[^}]*\})/g;
for (let m; (m = re.exec(text)); ) {
  let a = {};
  try { a = JSON.parse(m[2]); } catch {}
  tools.push({ name: m[1], readOnly: a.readOnlyHint === true, destructive: a.readOnlyHint !== true && a.destructiveHint !== false });
}
if (!tools.length) { console.error('no tools found in ' + src); process.exit(1); }
const writes = tools.filter((t) => !t.readOnly).map((t) => t.name);
const destructive = tools.filter((t) => t.destructive).map((t) => t.name);
const blockDestructive = process.env.TG_BLOCK_DESTRUCTIVE === 'y';
const extra = (process.env.TG_DENY || '').split(',').map((s) => s.trim()).filter(Boolean);
const deny = [...new Set([...(blockDestructive ? destructive : []), ...extra])];
// Same glob semantics as mcp-toolguard: '*' and '?', anchored.
const globRe = (g) => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
const denyRes = deny.map(globRe);
const blocked = tools.map((t) => t.name).filter((n) => denyRes.some((r) => r.test(n)));
const approval = writes.filter((n) => !blocked.includes(n));
const list = (xs) => (xs.length ? '\n' + xs.map((x) => '    - ' + JSON.stringify(x)).join('\n') : ' []');
const yaml = `# mcp-toolguard policy for ${process.env.SERVER_NAME} (generated by deploy-guarded-mcp.sh)
# Validate: npx -y mcp-toolguard-cli check-policy toolguard.yaml
# Approve a waiting call: npx -y mcp-toolguard-cli approve <id> --policy <this file>
version: 1
mode: ${process.env.TG_MODE || 'enforce'} # "monitor" logs and warns but never blocks

tools:
  # Only the ${tools.length} tool(s) this server was generated with; anything else is hidden and blocked.
  allow:${list(tools.map((t) => t.name))}
  unlisted: block
  unknown: block
  deny:${list(deny)}

approval:
  # ${approval.length} tool(s) that can change data wait for: mcp-toolguard approve <id>
  tools:${list(approval)}
`;
fs.writeFileSync(out, yaml);
fs.writeFileSync(out + '.counts', [tools.length - approval.length - blocked.length, approval.length, blocked.length].join(' '));
NODE
  "$NODE_BIN" "$TG_CLI" check-policy "$POLICY" >"$LOG_DIR/check-policy.log" 2>&1 || fail "toolguard.yaml is not valid" "$LOG_DIR/check-policy.log"
  ok "Wrote $POLICY and it validates"
  read -r FREE_N APPROVE_N DENY_N <"$POLICY.counts" || true; rm -f "$POLICY.counts"
  info "${G}$FREE_N${N} tool(s) run freely · ${Y}$APPROVE_N${N} wait for your approval · ${R}$DENY_N${N} blocked · mode: $TG_MODE"
else
  info "Skipped."
fi

# ── 8. clients ───────────────────────────────────────────────────────────────
step "Connect Claude Desktop / Cursor"
add_client() { # config-file label
  local cfg="$1" label="$2"
  local backup=""
  mkdir -p "$(dirname "$cfg")"
  if [ -f "$cfg" ]; then backup="$cfg.bak.$(date +%Y%m%d-%H%M%S)"; cp "$cfg" "$backup"; fi
  CFG="$cfg" NAME="$SERVER_NAME" NODE_BIN="$NODE_BIN" TG_CLI="$TG_CLI" POLICY="$POLICY" MCP_URL="$MCP_URL" TOKEN="$MCP_TOKEN" node <<'NODE' || return 1
const fs = require('fs');
const f = process.env.CFG;
let cfg = {};
if (fs.existsSync(f) && fs.readFileSync(f, 'utf8').trim()) cfg = JSON.parse(fs.readFileSync(f, 'utf8'));
cfg.mcpServers = cfg.mcpServers || {};
const args = [process.env.TG_CLI, 'run', '--policy', process.env.POLICY, '--server-id', process.env.NAME,
  '--transport', 'http', '--url', process.env.MCP_URL];
if (process.env.TOKEN) args.push('--header', 'Authorization: Bearer ' + process.env.TOKEN);
cfg.mcpServers[process.env.NAME] = { command: process.env.NODE_BIN, args };
const tmp = f + '.tmp-' + process.pid;
fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
fs.renameSync(tmp, f);
NODE
  if [ -n "$backup" ]; then ok "$label: added '$SERVER_NAME' (previous config saved as $(basename "$backup"))"
  else ok "$label: added '$SERVER_NAME' (new $(basename "$cfg"))"; fi
}
if [ "$TOOLGUARD" = y ] && [ -n "$MCP_URL" ] && { [ "$ADD_CLAUDE" = y ] || [ "$ADD_CURSOR" = y ]; }; then
  [ -n "$MCP_TOKEN" ] && warn "The inbound token is stored in the client config file; keep that file private."
  [ "$ADD_CLAUDE" = y ] && { add_client "$CLAUDE_CFG" "Claude Desktop" || warn "Claude Desktop config is not valid JSON; left unchanged."; }
  [ "$ADD_CURSOR" = y ] && { add_client "$CURSOR_CFG" "Cursor" || warn "Cursor config is not valid JSON; left unchanged."; }
  info "Quit and reopen the apps (Cmd+Q) to load it."
elif [ "$TOOLGUARD" = y ] && [ -z "$MCP_URL" ]; then
  info "Skipped: no Worker URL yet. Run this script again after deploying."
else
  info "Skipped."
fi

# ── 9. done ──────────────────────────────────────────────────────────────────
step "Done"
hr
printf '  %s%s✔ %s is ready%s\n' "$G" "$B" "$SERVER_NAME" "$N"
printf '  %-16s %s\n' "Project" "$PROJECT_DIR" "Tools" "$TOOL_COUNT"
[ -n "$MCP_URL" ] && printf '  %-16s %s\n' "MCP endpoint" "$MCP_URL" "Playground" "$WORKER_URL/"
[ -f "$PROJECT_DIR/.mcp-auth-token" ] && printf '  %-16s %s\n' "Inbound token" "$PROJECT_DIR/.mcp-auth-token"
[ "$TOOLGUARD" = y ] && printf '  %-16s %s\n' "Policy" "$POLICY" "Audit log" "~/.mcp-toolguard/audit.jsonl"
hr
printf '  %sUseful commands%s\n' "$B" "$N"
printf '  %sRedeploy%s          (cd "%s" && npx wrangler deploy)\n' "$D" "$N" "$PROJECT_DIR"
printf '  %sLogs%s              (cd "%s" && npx wrangler tail)\n' "$D" "$N" "$PROJECT_DIR"
if [ "$TOOLGUARD" = y ]; then
  printf '  %sApprove a call%s    node "%s" approve <id> --policy "%s"\n' "$D" "$N" "$TG_CLI" "$POLICY"
  printf '  %sPending approvals%s node "%s" approvals list --policy "%s"\n' "$D" "$N" "$TG_CLI" "$POLICY"
  printf '  %sCheck audit log%s   node "%s" verify-log ~/.mcp-toolguard/audit.jsonl\n' "$D" "$N" "$TG_CLI"
fi
echo

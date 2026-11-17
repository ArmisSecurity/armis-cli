#!/usr/bin/env bash
# Enterprise rollout of armis-cli and the Armis AppSec MCP server on macOS.
#
# Run it by hand, or as root from an MDM (Jamf, Kandji, Intune for macOS). It
# installs armis-cli, signs developers in, registers the MCP server in every
# supported editor and code agent it finds, checks that the result works, and
# reports per endpoint, user and component.
#
# Stages: preflight, cli, auth, mcp, jetbrains, hook, verify, report.
# A component that fails does not stop components that do not depend on it.
# Only a preflight failure or a failed armis-cli install stops the run.
#
# Usage:
#   enterprise-setup.sh [--dry-run] [--uninstall] [--non-interactive]
#                       [--only a,b] [--skip a,b] [--report PATH] [--bundle]
#                       [--verbose] [--help]
#
#   --dry-run          Print what would change; write nothing.
#   --uninstall        Remove what this script installed (see docs).
#   --non-interactive  Never prompt (implied when stdin is not a terminal).
#   --only / --skip    Comma-separated components: cursor, vscode, copilot,
#                      codex, claude, antigravity, junie, jetbrains, hook.
#   --report PATH      Write the JSON report to PATH.json.
#   --bundle           Also write an `armis-cli mcp doctor` support bundle per user.
#   --verbose          Log every command the script runs.
#
# Exit codes: 0 ok, 1 partial (something needs attention), 2 verification
# failed or armis-cli could not be installed, 3 bad arguments or preflight failure.
#
# Secrets: client credentials come from the environment or a root-owned 0600
# file, never from arguments. They are not written to logs or reports.
#
# Requirements: macOS 12+, curl, git, Python 3.11+ on each developer's PATH.
set -u
set -o pipefail

# Started with zsh or sh instead of bash: re-run under bash.
if [ -z "${BASH_VERSION:-}" ]; then
    exec /bin/bash "$0" "$@"
fi

# ---- CONFIG BEGIN ----------------------------------------------------------
# Every value can be set from the environment (MDM script parameters or a
# wrapper). Values given here are the defaults.

# armis-cli release to install, 1.27.0 or later. Required with --non-interactive
# unless ARMIS_ALLOW_LATEST=1. The installer script is fetched from the same tag.
ARMIS_CLI_VERSION="${ARMIS_CLI_VERSION:-}"
ARMIS_ALLOW_LATEST="${ARMIS_ALLOW_LATEST:-0}"
# MCP server release to pin, e.g. 1.4.2. Empty follows the latest release.
ARMIS_MCP_VERSION="${ARMIS_MCP_VERSION:-}"

# Tenant and region. The tenant is required for sso. The region is only needed
# outside the default one (for example eu1).
ARMIS_TENANT_ID="${ARMIS_TENANT_ID:-}"
ARMIS_REGION="${ARMIS_REGION:-}"

# client-credentials: ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET from the
# environment, or from ARMIS_CREDENTIALS_FILE (KEY=VALUE lines, owned by the
# user running this script, mode 0600 or 0400).
# sso: developers sign in through the browser (see docs/SSO-SETUP.md).
ARMIS_AUTH_MODE="${ARMIS_AUTH_MODE:-client-credentials}"
ARMIS_CREDENTIALS_FILE="${ARMIS_CREDENTIALS_FILE:-}"
# Browser sign-in: auto (when run by a developer in a terminal), now, or skip.
ARMIS_SSO_LOGIN="${ARMIS_SSO_LOGIN:-auto}"

# Clients to configure (space or comma separated).
ARMIS_CLIENTS="${ARMIS_CLIENTS:-cursor vscode copilot codex claude antigravity junie}"
# JetBrains AI Assistant is per project: comma-separated project directories.
ARMIS_JETBRAINS_PROJECTS="${ARMIS_JETBRAINS_PROJECTS:-}"
# Commit gate (pre-commit hook) in specific repositories: 1 to enable, plus a
# comma-separated list of repositories. ARMIS_HOOK_FAIL_OPEN=1 warns instead of blocking.
ARMIS_HOOK_ENABLE="${ARMIS_HOOK_ENABLE:-0}"
ARMIS_HOOK_REPOS="${ARMIS_HOOK_REPOS:-}"
ARMIS_HOOK_FAIL_OPEN="${ARMIS_HOOK_FAIL_OPEN:-0}"

# Also install Armis Knowledge (cannot be pinned).
ARMIS_WITH_KNOWLEDGE="${ARMIS_WITH_KNOWLEDGE:-0}"
# Scan a two-line sample through the API to prove the whole path. This uses
# tenant scan quota. 0 to skip.
ARMIS_SAMPLE_SCAN="${ARMIS_SAMPLE_SCAN:-1}"

# Accounts to configure (comma separated). Default: the console user when run
# as root, otherwise the current user.
ARMIS_TARGET_USERS="${ARMIS_TARGET_USERS:-}"

# Where armis-cli goes. Default: /usr/local/bin as root, ~/.local/bin otherwise.
ARMIS_INSTALL_DIR="${ARMIS_INSTALL_DIR:-}"
# Internal mirror of scripts/install.sh, for endpoints that cannot reach GitHub raw.
ARMIS_INSTALLER_URL="${ARMIS_INSTALLER_URL:-}"
# Extra directories appended to every user's PATH when looking for Python.
ARMIS_EXTRA_PATH="${ARMIS_EXTRA_PATH:-}"

# Logs and reports. Default: /Library/Logs/Armis as root, ~/Library/Logs/Armis otherwise.
ARMIS_LOG_DIR="${ARMIS_LOG_DIR:-}"
ARMIS_REPORT_PATH="${ARMIS_REPORT_PATH:-}"

# Uninstall: keep credentials / also remove /usr/local/bin/armis-cli (root only).
ARMIS_KEEP_CREDENTIALS="${ARMIS_KEEP_CREDENTIALS:-0}"
ARMIS_REMOVE_CLI="${ARMIS_REMOVE_CLI:-0}"

# Proxy and TLS inspection: HTTPS_PROXY, HTTP_PROXY, NO_PROXY (either case),
# SSL_CERT_FILE and ARMIS_API_URL are passed on to curl and to every armis-cli command.
# ---- CONFIG END ------------------------------------------------------------

SCRIPT_VERSION="1.0.0"
MIN_CLI_VERSION="1.27.0"
MARK_BEGIN="# >>> armis-cli (managed) >>>"
MARK_END="# <<< armis-cli (managed) <<<"
REPO="ArmisSecurity/armis-cli"
# Fixed so MDM runs do not depend on the caller's PATH. ARMIS_SAFE_PATH exists for tests.
SAFE_PATH="${ARMIS_SAFE_PATH:-/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin}"
SERVER_KEY="armis-appsec"
ALL_CLIENTS="cursor vscode copilot codex claude antigravity junie"
VALID_NAMES="$ALL_CLIENTS jetbrains hook"
# Variables passed through sudo to the user's armis-cli commands. Credentials
# travel only this way, never as arguments.
PRESERVE_ENV="ARMIS_CLIENT_ID,ARMIS_CLIENT_SECRET,ARMIS_TENANT_ID,ARMIS_REGION,ARMIS_API_URL,ARMIS_DEFAULT_AUTH_METHOD,ARMIS_MCP_VERSION,HTTPS_PROXY,https_proxy,HTTP_PROXY,http_proxy,NO_PROXY,no_proxy,SSL_CERT_FILE"

DRY_RUN=0
DO_UNINSTALL=0
NONINTERACTIVE=0
VERBOSE=0
WANT_BUNDLE=0
ONLY=""
SKIP=""
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

CRED_ID=""
CRED_SECRET=""
WORK=""
RESULTS=""
LOG_FILE=""
LOG_DIR=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
CLI_BIN=""
CLI_COSIGN="unknown"
FORCED_EXIT=0
LAST_OUT=""
LAST_RC=0
SEQ=0
USERS=""
NO_PYTHON_USERS=""

# ---- logging and results ---------------------------------------------------

redact() {
    sed -E \
        -e 's/(ARMIS_CLIENT_SECRET[[:space:]]*[=:][[:space:]]*)[^[:space:]]+/\1***/g' \
        -e 's/([Bb]earer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1***/g' \
        -e 's/("?client_secret"?[[:space:]]*[=:][[:space:]]*"?)[^[:space:]",}]+/\1***/g' |
        if [ "${#CRED_SECRET}" -ge 8 ]; then
            CS="$CRED_SECRET" awk '{
                s = ENVIRON["CS"]
                while ((i = index($0, s)) > 0) $0 = substr($0, 1, i - 1) "***" substr($0, i + length(s))
                print
            }'
        else
            cat
        fi
}

emit() {
    local line
    line=$(printf '%s' "$1" | redact)
    printf '%s\n' "$line" >&2
    if [ -n "$LOG_FILE" ]; then printf '%s\n' "$line" >> "$LOG_FILE"; fi
}

log()  { emit "[armis-setup] $*"; }
warn() { emit "[armis-setup] WARNING: $*"; }
vlog() { if [ "$VERBOSE" -eq 1 ]; then emit "[armis-setup] + $*"; fi; }

# show_out FILE: log a command's captured output, indented.
show_out() {
    local text
    [ -s "$1" ] || return 0
    text=$(redact < "$1" | sed 's/^/    /')
    printf '%s\n' "$text" >&2
    if [ -n "$LOG_FILE" ]; then printf '%s\n' "$text" >> "$LOG_FILE"; fi
}

# rec USER COMPONENT FIELD VALUE: append one fact to the results table.
rec() {
    local v=${4//$'\t'/ }
    v=${v//$'\n'/ }
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$v" >> "$RESULTS"
}

die_usage() {
    printf '[armis-setup] ERROR: %s\n' "$*" >&2
    printf 'Run with --help for usage.\n' >&2
    exit 3
}

# ---- small helpers ---------------------------------------------------------

has() { command -v "$1" >/dev/null 2>&1; }

in_list() { # in_list WORD "a b c"
    case " $2 " in *" $1 "*) return 0 ;; esac
    return 1
}

split_list() { printf '%s' "$1" | tr ',' ' ' | tr -s ' '; }

# lines_of_list "a,b c": one entry per line, splitting on commas only (paths may contain spaces).
lines_of_list() { printf '%s' "$1" | tr ',' '\n' | sed '/^[[:space:]]*$/d'; }

require_ident() {
    local name=$1 value=$2
    printf '%s' "$value" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' \
        || die_usage "$name has invalid characters or length: '$value'"
}

user_home() {
    if [ "$1" = "$(id -un)" ] && [ -n "${HOME:-}" ]; then
        printf '%s\n' "$HOME"
        return
    fi
    dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{ $1 = ""; sub(/^ /, ""); print }'
}

resolve_users() {
    if [ -n "$ARMIS_TARGET_USERS" ]; then
        split_list "$ARMIS_TARGET_USERS" | tr ' ' '\n'
        return
    fi
    if [ "$IS_ROOT" -eq 0 ]; then
        id -un
        return
    fi
    local u
    u=$(stat -f%Su /dev/console 2>/dev/null || true)
    case "$u" in "" | root | loginwindow) ;; *) printf '%s\n' "$u" ;; esac
}

# kill_tree SIGNAL PID: signal PID and every descendant, children first.
kill_tree() {
    local c
    for c in $(pgrep -P "$2" 2>/dev/null); do kill_tree "$1" "$c"; done
    kill "-$1" "$2" 2>/dev/null
}

# with_timeout SECONDS CMD...: run CMD, kill it and everything it started after
# SECONDS. CMD is usually as_user, whose real command is a grandchild (sudo).
with_timeout() {
    local secs=$1 pid watcher rc
    shift
    "$@" &
    pid=$!
    (
        sleep "$secs" &
        sleeper=$!
        trap 'kill "$sleeper" 2>/dev/null; exit 0' TERM
        wait "$sleeper"
        kill_tree TERM "$pid"
        sleep 5 &
        sleeper=$!
        wait "$sleeper"
        kill_tree KILL "$pid"
    ) >/dev/null 2>&1 &
    watcher=$!
    wait "$pid" 2>/dev/null
    rc=$?
    kill -TERM "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    return "$rc"
}

# exec_cmd CMD...: run CMD, capture all output in LAST_OUT, status in LAST_RC.
exec_cmd() {
    SEQ=$((SEQ + 1))
    LAST_OUT="$WORK/out.$SEQ"
    vlog "$*"
    "$@" > "$LAST_OUT" 2>&1 < /dev/null
    LAST_RC=$?
}

# as_user USER HOME CREDS GUI CMD...: run CMD as USER. Credentials are put in
# the child's environment only, and only when CREDS is 1. GUI=1 attaches the
# command to the user's login session so a browser can open.
as_user() {
    local user=$1 home=$2 creds=$3 gui=$4 uid upath
    shift 4
    uid=$(id -u "$user" 2>/dev/null) || return 127
    upath="$SAFE_PATH:$home/.local/bin"
    if [ -n "$ARMIS_EXTRA_PATH" ]; then upath="$ARMIS_EXTRA_PATH:$upath"; fi
    if [ -n "$CLI_BIN" ]; then upath="$upath:$(dirname "$CLI_BIN")"; fi
    (
        if [ "$creds" = 1 ] && [ -n "$CRED_ID" ]; then
            # shellcheck disable=SC2030 # subshell-local on purpose: secrets never leak into this shell
            export ARMIS_CLIENT_ID="$CRED_ID" ARMIS_CLIENT_SECRET="$CRED_SECRET"
        fi
        if [ "$uid" = "$(id -u)" ]; then
            exec env PATH="$upath" HOME="$home" USER="$user" LOGNAME="$user" "$@" < /dev/null
        elif [ "$gui" = 1 ]; then
            exec launchctl asuser "$uid" sudo -n -H -u "$user" --preserve-env="$PRESERVE_ENV" \
                env PATH="$upath" HOME="$home" USER="$user" LOGNAME="$user" "$@" < /dev/null
        else
            exec sudo -n -H -u "$user" --preserve-env="$PRESERVE_ENV" \
                env PATH="$upath" HOME="$home" USER="$user" LOGNAME="$user" "$@" < /dev/null
        fi
    )
}

# user_cmd USER HOME CREDS GUI CMD...: as_user with captured output.
user_cmd() {
    local user=$1 home=$2 creds=$3 gui=$4
    shift 4
    SEQ=$((SEQ + 1))
    LAST_OUT="$WORK/out.$SEQ"
    vlog "as $user: $*"
    as_user "$user" "$home" "$creds" "$gui" "$@" > "$LAST_OUT" 2>&1
    LAST_RC=$?
}

# ---- JSON helper (JavaScript for Automation, ships with macOS) --------------

write_json_tool() {
    cat > "$WORK/json_tool.js" <<'JSEOF'
ObjC.import('Foundation');

function readFile(p) {
    var s = $.NSString.stringWithContentsOfFileEncodingError($(p), $.NSUTF8StringEncoding, $());
    return s.isNil() ? null : ObjC.unwrap(s);
}

function writeFile(p, text) {
    var ok = $(text).writeToFileAtomicallyEncodingError($(p), true, $.NSUTF8StringEncoding, $());
    if (!ok) throw new Error('cannot write ' + p);
}

// Comments and trailing commas outside strings, as VS Code's mcp.json allows.
function stripJsonc(s) {
    var out = '', i = 0, n = s.length, inStr = false, c;
    while (i < n) {
        c = s[i];
        if (inStr) {
            out += c;
            if (c === '\\') { out += s[i + 1] || ''; i += 2; continue; }
            if (c === '"') inStr = false;
            i++;
            continue;
        }
        if (c === '"') { inStr = true; out += c; i++; continue; }
        if (c === '/' && s[i + 1] === '/') { while (i < n && s[i] !== '\n') i++; continue; }
        if (c === '/' && s[i + 1] === '*') {
            i += 2;
            while (i < n && !(s[i] === '*' && s[i + 1] === '/')) i++;
            i += 2;
            continue;
        }
        out += c;
        i++;
    }
    var res = '', j, k;
    inStr = false;
    for (i = 0; i < out.length; i++) {
        c = out[i];
        if (inStr) {
            res += c;
            if (c === '\\') { res += out[i + 1] || ''; i++; continue; }
            if (c === '"') inStr = false;
            continue;
        }
        if (c === '"') { inStr = true; res += c; continue; }
        if (c === ',') {
            k = i + 1;
            while (k < out.length && /\s/.test(out[k])) k++;
            if (out[k] === '}' || out[k] === ']') continue;
        }
        res += c;
    }
    return res;
}

function load(p) {
    var t = readFile(p);
    if (t === null) throw new Error('cannot read ' + p);
    t = t.replace(/^﻿/, '');
    if (t.trim() === '') return {};
    var o = JSON.parse(stripJsonc(t));
    if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new Error('top level is not an object');
    return o;
}

function line(fields) {
    return fields.map(function (x) { return String(x || '').replace(/[\u001f\n\r]+/g, ' '); }).join('\u001f');
}

function run(argv) {
    var cmd = argv[0], o, v, i;
    if (cmd === 'check') {
        load(argv[1]);
        return '';
    }
    if (cmd === 'keys') {
        o = load(argv[1]);
        v = o[argv[2]];
        if (v && typeof v === 'object' && !Array.isArray(v)) return Object.keys(v).sort().join('\n');
        return '';
    }
    if (cmd === 'delserver') {
        o = load(argv[1]);
        v = o[argv[2]];
        if (!v || typeof v !== 'object' || !v.hasOwnProperty(argv[3])) return 'absent';
        delete v[argv[3]];
        writeFile(argv[1], JSON.stringify(o, null, 2) + '\n');
        return 'removed';
    }
    if (cmd === 'doctor') {
        o = JSON.parse(readFile(argv[1]));
        return (o.checks || []).map(function (c) {
            return line([c.component, c.editor, c.name, c.status, c.detail, c.remediation]);
        }).join('\n');
    }
    // The --format json document of `armis-cli install` or `uninstall`.
    if (cmd === 'result') {
        o = JSON.parse(readFile(argv[1]));
        v = (o.clients || []).map(function (c) {
            var h = c.hook || {};
            return line([c.client, c.status, c.detail, h.status, h.detail]);
        });
        if (o.credentials) {
            v.push(line(['_credentials', o.credentials.status, (o.credentials.files || [])
                .filter(function (f) { return f.status === 'failed'; })
                .map(function (f) { return f.path + ': ' + f.detail; }).join('; ')]));
        }
        if (o.error) v.push(line(['_error', 'fail', o.error]));
        return v.join('\n');
    }
    // report TABLE OUT KEY VALUE...: the run report, from build_table rows.
    if (cmd === 'report') {
        o = {};
        for (i = 3; i + 1 < argv.length; i += 2) o[argv[i]] = argv[i] === 'exit_code' ? Number(argv[i + 1]) : argv[i + 1];
        o.components = (readFile(argv[1]) || '').split('\n').filter(Boolean).map(function (r) {
            var f = r.split('\u001f');
            return { user: f[0], component: f[1], detected: f[2], installed: f[3], auth: f[4], verified: f[5], action: f[6] };
        });
        writeFile(argv[2], JSON.stringify(o, null, 2) + '\n');
        return '';
    }
    throw new Error('unknown command ' + cmd);
}
JSEOF
    chmod 644 "$WORK/json_tool.js"
}

# jt CMD ARGS...: run the JSON helper; output in stdout, nonzero on invalid input.
jt() { osascript -l JavaScript "$WORK/json_tool.js" "$@" 2>/dev/null; }

# json_ok FILE: 0 if FILE is absent, empty, or parses as JSON (comments allowed).
json_ok() {
    [ -e "$1" ] || return 0
    jt check "$1" >/dev/null
}

# ---- per-client definitions -------------------------------------------------

# client_label CLIENT: the editor name `mcp doctor` uses.
client_label() {
    case $1 in
        cursor) echo "Cursor" ;;
        vscode) echo "VS Code" ;;
        copilot) echo "Copilot CLI" ;;
        codex) echo "Codex CLI" ;;
        claude) echo "Claude Code" ;;
        antigravity) echo "Antigravity" ;;
        junie) echo "Junie" ;;
    esac
}

client_from_doctor() { # client_from_doctor LABEL
    local c
    for c in $ALL_CLIENTS; do
        if [ "$(client_label "$c")" = "$1" ]; then echo "$c"; return; fi
    done
}

client_detect_dir() { # client HOME: directory whose presence means "installed"
    case $1 in
        cursor) echo "$2/.cursor" ;;
        vscode) echo "$2/Library/Application Support/Code/User" ;;
        copilot) echo "$2/.copilot" ;;
        codex) echo "$2/.codex" ;;
        claude) echo "$2/.claude" ;;
        antigravity) echo "$2/.gemini/config" ;;
        junie) echo "$2/.junie/mcp" ;;
    esac
}

# client_files CLIENT HOME: lines of "kind|path|topkey". Kinds: json (parsed
# before and after), toml (backed up only). topkey names the object holding servers.
client_files() {
    case $1 in
        cursor) printf 'json|%s|mcpServers\njson|%s|\n' "$2/.cursor/mcp.json" "$2/.cursor/hooks.json" ;;
        vscode) printf 'json|%s|servers\n' "$2/Library/Application Support/Code/User/mcp.json" ;;
        copilot) printf 'json|%s|mcpServers\njson|%s|\n' "$2/.copilot/mcp-config.json" "$2/.copilot/settings.json" ;;
        codex) printf 'toml|%s|\njson|%s|\n' "$2/.codex/config.toml" "$2/.codex/hooks.json" ;;
        claude) printf 'json|%s|\njson|%s|\njson|%s|\n' "$2/.claude/settings.json" \
            "$2/.claude/plugins/installed_plugins.json" "$2/.claude/plugins/known_marketplaces.json" ;;
        antigravity) printf 'json|%s|mcpServers\n' "$2/.gemini/config/mcp_config.json" ;;
        junie) printf 'json|%s|mcpServers\n' "$2/.junie/mcp/mcp.json" ;;
    esac
}

is_running() { # is_running CLIENT USER
    local uid
    uid=$(id -u "$2" 2>/dev/null) || return 1
    case $1 in
        cursor) pgrep -f -u "$uid" "Cursor.app/Contents/MacOS" >/dev/null 2>&1 ;;
        vscode) pgrep -f -u "$uid" "Visual Studio Code.app/Contents/MacOS" >/dev/null 2>&1 ;;
        antigravity) pgrep -f -u "$uid" "Antigravity.app/Contents/MacOS" >/dev/null 2>&1 ;;
        claude) pgrep -x -u "$uid" claude >/dev/null 2>&1 ;;
        codex) pgrep -x -u "$uid" codex >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# ---- backups ---------------------------------------------------------------

# Every write under a developer's home runs as that developer (as_user), never
# as root: the paths are theirs to symlink anywhere.

# backup_file USER HOME FILE LISTFILE: copy FILE to FILE.armis-bak.<ts> once per
# run and note it in LISTFILE as "orig<TAB>bak".
backup_file() {
    local user=$1 home=$2 f=$3 list=$4 bak
    [ -f "$f" ] || return 0
    bak="$f.armis-bak.$RUN_TS"
    if [ ! -e "$bak" ] && [ ! -L "$bak" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] would back up $f to $bak"
            return 0
        fi
        # shellcheck disable=SC2016 # expanded by the inner shell
        as_user "$user" "$home" 0 0 /bin/sh -c 'umask 077; cp -p "$1" "$2"' sh "$f" "$bak" || return 1
    fi
    printf '%s\t%s\n' "$f" "$bak" >> "$list"
}

# norm_sum FILE: checksum ignoring timestamps the installers refresh.
norm_sum() {
    [ -f "$1" ] || { echo none; return; }
    grep -v -e '"installedAt"' -e '"lastUpdated"' "$1" | shasum -a 256 | awk '{print $1}'
}

# drop_unchanged USER HOME LISTFILE: delete backups whose original did not change.
drop_unchanged() {
    local orig bak
    while IFS=$'\t' read -r orig bak; do
        [ -f "$bak" ] || continue
        if [ -f "$orig" ] && [ "$(norm_sum "$orig")" = "$(norm_sum "$bak")" ]; then
            as_user "$1" "$2" 0 0 /bin/rm -f "$bak"
        fi
    done < "$3"
}

# ---- credentials -----------------------------------------------------------

load_credentials() {
    local f owner mode id="" secret=""
    # shellcheck disable=SC2031 # the export in as_user is deliberately subshell-local
    CRED_ID="${ARMIS_CLIENT_ID:-}"
    # shellcheck disable=SC2031
    CRED_SECRET="${ARMIS_CLIENT_SECRET:-}"
    unset ARMIS_CLIENT_ID ARMIS_CLIENT_SECRET
    f=$ARMIS_CREDENTIALS_FILE
    if [ -n "$f" ] && { [ -z "$CRED_ID" ] || [ -z "$CRED_SECRET" ]; }; then
        [ -f "$f" ] || die_usage "ARMIS_CREDENTIALS_FILE not found: $f"
        owner=$(stat -f %u "$f")
        mode=$(stat -f %Lp "$f")
        if [ "$owner" != "$(id -u)" ]; then
            die_usage "credentials file $f must be owned by the user running this script"
        fi
        case $mode in
            600 | 400) ;;
            *) die_usage "credentials file $f has mode $mode; it must be 600 or 400" ;;
        esac
        id=$(sed -n 's/^ARMIS_CLIENT_ID=//p' "$f" | head -n 1)
        secret=$(sed -n 's/^ARMIS_CLIENT_SECRET=//p' "$f" | head -n 1)
        [ -n "$CRED_ID" ] || CRED_ID=$id
        [ -n "$CRED_SECRET" ] || CRED_SECRET=$secret
    fi
    if [ -n "$CRED_ID$CRED_SECRET" ] && { [ -z "$CRED_ID" ] || [ -z "$CRED_SECRET" ]; }; then
        die_usage "set both ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET (or neither)"
    fi
    case "$CRED_ID$CRED_SECRET" in
        *$'\n'* | *$'\r'*) die_usage "client credentials must not contain newlines" ;;
    esac
}

# ---- preflight --------------------------------------------------------------

fatal() { # fatal CODE MESSAGE
    warn "$2"
    rec "-" preflight installed fail
    rec "-" preflight action "$2"
    FORCED_EXIT=$1
    finish
}

probe() { # probe URL: prints the HTTP status, 000 if unreachable
    local code
    if [ -n "${SSL_CERT_FILE:-}" ]; then
        code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 20 \
            --cacert "$SSL_CERT_FILE" "$1" 2>/dev/null) || code=000
    else
        code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 20 "$1" 2>/dev/null) || code=000
    fi
    printf '%s' "${code:-000}"
}

api_base() {
    if [ -n "${ARMIS_API_URL:-}" ]; then
        printf '%s' "$ARMIS_API_URL"
    elif [ "$ARMIS_REGION" = eu1 ]; then
        printf '%s' "https://eu.moose.armis.com"
    else
        printf '%s' "https://moose.armis.com"
    fi
}

stage_preflight() {
    local os ver major arch translated free dir target code url name
    log "Preflight"
    os=$(uname -s)
    [ "$os" = Darwin ] || fatal 3 "unsupported OS: $os (this script is for macOS)"
    ver=$(sw_vers -productVersion 2>/dev/null || echo 0)
    major=${ver%%.*}
    if [ "${major:-0}" -lt 12 ] 2>/dev/null; then
        fatal 3 "macOS $ver is not supported (12 or later is required)"
    fi
    arch=$(uname -m)
    translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)
    log "macOS $ver on $arch$([ "$translated" = 1 ] && echo ' (under Rosetta)')"

    for name in curl git osascript; do
        has "$name" || fatal 3 "$name is required but was not found"
    done
    if [ "$IS_ROOT" -eq 1 ]; then
        for name in dscl launchctl sudo; do
            has "$name" || fatal 3 "$name is required when running as root but was not found"
        done
    fi

    # Uninstall downloads nothing and writes nothing new.
    [ "$DO_UNINSTALL" -eq 0 ] || return 0

    dir=$CLI_DIR
    target=$dir
    while [ ! -d "$target" ] && [ "$target" != / ]; do target=$(dirname "$target"); done
    free=$(df -k "$target" | awk 'NR == 2 { print int($4 / 1024) }')
    if [ "${free:-0}" -lt 500 ]; then
        fatal 3 "less than 500 MB free on the volume holding $dir (${free:-0} MB)"
    fi
    if [ "$DRY_RUN" -eq 0 ] && [ ! -w "$target" ]; then
        fatal 3 "$dir is not writable by $(id -un)"
    fi

    for url in "$(api_base)" "https://api.github.com" "https://github.com/$REPO/releases"; do
        code=$(probe "$url")
        if [ "$code" = 000 ]; then
            fatal 3 "cannot reach $url (check the network, HTTPS_PROXY and SSL_CERT_FILE)"
        fi
        vlog "reachable: $url ($code)"
    done
    if [ -z "$ARMIS_INSTALLER_URL" ]; then
        code=$(probe "https://raw.githubusercontent.com")
        [ "$code" != 000 ] || fatal 3 "cannot reach https://raw.githubusercontent.com (set ARMIS_INSTALLER_URL to an internal mirror)"
    fi
}

# ---- armis-cli --------------------------------------------------------------

cli_version_ok() { # does the installed binary report exactly the wanted version?
    local got
    [ -x "$CLI_BIN" ] || return 1
    got=$("$CLI_BIN" --version 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) if ($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+/) { sub(/^v/, "", $i); print $i; exit }
    }')
    [ -n "$got" ] && [ "$got" = "$ARMIS_CLI_VERSION" ]
}

stage_cli() {
    local ref installer_url version_arg
    log "armis-cli"
    CLI_BIN="$CLI_DIR/armis-cli"

    if [ "$ARMIS_CLI_VERSION" != latest ] && cli_version_ok; then
        log "armis-cli $ARMIS_CLI_VERSION already installed at $CLI_BIN"
        rec "-" armis-cli detected yes
        rec "-" armis-cli installed ok
        rec "-" armis-cli verified ok
        return 0
    fi

    if [ "$ARMIS_CLI_VERSION" = latest ]; then ref=main; version_arg=latest; else ref="v$ARMIS_CLI_VERSION"; version_arg="v$ARMIS_CLI_VERSION"; fi
    installer_url="${ARMIS_INSTALLER_URL:-https://raw.githubusercontent.com/$REPO/$ref/scripts/install.sh}"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] would download $installer_url and install armis-cli $ARMIS_CLI_VERSION to $CLI_DIR"
        rec "-" armis-cli detected no
        rec "-" armis-cli installed skip
        rec "-" armis-cli action "dry-run: would install armis-cli $ARMIS_CLI_VERSION"
        return 0
    fi

    mkdir -p "$CLI_DIR" || { rec "-" armis-cli installed fail; FORCED_EXIT=2; finish; }
    exec_cmd curl -fsSL "$installer_url" -o "$WORK/install.sh"
    if [ "$LAST_RC" -ne 0 ]; then
        show_out "$LAST_OUT"
        rec "-" armis-cli installed fail
        rec "-" armis-cli action "could not download the installer from $installer_url"
        FORCED_EXIT=2
        finish
    fi

    log "Installing armis-cli $ARMIS_CLI_VERSION to $CLI_DIR"
    # CI=1 keeps the installer from editing the invoking account's shell rc;
    # profiles are managed per developer below.
    exec_cmd env CI=1 SHELL="${SHELL:-/bin/bash}" INSTALL_DIR="$CLI_DIR" VERIFY=true \
        PATH="$SAFE_PATH:$CLI_DIR:$PATH" bash "$WORK/install.sh" "$version_arg"
    show_out "$LAST_OUT"
    if grep -Eq "(Checksum|Signature) verification failed" "$LAST_OUT"; then
        rec "-" armis-cli installed fail
        rec "-" armis-cli action "checksum or signature verification failed; the download may have been tampered with"
        FORCED_EXIT=3
        finish
    fi
    if [ "$LAST_RC" -ne 0 ] || [ ! -x "$CLI_BIN" ]; then
        rec "-" armis-cli installed fail
        rec "-" armis-cli action "installer failed; see the log"
        FORCED_EXIT=2
        finish
    fi
    if [ "$IS_ROOT" -eq 1 ]; then chmod 755 "$CLI_BIN"; fi

    rec "-" armis-cli detected yes
    rec "-" armis-cli installed ok
    if [ "$ARMIS_CLI_VERSION" != latest ] && ! cli_version_ok; then
        rec "-" armis-cli verified fail
        rec "-" armis-cli action "installed binary does not report version $ARMIS_CLI_VERSION"
        FORCED_EXIT=2
        finish
    fi
    rec "-" armis-cli verified ok

    if grep -q "Verifying signature with cosign" "$LAST_OUT" && ! grep -q "verifying checksums only" "$LAST_OUT"; then
        CLI_COSIGN=yes
    else
        CLI_COSIGN=no
        rec "-" armis-cli action "only the checksum was verified; install cosign for signature verification"
    fi
}

# ---- profiles ---------------------------------------------------------------

# shellcheck disable=SC2016 # expanded by the inner shell
MANAGED_BLOCK_SH='f=$1 b=$2 e=$3 c=$4
tmp=$(mktemp "${TMPDIR:-/tmp}/armis-profile.XXXXXX") || exit 1
if [ -f "$f" ]; then
    awk -v b="$b" -v e="$e" "\$0 == b { skip = 1; next } \$0 == e { skip = 0; next } !skip" "$f" > "$tmp" \
        || { rm -f "$tmp"; exit 1; }
fi
if [ -n "$c" ]; then printf "%s\n%s\n%s\n" "$b" "$c" "$e" >> "$tmp"; fi
cat "$tmp" > "$f"
rc=$?
rm -f "$tmp"
exit $rc'

set_managed_block() { # set_managed_block FILE USER HOME CONTENT
    local file=$1 user=$2 home=$3 content=$4 list
    list="$WORK/profile-backups"
    : > "$list"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] would update the managed block in $file"
        return 0
    fi
    backup_file "$user" "$home" "$file" "$list"
    as_user "$user" "$home" 0 0 /bin/sh -c "$MANAGED_BLOCK_SH" sh "$file" "$MARK_BEGIN" "$MARK_END" "$content" \
        || warn "[$user] could not update $file"
    drop_unchanged "$user" "$home" "$list"
}

profile_block_content() {
    local c=""
    if [ -n "$ARMIS_TENANT_ID" ]; then c="export ARMIS_TENANT_ID='$ARMIS_TENANT_ID'"; fi
    if [ "$ARMIS_AUTH_MODE" = sso ]; then c="${c:+$c$'\n'}export ARMIS_DEFAULT_AUTH_METHOD='SSO'"; fi
    if [ -n "$ARMIS_REGION" ]; then c="${c:+$c$'\n'}export ARMIS_REGION='$ARMIS_REGION'"; fi
    if [ "$IS_ROOT" -eq 0 ] && [ "$CLI_DIR" = "$HOME/.local/bin" ]; then
        # shellcheck disable=SC2016 # $HOME must expand when the profile is sourced
        c="${c:+$c$'\n'}"'export PATH="$HOME/.local/bin:$PATH"'
    fi
    printf '%s' "$c"
}

configure_profiles() { # configure_profiles USER HOME
    local user=$1 home=$2 content f
    content=$(profile_block_content)
    [ -n "$content" ] || return 0
    set_managed_block "$home/.zshenv" "$user" "$home" "$content"
    if [ -f "$home/.bash_profile" ]; then f="$home/.bash_profile"; else f="$home/.profile"; fi
    set_managed_block "$f" "$user" "$home" "$content"
    if [ -f "$home/.bashrc" ]; then set_managed_block "$home/.bashrc" "$user" "$home" "$content"; fi
}

remove_profiles() { # remove_profiles USER HOME
    local user=$1 home=$2 f
    for f in "$home/.zshenv" "$home/.bash_profile" "$home/.profile" "$home/.bashrc"; do
        if [ -f "$f" ] && grep -qF "$MARK_BEGIN" "$f"; then set_managed_block "$f" "$user" "$home" ""; fi
    done
}

# ---- auth -------------------------------------------------------------------

session_present() {
    [ -f "$1/.armis/.sessions" ] && grep -q refresh_token "$1/.armis/.sessions" 2>/dev/null
}

stage_auth() { # stage_auth USER HOME
    local user=$1 home=$2 want login_rc
    log "[$user] auth ($ARMIS_AUTH_MODE)"
    configure_profiles "$user" "$home"

    if [ "$DRY_RUN" -eq 1 ]; then
        rec "$user" _user auth skip
        return 0
    fi

    local authmethod_env=""
    if [ "$ARMIS_AUTH_MODE" = sso ]; then authmethod_env=SSO; fi

    if [ "$ARMIS_AUTH_MODE" = client-credentials ] && [ -n "$CRED_ID" ]; then
        user_cmd "$user" "$home" 1 0 "$CLI_BIN" auth whoami
        show_out "$LAST_OUT"
        if [ "$LAST_RC" -eq 0 ]; then
            rec "$user" _user auth ok
        else
            rec "$user" _user auth fail
            rec "$user" _user action "client credentials were rejected; check ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET and ARMIS_REGION"
        fi
        return 0
    fi

    # sso, or client-credentials with no credentials supplied
    if session_present "$home"; then
        user_cmd "$user" "$home" 0 0 env ARMIS_DEFAULT_AUTH_METHOD="$authmethod_env" "$CLI_BIN" auth whoami
        show_out "$LAST_OUT"
        if [ "$LAST_RC" -eq 0 ]; then
            rec "$user" _user auth ok
            return 0
        fi
    fi

    want=$ARMIS_SSO_LOGIN
    if [ "$want" = auto ]; then
        if [ "$IS_ROOT" -eq 0 ] && [ "$NONINTERACTIVE" -eq 0 ]; then want=now; else want=skip; fi
    fi
    if [ "$ARMIS_AUTH_MODE" = client-credentials ] && [ "$NONINTERACTIVE" -eq 1 ] && [ "$ARMIS_SSO_LOGIN" != now ]; then
        want=skip
    fi
    if [ "$want" = now ]; then
        log "[$user] starting browser sign-in"
        local tenant_args=""
        [ -z "$ARMIS_TENANT_ID" ] || tenant_args="--tenant-id $ARMIS_TENANT_ID"
        # shellcheck disable=SC2086 # tenant_args is two words on purpose
        with_timeout 300 as_user "$user" "$home" 0 1 env ARMIS_DEFAULT_AUTH_METHOD=SSO "$CLI_BIN" auth login $tenant_args >&2
        login_rc=$?
        if [ "$login_rc" -eq 0 ]; then
            rec "$user" _user auth ok
            return 0
        fi
    fi
    rec "$user" _user auth warn
    rec "$user" _user action "sign-in pending: run 'armis-cli auth login'"
}

# ---- python -----------------------------------------------------------------

# shellcheck disable=SC2016 # expanded by the inner shell
PY_PROBE='for p in python3.14 python3.13 python3.12 python3.11 python3 python; do
  b=$(command -v "$p" 2>/dev/null) || continue
  if [ "$("$b" -c "import sys; print(sys.version_info >= (3, 11))" 2>/dev/null)" = True ]; then echo "$b"; exit 0; fi
done
exit 1'

user_has_python() { # user_has_python USER HOME
    user_cmd "$1" "$2" 0 0 /bin/sh -c "$PY_PROBE"
    [ "$LAST_RC" -eq 0 ]
}

# ---- mcp --------------------------------------------------------------------

# servers_kept HOME CLIENT DIR: are the client's configs still valid JSON, with
# every server that was registered before install still there?
servers_kept() {
    local kind path top lost
    while IFS='|' read -r kind path top; do
        [ "$kind" = json ] || continue
        if ! json_ok "$path"; then
            CHECK_MSG="$path is not valid JSON after install"
            return 1
        fi
        [ -n "$top" ] && [ -f "$3/$2.before" ] || continue
        lost=$(jt keys "$path" "$top" | awk 'NR == FNR { a[$0] = 1; next } !($0 in a)' - "$3/$2.before" | head -n 1)
        if [ -n "$lost" ]; then
            CHECK_MSG="existing server '$lost' disappeared from $path"
            return 1
        fi
    done <<< "$(client_files "$2" "$1")"
}

# result_field FILE CLIENT N: field N of CLIENT's line from `jt result`.
result_field() {
    awk -F'\037' -v c="$2" -v n="$3" '$1 == c { print $n; exit }' "$1"
}

stage_mcp() { # stage_mcp USER HOME
    local user=$1 home=$2 client dir targets="" kind path top list status detail
    local mdir="$WORK/mcp.$user"
    log "[$user] MCP server"
    mkdir -p "$mdir"
    list="$mdir/backups"
    : > "$list"

    for client in $CLIENT_LIST; do
        in_list "$client" "$ALL_CLIENTS" || continue
        dir=$(client_detect_dir "$client" "$home")
        if [ -d "$dir" ]; then
            rec "$user" "$client" detected yes
        else
            rec "$user" "$client" detected no
            rec "$user" "$client" installed skip
            continue
        fi
        # armis-cli replaces a config it cannot parse, which would delete the
        # user's other servers, so such a client is skipped.
        local invalid=""
        while IFS='|' read -r kind path top; do
            [ -n "$kind" ] || continue
            if [ "$kind" = json ] && ! json_ok "$path"; then invalid=$path; break; fi
        done <<< "$(client_files "$client" "$home")"
        if [ -n "$invalid" ]; then
            rec "$user" "$client" installed fail
            rec "$user" "$client" action "config at $invalid is not valid JSON; fix or remove it, then re-run"
            continue
        fi
        while IFS='|' read -r kind path top; do
            [ -n "$kind" ] || continue
            if [ -n "$top" ] && [ -f "$path" ]; then jt keys "$path" "$top" > "$mdir/$client.before" || true; fi
            backup_file "$user" "$home" "$path" "$list"
        done <<< "$(client_files "$client" "$home")"
        targets="$targets $client"
    done
    targets=${targets# }

    if [ -z "$targets" ]; then
        log "[$user] no clients to configure"
        return 0
    fi

    if ! user_has_python "$user" "$home"; then
        NO_PYTHON_USERS="$NO_PYTHON_USERS $user"
        rec "$user" mcp-server installed warn
        rec "$user" mcp-server action "install Python 3.11+ (brew install python@3.12, or the python.org installer), then re-run"
        for client in $targets; do
            rec "$user" "$client" installed fail
            rec "$user" "$client" action "blocked: Python 3.11+ is missing for $user"
        done
        return 0
    fi

    local flags="--format json"
    [ "$ARMIS_WITH_KNOWLEDGE" = 1 ] && flags="$flags --with-knowledge"
    [ -z "$ARMIS_MCP_VERSION" ] || flags="$flags --plugin-version $ARMIS_MCP_VERSION"
    # armis-cli keeps an existing .env as is; this brings every one it manages
    # to the configured credentials.
    [ -z "$CRED_ID" ] || flags="$flags --rotate-credentials"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] would run: armis-cli install $targets $flags"
        for client in $targets; do
            rec "$user" "$client" installed skip
            rec "$user" "$client" action "dry-run: would register"
        done
        return 0
    fi

    SEQ=$((SEQ + 1))
    LAST_OUT="$WORK/out.$SEQ"
    vlog "as $user: $CLI_BIN install $targets $flags"
    # shellcheck disable=SC2086 # targets and flags are word lists
    as_user "$user" "$home" 1 0 "$CLI_BIN" install $targets $flags > "$mdir/install.json" 2> "$LAST_OUT"
    local install_rc=$?
    show_out "$LAST_OUT"
    jt result "$mdir/install.json" > "$mdir/install.tsv" || : > "$mdir/install.tsv"
    local install_err
    install_err=$(result_field "$mdir/install.tsv" _error 3)
    [ -s "$mdir/install.tsv" ] || install_err=$(grep -v '^[[:space:]]*$' "$LAST_OUT" | tail -n 1)

    for client in $targets; do
        status=$(result_field "$mdir/install.tsv" "$client" 2)
        detail=$(result_field "$mdir/install.tsv" "$client" 3)
        CHECK_MSG=""
        if [ "$status" != ok ]; then
            rec "$user" "$client" installed fail
            rec "$user" "$client" action "${detail:-${install_err:-armis-cli install failed}}"
            restore_files "$user" "$home" "$client" "$list"
            continue
        fi
        if ! servers_kept "$home" "$client" "$mdir"; then
            rec "$user" "$client" installed fail
            rec "$user" "$client" action "$CHECK_MSG; restored the previous config"
            restore_files "$user" "$home" "$client" "$list"
            continue
        fi
        rec "$user" "$client" installed ok
        if [ "$(result_field "$mdir/install.tsv" "$client" 4)" = warn ]; then
            rec "$user" "$client" installed warn
            rec "$user" "$client" action "native hook not installed: $(result_field "$mdir/install.tsv" "$client" 5)"
        fi
        if config_changed "$home" "$client" "$list" && is_running "$client" "$user"; then
            rec "$user" "$client" action "restart $(client_label "$client")"
        fi
    done
    drop_unchanged "$user" "$home" "$list"

    case $(result_field "$mdir/install.tsv" _credentials 2) in
        failed)
            rec "$user" _user auth fail
            rec "$user" mcp-server action "could not rotate credentials ($(result_field "$mdir/install.tsv" _credentials 3)); fix permissions on ~/.armis/plugins and re-run" ;;
        rotated) rec "$user" mcp-server action "credentials rotated; restart editors" ;;
    esac

    if [ "$install_rc" -ne 0 ]; then
        rec "$user" mcp-server installed warn
        rec "$user" mcp-server action "armis-cli install exited $install_rc${install_err:+: $install_err}"
    else
        rec "$user" mcp-server installed ok
    fi
}

restore_files() { # restore_files USER HOME CLIENT LIST
    local kind path top
    while IFS='|' read -r kind path top; do
        [ -n "$kind" ] || continue
        restore_one "$1" "$2" "$path" "$4"
    done <<< "$(client_files "$3" "$2")"
}

restore_one() { # restore_one USER HOME FILE LIST
    local bak
    bak=$(awk -F'\t' -v o="$3" '$1 == o { b = $2 } END { print b }' "$4")
    if [ -n "$bak" ] && [ -f "$bak" ]; then
        as_user "$1" "$2" 0 0 /bin/cp -p "$bak" "$3" && log "restored $3 from $bak"
    fi
}

config_changed() { # config_changed HOME CLIENT LIST
    local kind path top bak
    while IFS='|' read -r kind path top; do
        [ -n "$kind" ] || continue
        bak=$(awk -F'\t' -v o="$path" '$1 == o { b = $2 } END { print b }' "$3")
        if [ -z "$bak" ]; then
            [ -f "$path" ] && return 0
            continue
        fi
        [ "$(norm_sum "$path")" = "$(norm_sum "$bak")" ] || return 0
    done <<< "$(client_files "$2" "$1")"
    return 1
}

# ---- jetbrains --------------------------------------------------------------

stage_jetbrains() { # stage_jetbrains USER HOME
    local user=$1 home=$2 p owner cfg list found=0 ok=1
    in_list jetbrains "$ENABLED_EXTRAS" || return 0
    log "[$user] JetBrains"
    list="$WORK/jb.$user"
    : > "$list"

    if [ -z "$ARMIS_JETBRAINS_PROJECTS" ]; then
        if ls -d "$home/Library/Application Support/JetBrains"/* >/dev/null 2>&1; then
            rec "$user" jetbrains detected yes
            rec "$user" jetbrains installed warn
            rec "$user" jetbrains action "JetBrains AI Assistant is per project: run 'armis-cli install jetbrains --project <repo>' in each repo, set ARMIS_JETBRAINS_PROJECTS, or use Junie"
        else
            rec "$user" jetbrains detected no
            rec "$user" jetbrains installed skip
        fi
        return 0
    fi

    rec "$user" jetbrains detected yes
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        owner=$(stat -f %Su "$p" 2>/dev/null || true)
        [ "$owner" = "$user" ] || continue
        found=1
        cfg="$p/.jb-mcp.json"
        if ! json_ok "$cfg"; then
            rec "$user" jetbrains action "$cfg is not valid JSON; fix or remove it"
            ok=0
            continue
        fi
        backup_file "$user" "$home" "$cfg" "$list"
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] would run: armis-cli install jetbrains --project $p"
            continue
        fi
        user_cmd "$user" "$home" 1 0 "$CLI_BIN" install jetbrains --project "$p" --non-interactive
        show_out "$LAST_OUT"
        if [ "$LAST_RC" -ne 0 ] || ! jt keys "$cfg" mcpServers | grep -qx "$SERVER_KEY"; then
            restore_one "$user" "$home" "$cfg" "$list"
            rec "$user" jetbrains action "registration failed for $p"
            ok=0
        fi
    done <<< "$(lines_of_list "$ARMIS_JETBRAINS_PROJECTS")"
    drop_unchanged "$user" "$home" "$list"
    if [ "$found" -eq 0 ]; then
        rec "$user" jetbrains installed skip
        rec "$user" jetbrains action "no configured project belongs to $user"
    elif [ "$DRY_RUN" -eq 1 ]; then
        rec "$user" jetbrains installed skip
    elif [ "$ok" -eq 1 ]; then
        rec "$user" jetbrains installed ok
        rec "$user" jetbrains action "enable the server in the IDE's AI Assistant MCP settings"
    else
        rec "$user" jetbrains installed fail
    fi
}

# ---- hook -------------------------------------------------------------------

stage_hook() { # stage_hook USER HOME
    local user=$1 home=$2 repo owner hooks hook list found=0 ok=1 flags=""
    in_list hook "$ENABLED_EXTRAS" || return 0
    log "[$user] commit gate"
    if [ -z "$ARMIS_HOOK_REPOS" ]; then
        rec "$user" hook installed warn
        rec "$user" hook action "the commit gate is per repository: run 'armis-cli hook init' in each repo, or set ARMIS_HOOK_REPOS"
        return 0
    fi
    list="$WORK/hook.$user"
    : > "$list"
    [ "$ARMIS_HOOK_FAIL_OPEN" = 1 ] && flags="--fail-open"
    rec "$user" hook detected yes
    while IFS= read -r repo; do
        [ -n "$repo" ] || continue
        owner=$(stat -f %Su "$repo" 2>/dev/null || true)
        [ "$owner" = "$user" ] || continue
        found=1
        user_cmd "$user" "$home" 0 0 git -C "$repo" rev-parse --git-path hooks
        if [ "$LAST_RC" -ne 0 ]; then
            rec "$user" hook action "$repo is not a git repository"
            ok=0
            continue
        fi
        hooks=$(tail -n 1 "$LAST_OUT")
        case $hooks in /*) ;; *) hooks="$repo/$hooks" ;; esac
        hook="$hooks/pre-commit"
        backup_file "$user" "$home" "$hook" "$list"
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] would run: armis-cli hook init $flags in $repo"
            continue
        fi
        # shellcheck disable=SC2016 # expanded by the inner shell
        user_cmd "$user" "$home" 0 0 /bin/sh -c 'cd "$1" && shift && exec "$@"' sh "$repo" "$CLI_BIN" hook init $flags
        show_out "$LAST_OUT"
        if [ "$LAST_RC" -ne 0 ] || [ ! -x "$hook" ]; then
            restore_one "$user" "$home" "$hook" "$list"
            rec "$user" hook action "could not install the hook in $repo"
            ok=0
        fi
    done <<< "$(lines_of_list "$ARMIS_HOOK_REPOS")"
    drop_unchanged "$user" "$home" "$list"
    if [ "$found" -eq 0 ]; then
        rec "$user" hook installed skip
        rec "$user" hook action "no configured repository belongs to $user"
    elif [ "$DRY_RUN" -eq 1 ]; then
        rec "$user" hook installed skip
    elif [ "$ok" -eq 1 ]; then
        rec "$user" hook installed ok
    else
        rec "$user" hook installed fail
    fi
}

# ---- verify -----------------------------------------------------------------

stage_verify() { # stage_verify USER HOME
    local user=$1 home=$2 bundle="" report comp editor name status detail fix client c
    log "[$user] verify"
    if [ "$DRY_RUN" -eq 1 ]; then return 0; fi
    if in_list "$user" "$NO_PYTHON_USERS"; then
        log "[$user] MCP server not installed (no Python 3.11+); skipping mcp doctor"
        if [ "$ARMIS_SAMPLE_SCAN" = 1 ]; then sample_scan "$user" "$home"; fi
        return 0
    fi

    if [ "$WANT_BUNDLE" -eq 1 ]; then
        bundle="--bundle-path $LOG_DIR/doctor-$user-$RUN_TS.zip"
    fi
    report="$WORK/doctor.$user.json"
    SEQ=$((SEQ + 1))
    LAST_OUT="$WORK/out.$SEQ"
    # shellcheck disable=SC2086 # bundle is two words on purpose
    with_timeout 300 as_user "$user" "$home" 1 0 "$CLI_BIN" mcp doctor -f json --deep $bundle > "$report" 2> "$LAST_OUT"
    LAST_RC=$?
    show_out "$LAST_OUT"

    if ! jt doctor "$report" > "$WORK/doctor.$user.tsv" 2>/dev/null; then
        rec "$user" mcp-server verified fail
        rec "$user" mcp-server action "mcp doctor produced no report; run 'armis-cli mcp doctor' as $user"
    else
        while IFS=$'\037' read -r comp editor name status detail fix; do
            [ -n "$comp" ] || continue
            client=""
            [ -z "$editor" ] || client=$(client_from_doctor "$editor")
            case $status in ok | info) continue ;; esac
            c=warn
            [ "$status" = fail ] && c=fail
            if [ -n "$client" ]; then
                if in_list "$client" "$CLIENT_LIST" && ! install_failed "$user" "$client"; then
                    rec "$user" "$client" verified "$c"
                    rec "$user" "$client" action "$(doctor_action "$name" "$detail" "$fix")"
                fi
            else
                rec "$user" mcp-server verified "$c"
                rec "$user" mcp-server action "$(doctor_action "$name" "$detail" "$fix")"
            fi
        done < "$WORK/doctor.$user.tsv"
    fi
    for client in $CLIENT_LIST; do
        in_list "$client" "$ALL_CLIENTS" || continue
        if client_is_ok "$user" "$client"; then rec "$user" "$client" verified ok; fi
    done
    if ! awk -F'\t' -v u="$user" '$1 == u && $2 == "mcp-server" && $3 == "verified" { f = 1 } END { exit f ? 0 : 1 }' "$RESULTS"; then
        rec "$user" mcp-server verified ok
    fi

    if [ "$ARMIS_SAMPLE_SCAN" = 1 ]; then sample_scan "$user" "$home"; fi
}

# doctor_action NAME DETAIL REMEDIATION: one-line action text, capped in length.
doctor_action() {
    local t="$1: $2"
    [ -z "$3" ] || t="$t. $3"
    if [ "${#t}" -gt 300 ]; then t="${t:0:297}..."; fi
    printf '%s' "$t"
}

install_failed() { # install_failed USER CLIENT
    awk -F'\t' -v u="$1" -v c="$2" '$1 == u && $2 == c && $3 == "installed" && $4 == "fail" { f = 1 } END { exit f ? 0 : 1 }' "$RESULTS"
}

# client_is_ok USER CLIENT: installed ok and no verification result yet.
client_is_ok() {
    awk -F'\t' -v u="$1" -v c="$2" '
        $1 == u && $2 == c && $3 == "installed" { i = $4 }
        $1 == u && $2 == c && $3 == "verified" { v = 1 }
        END { exit (i == "ok" && !v) ? 0 : 1 }
    ' "$RESULTS"
}

sample_scan() { # sample_scan USER HOME
    local user=$1 home=$2 dir
    dir=$(mktemp -d "$WORK/sample.XXXXXX")
    chmod 755 "$dir"
    printf 'import hashlib\nprint(hashlib.md5(b"armis-sample").hexdigest())\n' > "$dir/sample.py"
    chmod 644 "$dir/sample.py"
    SEQ=$((SEQ + 1))
    LAST_OUT="$WORK/out.$SEQ"
    with_timeout 600 as_user "$user" "$home" 1 0 "$CLI_BIN" scan repo "$dir" --format json > "$LAST_OUT" 2>&1
    LAST_RC=$?
    # Findings make the scan exit non-zero by design; only a missing result counts as failure.
    if [ "$LAST_RC" -ne 0 ] && ! grep -q '"findings"' "$LAST_OUT"; then
        show_out "$LAST_OUT"
        rec "$user" sample-scan verified fail
        rec "$user" sample-scan action "the sample scan did not complete; check 'armis-cli auth whoami' and the network"
    else
        rec "$user" sample-scan verified ok
    fi
    rec "$user" sample-scan detected yes
    rec "$user" sample-scan installed ok
}

# network check once, as the first user
network_check() { # network_check USER HOME
    [ "$DRY_RUN" -eq 0 ] || return 0
    user_cmd "$1" "$2" 0 0 "$CLI_BIN" mcp doctor --network
    if [ "$LAST_RC" -ne 0 ]; then
        show_out "$LAST_OUT"
        rec "-" armis-cli verified warn
        rec "-" armis-cli action "network check reported problems; run 'armis-cli mcp doctor --network' (proxy, TLS inspection, certificates)"
    fi
}

# ---- uninstall --------------------------------------------------------------

stage_uninstall() { # stage_uninstall USER HOME
    local user=$1 home=$2 client targets="" flags="--force" p repo cfg
    log "[$user] uninstall"
    for client in $CLIENT_LIST; do
        in_list "$client" "$ALL_CLIENTS" || continue
        rec "$user" "$client" detected "$([ -d "$(client_detect_dir "$client" "$home")" ] && echo yes || echo no)"
        targets="$targets $client"
    done
    targets=${targets# }
    [ "$ARMIS_KEEP_CREDENTIALS" = 1 ] && flags="$flags --keep-credentials"

    local args=$targets res="$WORK/uninstall.$user" status detail
    [ "$FULL_UNINSTALL" -eq 0 ] || args=$flags
    : > "$res.tsv"
    if [ "$FULL_UNINSTALL" -eq 0 ] && [ -z "$targets" ]; then
        # A bare `armis-cli uninstall` means everything; nothing here was selected.
        vlog "[$user] no client selected; not running armis-cli uninstall"
    elif [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] would run: armis-cli uninstall $args"
    elif [ -x "$CLI_BIN" ]; then
        SEQ=$((SEQ + 1))
        LAST_OUT="$WORK/out.$SEQ"
        # shellcheck disable=SC2086 # args is a word list
        as_user "$user" "$home" 0 0 "$CLI_BIN" uninstall $args --format json > "$res.json" 2> "$LAST_OUT"
        LAST_RC=$?
        show_out "$LAST_OUT"
        jt result "$res.json" > "$res.tsv" || true
        if [ "$LAST_RC" -ne 0 ]; then
            rec "$user" mcp-server installed fail
            rec "$user" mcp-server action "armis-cli uninstall exited $LAST_RC; see the log"
        else
            rec "$user" mcp-server installed ok
            rec "$user" mcp-server action "uninstalled"
        fi
    else
        rec "$user" mcp-server installed skip
        rec "$user" mcp-server action "armis-cli is not installed; nothing to uninstall through it"
    fi

    for client in $targets; do
        [ "$DRY_RUN" -eq 0 ] || continue
        if [ ! -d "$(client_detect_dir "$client" "$home")" ]; then
            rec "$user" "$client" installed skip
            continue
        fi
        status=$(result_field "$res.tsv" "$client" 2)
        detail=$(result_field "$res.tsv" "$client" 3)
        case $status in
            fail | warn)
                rec "$user" "$client" installed "$status"
                rec "$user" "$client" action "${detail:-could not be removed}" ;;
            *)
                rec "$user" "$client" installed ok
                rec "$user" "$client" verified ok
                rec "$user" "$client" action "removed" ;;
        esac
    done

    # The profile block serves every client: keep it while any client stays registered.
    local keep_profile=0
    for client in $ALL_CLIENTS; do in_list "$client" "$targets" || keep_profile=1; done
    if [ "$FULL_UNINSTALL" -eq 1 ] || [ "$keep_profile" -eq 0 ]; then remove_profiles "$user" "$home"; fi

    if in_list hook "$ENABLED_EXTRAS" && [ -x "$CLI_BIN" ] && [ "$DRY_RUN" -eq 0 ]; then
        while IFS= read -r repo; do
            [ -n "$repo" ] || continue
            [ "$(stat -f %Su "$repo" 2>/dev/null)" = "$user" ] || continue
            # shellcheck disable=SC2016
            user_cmd "$user" "$home" 0 0 /bin/sh -c 'cd "$1" && shift && exec "$@"' sh "$repo" "$CLI_BIN" hook init --remove
            show_out "$LAST_OUT"
        done <<< "$(lines_of_list "$ARMIS_HOOK_REPOS")"
    fi
    if in_list jetbrains "$ENABLED_EXTRAS" && [ "$DRY_RUN" -eq 0 ]; then
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            [ "$(stat -f %Su "$p" 2>/dev/null)" = "$user" ] || continue
            cfg="$p/.jb-mcp.json"
            [ -f "$cfg" ] || continue
            user_cmd "$user" "$home" 0 0 osascript -l JavaScript "$WORK/json_tool.js" delserver "$cfg" mcpServers "$SERVER_KEY"
            show_out "$LAST_OUT"
            rec "$user" jetbrains installed ok
            rec "$user" jetbrains action "removed from $cfg"
        done <<< "$(lines_of_list "$ARMIS_JETBRAINS_PROJECTS")"
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        as_user "$user" "$home" 0 0 /bin/rm -f \
            "$home/.armis/plugins/armis-appsec-mcp/.env.bak" "$home/.armis/plugins/armis-knowledge-mcp/.env.bak"
    fi
}

# ---- report -----------------------------------------------------------------

# compute_exit: 3 > 2 > 1 > 0
compute_exit() {
    local code=0
    if [ "$FORCED_EXIT" -ne 0 ]; then
        echo "$FORCED_EXIT"
        return
    fi
    if awk -F'\t' '$3 == "verified" && $4 == "fail" { f = 1 } END { exit f ? 0 : 1 }' "$RESULTS"; then
        code=2
    elif awk -F'\t' '($3 == "installed" || $3 == "auth" || $3 == "verified") && ($4 == "fail" || $4 == "warn") { f = 1 } END { exit f ? 0 : 1 }' "$RESULTS"; then
        code=1
    fi
    echo "$code"
}

# build_table: one row per (user, component), fields separated by \037 so that
# empty fields survive `read`:
# user component detected installed auth verified action
build_table() {
    awk -F'\t' '
        BEGIN { rank["skip"] = 1; rank["ok"] = 2; rank["warn"] = 3; rank["fail"] = 4 }
        $2 == "_user" {
            if ($3 == "auth") auth[$1] = $4
            if ($3 == "action") uact[$1] = (uact[$1] == "" ? $4 : uact[$1] "; " $4)
            next
        }
        {
            k = $1 SUBSEP $2
            if (!(k in seen)) { seen[k] = 1; order[++n] = k; u[k] = $1; c[k] = $2 }
            if ($3 == "action") { act[k] = (act[k] == "" ? $4 : act[k] "; " $4) }
            else if ($3 == "detected") det[k] = $4
            else if ($3 == "installed") { if (rank[$4] >= rank[ins[k]]) ins[k] = $4 }
            else if ($3 == "verified") { if (rank[$4] >= rank[ver[k]]) ver[k] = $4 }
        }
        END {
            for (i = 1; i <= n; i++) {
                k = order[i]
                a = (u[k] in auth) ? auth[u[k]] : ""
                if (c[k] == "armis-cli" || c[k] == "preflight" || det[k] == "no") a = ""
                action = act[k]
                if (c[k] == "mcp-server" && uact[u[k]] != "") action = (action == "" ? uact[u[k]] : action "; " uact[u[k]])
                printf "%s\037%s\037%s\037%s\037%s\037%s\037%s\n", u[k], c[k], det[k], ins[k], a, ver[k], action
            }
        }
    ' "$RESULTS"
}

print_matrix() { # print_matrix TABLEFILE ENDPOINT
    local u c d i a v act
    {
        printf 'Endpoint\tUser\tComponent\tDetected\tInstalled\tAuth\tVerified\tAction needed\n'
        while IFS=$'\037' read -r u c d i a v act; do
            if [ "$d" = no ] && [ "$i" = skip ]; then i="skip (not installed)"; fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "${u/#-/(machine)}" "$c" "${d:--}" "${i:--}" \
                "${a:--}" "${v:--}" "${act:--}"
        done < "$1"
    } | column -t -s $'\t'
}

write_report() { # write_report TABLEFILE ENDPOINT SERIAL CODE STATUS
    local json=${ARMIS_REPORT_PATH%.json}.json
    mkdir -p "$(dirname "$json")" 2>/dev/null || return 1
    jt report "$1" "$json" endpoint "$2" serial "$3" timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        script_version "$SCRIPT_VERSION" cli_version "$ARMIS_CLI_VERSION" mcp_version "${ARMIS_MCP_VERSION:-latest}" \
        cosign_verified "$CLI_COSIGN" mode "$([ "$DO_UNINSTALL" -eq 1 ] && echo uninstall || echo install)" \
        exit_code "$4" status "$5" || return 1
    chmod 644 "$json"
    log "report: $json"
}

stage_report() {
    local code status table endpoint serial n_components n_failing
    table="$WORK/table.tsv"
    build_table > "$table"
    code=$(compute_exit)
    case $code in
        0) status=ok ;;
        1) status=partial ;;
        *) status=failed ;;
    esac
    endpoint=$(scutil --get ComputerName 2>/dev/null || hostname)
    serial=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/ { print $4 }')
    print_matrix "$table" "$endpoint"
    n_components=$(awk -F'\037' 'END { print NR }' "$table")
    n_failing=$(awk -F'\037' '$4 == "fail" || $4 == "warn" || $5 == "fail" || $5 == "warn" || $6 == "fail" || $6 == "warn" { n++ } END { print n + 0 }' "$table")
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] no report written"
    elif [ -n "$ARMIS_REPORT_PATH" ]; then
        write_report "$table" "$endpoint" "$serial" "$code" "$status" || warn "could not write the report to $ARMIS_REPORT_PATH"
    fi
    printf 'ARMIS_STATUS=%s components=%s failing=%s\n' "$status" "$n_components" "$n_failing"
    FINAL_CODE=$code
}

# shellcheck disable=SC2329 # runs from the EXIT trap
cleanup() {
    [ -z "$WORK" ] || rm -rf "$WORK"
}

finish() {
    stage_report
    exit "$FINAL_CODE"
}

FINAL_CODE=0

# ---- arguments ---------------------------------------------------------------

usage() {
    awk 'NR > 1 && /^set -u$/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"
    echo ""
    echo "Configuration (environment variables):"
    awk '/^# ---- CONFIG BEGIN/ { on = 1; next } /^# ---- CONFIG END/ { on = 0 } on { print }' "$0"
}

while [ $# -gt 0 ]; do
    case $1 in
        -h | --help) usage; exit 0 ;;
        --dry-run) DRY_RUN=1 ;;
        --uninstall) DO_UNINSTALL=1 ;;
        --non-interactive) NONINTERACTIVE=1 ;;
        --verbose) VERBOSE=1 ;;
        --bundle) WANT_BUNDLE=1 ;;
        --only) [ $# -ge 2 ] || die_usage "--only needs a value"; ONLY=$(split_list "$2"); shift ;;
        --skip) [ $# -ge 2 ] || die_usage "--skip needs a value"; SKIP=$(split_list "$2"); shift ;;
        --report) [ $# -ge 2 ] || die_usage "--report needs a path"; ARMIS_REPORT_PATH=$2; shift ;;
        *) die_usage "unknown option: $1" ;;
    esac
    shift
done

[ -t 0 ] || NONINTERACTIVE=1

[ -z "$ARMIS_TENANT_ID" ] || export ARMIS_TENANT_ID
[ -z "$ARMIS_REGION" ] || export ARMIS_REGION

for n in $ONLY $SKIP; do
    in_list "$n" "$VALID_NAMES" || die_usage "unknown component '$n' (valid: $VALID_NAMES)"
done

ARMIS_CLIENTS=$(split_list "$ARMIS_CLIENTS")
for n in $ARMIS_CLIENTS; do
    in_list "$n" "$ALL_CLIENTS" || die_usage "unknown client '$n' in ARMIS_CLIENTS (valid: $ALL_CLIENTS)"
done

case $ARMIS_AUTH_MODE in client-credentials | sso) ;; *) die_usage "ARMIS_AUTH_MODE must be client-credentials or sso" ;; esac
case $ARMIS_SSO_LOGIN in auto | now | skip) ;; *) die_usage "ARMIS_SSO_LOGIN must be auto, now or skip" ;; esac
for v in ARMIS_ALLOW_LATEST ARMIS_HOOK_ENABLE ARMIS_HOOK_FAIL_OPEN ARMIS_WITH_KNOWLEDGE ARMIS_SAMPLE_SCAN ARMIS_KEEP_CREDENTIALS ARMIS_REMOVE_CLI; do
    case ${!v} in 0 | 1) ;; *) die_usage "$v must be 0 or 1" ;; esac
done
[ -z "$ARMIS_TENANT_ID" ] || require_ident ARMIS_TENANT_ID "$ARMIS_TENANT_ID"
[ -z "$ARMIS_REGION" ] || require_ident ARMIS_REGION "$ARMIS_REGION"
if [ -n "$ARMIS_MCP_VERSION" ]; then
    ARMIS_MCP_VERSION=${ARMIS_MCP_VERSION#v}
    printf '%s' "$ARMIS_MCP_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
        || die_usage "ARMIS_MCP_VERSION must look like 1.4.2"
fi

if [ "$DO_UNINSTALL" -eq 0 ]; then
    if [ -z "$ARMIS_CLI_VERSION" ]; then
        if [ "$NONINTERACTIVE" -eq 1 ] && [ "$ARMIS_ALLOW_LATEST" != 1 ]; then
            die_usage "ARMIS_CLI_VERSION is required with --non-interactive (or set ARMIS_ALLOW_LATEST=1)"
        fi
        ARMIS_CLI_VERSION=latest
    fi
    if [ "$ARMIS_CLI_VERSION" != latest ]; then
        ARMIS_CLI_VERSION=${ARMIS_CLI_VERSION#v}
        printf '%s' "$ARMIS_CLI_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' \
            || die_usage "ARMIS_CLI_VERSION must look like 1.27.0"
        # This script reads `install --format json`, added in this release.
        if awk -v a="${ARMIS_CLI_VERSION%%-*}" -v b="$MIN_CLI_VERSION" 'BEGIN {
            split(a, x, "."); split(b, y, ".")
            for (i = 1; i <= 3; i++) if (x[i] + 0 != y[i] + 0) exit !(x[i] + 0 < y[i] + 0)
            exit 1 }'; then
            die_usage "ARMIS_CLI_VERSION $ARMIS_CLI_VERSION is too old; this script needs $MIN_CLI_VERSION or later"
        fi
    fi
    if [ "$ARMIS_AUTH_MODE" = sso ] && [ -z "$ARMIS_TENANT_ID" ]; then
        die_usage "ARMIS_TENANT_ID is required with ARMIS_AUTH_MODE=sso"
    fi
    if [ "$ARMIS_AUTH_MODE" = client-credentials ]; then load_credentials; fi
fi

# The clients and extras this run touches.
CLIENT_LIST=""
if [ -n "$ONLY" ]; then
    for n in $ONLY; do in_list "$n" "$ALL_CLIENTS" && CLIENT_LIST="$CLIENT_LIST $n"; done
else
    CLIENT_LIST=$ARMIS_CLIENTS
fi
CLIENT_LIST=$(for n in $CLIENT_LIST; do in_list "$n" "$SKIP" || printf '%s ' "$n"; done)
CLIENT_LIST=${CLIENT_LIST% }

ENABLED_EXTRAS=""
for n in jetbrains hook; do
    in_list "$n" "$SKIP" && continue
    if [ -n "$ONLY" ]; then
        in_list "$n" "$ONLY" && ENABLED_EXTRAS="$ENABLED_EXTRAS $n"
    elif [ "$n" = jetbrains ] && [ -n "$ARMIS_JETBRAINS_PROJECTS" ]; then
        ENABLED_EXTRAS="$ENABLED_EXTRAS $n"
    elif [ "$n" = hook ] && [ "$ARMIS_HOOK_ENABLE" = 1 ]; then
        ENABLED_EXTRAS="$ENABLED_EXTRAS $n"
    fi
done
# A bare run (no --only) still reports on JetBrains, as a hint.
if [ -z "$ONLY" ] && ! in_list jetbrains "$SKIP" && ! in_list jetbrains "$ENABLED_EXTRAS"; then
    ENABLED_EXTRAS="$ENABLED_EXTRAS jetbrains"
fi
ENABLED_EXTRAS=${ENABLED_EXTRAS# }

# A full uninstall (nothing selected) removes everything; --only/--skip narrows it.
FULL_UNINSTALL=1
if [ -n "$ONLY" ] || [ -n "$SKIP" ]; then FULL_UNINSTALL=0; fi

if [ "$IS_ROOT" -eq 1 ]; then
    CLI_DIR=${ARMIS_INSTALL_DIR:-/usr/local/bin}
    LOG_DIR=${ARMIS_LOG_DIR:-/Library/Logs/Armis}
else
    CLI_DIR=${ARMIS_INSTALL_DIR:-$HOME/.local/bin}
    LOG_DIR=${ARMIS_LOG_DIR:-$HOME/Library/Logs/Armis}
fi
CLI_BIN="$CLI_DIR/armis-cli"

[ -n "${TMPDIR:-}" ] || TMPDIR=/tmp
WORK=$(mktemp -d "${TMPDIR%/}/armis-setup.XXXXXX") || die_usage "cannot create a temporary directory"
chmod 755 "$WORK"
trap cleanup EXIT
RESULTS="$WORK/results.tsv"
: > "$RESULTS"
chmod 600 "$RESULTS"
write_json_tool

if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$LOG_DIR" 2>/dev/null && chmod 755 "$LOG_DIR" 2>/dev/null
    if [ -d "$LOG_DIR" ] && [ -w "$LOG_DIR" ]; then
        LOG_FILE="$LOG_DIR/enterprise-setup-$RUN_TS.log"
        : > "$LOG_FILE"
        chmod 644 "$LOG_FILE"
    fi
    if [ -z "$ARMIS_REPORT_PATH" ] && [ -d "$LOG_DIR" ]; then
        ARMIS_REPORT_PATH="$LOG_DIR/enterprise-setup-$RUN_TS"
    fi
fi

log "armis enterprise-setup $SCRIPT_VERSION$([ "$DRY_RUN" -eq 1 ] && echo ' (dry run)')"

# ---- main -------------------------------------------------------------------

stage_preflight

USERS=$(resolve_users)
if [ -z "$USERS" ]; then
    rec "-" users installed warn
    rec "-" users action "no user account to configure (nobody logged in?); set ARMIS_TARGET_USERS or re-run when a user is logged in"
fi

for u in $USERS; do
    require_ident user "$u"
done

if [ "$DO_UNINSTALL" -eq 1 ]; then
    for u in $USERS; do
        id "$u" > /dev/null 2>&1 || { rec "$u" mcp-server installed fail; rec "$u" mcp-server action "unknown user $u"; continue; }
        h=$(user_home "$u")
        if [ -z "$h" ] || [ ! -d "$h" ]; then
            rec "$u" mcp-server installed fail
            rec "$u" mcp-server action "no home directory for $u"
            continue
        fi
        stage_uninstall "$u" "$h"
    done
    if [ "$ARMIS_REMOVE_CLI" = 1 ] && [ "$IS_ROOT" -eq 1 ] && [ "$FULL_UNINSTALL" -eq 1 ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] would remove $CLI_BIN"
        else
            rm -f "$CLI_BIN" && rec "-" armis-cli installed ok && rec "-" armis-cli action "removed $CLI_BIN"
        fi
    fi
    finish
fi

stage_cli

FIRST_USER=""
for u in $USERS; do
    id "$u" > /dev/null 2>&1 || { rec "$u" mcp-server installed fail; rec "$u" mcp-server action "unknown user $u"; continue; }
    h=$(user_home "$u")
    if [ -z "$h" ] || [ ! -d "$h" ]; then
        rec "$u" mcp-server installed fail
        rec "$u" mcp-server action "no home directory for $u"
        continue
    fi
    if [ -z "$FIRST_USER" ]; then
        FIRST_USER=$u
        network_check "$u" "$h"
    fi
    stage_auth "$u" "$h"
    stage_mcp "$u" "$h"
    stage_jetbrains "$u" "$h"
    stage_hook "$u" "$h"
    stage_verify "$u" "$h"
done

finish

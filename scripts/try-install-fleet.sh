#!/usr/bin/env bash
# Exercise `armis-cli install` against every supported agent at once.
#
# Editor detection is directory-presence based (install.Editor.IsDetected stats
# the parent of each editor's config file), so creating those directories under
# a sandboxed HOME makes the real binary detect the whole fleet on a machine
# where only two or three editors are actually installed.
#
# SAFETY: everything happens under a fresh mktemp HOME. Your real
# ~/.cursor, ~/.codex, ~/.claude, and editor configs are never read or written.
#
# Usage:
#   scripts/try-install-fleet.sh                 # install scanner + knowledge, then summarize
#   scripts/try-install-fleet.sh --scanner-only  # skip knowledge
#   scripts/try-install-fleet.sh --keep          # don't delete the sandbox on exit
#   scripts/try-install-fleet.sh --uninstall     # also run uninstall and re-summarize
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/bin/armis-cli"

WITH_KNOWLEDGE=1
KEEP_SANDBOX=0
RUN_UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --scanner-only) WITH_KNOWLEDGE=0 ;;
        --keep) KEEP_SANDBOX=1 ;;
        --uninstall) RUN_UNINSTALL=1 ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN — run 'make build' first." >&2
    exit 1
fi

SANDBOX="$(mktemp -d)"
cleanup() {
    if [ "$KEEP_SANDBOX" -eq 1 ]; then
        echo ""
        echo "Sandbox kept at: $SANDBOX"
    else
        rm -rf "$SANDBOX"
    fi
}
trap cleanup EXIT

# Mirror internal/install/editors.go::defaultConfigPath. appSupportPath differs
# per OS, so resolve that base the same way the Go code does.
case "$(uname -s)" in
    Darwin) APP_SUPPORT="$SANDBOX/Library/Application Support" ;;
    *)      APP_SUPPORT="${XDG_CONFIG_HOME:-$SANDBOX/.config}"
            # A sandboxed run must not inherit a real XDG_CONFIG_HOME.
            APP_SUPPORT="$SANDBOX/.config" ;;
esac

# editor-id => config file path, relative to the sandbox HOME.
AGENT_CONFIGS=(
    "vscode|$APP_SUPPORT/Code/User/mcp.json"
    "cursor|$SANDBOX/.cursor/mcp.json"
    "windsurf|$SANDBOX/.codeium/windsurf/mcp_config.json"
    "zed|$APP_SUPPORT/Zed/settings.json"
    "cline|$APP_SUPPORT/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    "amazonq|$SANDBOX/.aws/amazonq/mcp.json"
    "continue|$SANDBOX/.continue/mcpServers/armis-appsec.json"
    "antigravity|$SANDBOX/.gemini/antigravity/mcp_config.json"
    "gemini|$SANDBOX/.gemini/settings.json"
    "roocode|$SANDBOX/.roo-cline/mcp_settings.json"
    "junie|$SANDBOX/.junie/mcp/mcp.json"
    "claude-desktop|$APP_SUPPORT/Claude/claude_desktop_config.json"
    "copilot|$SANDBOX/.copilot/mcp-config.json"
    "codex|$SANDBOX/.codex/config.toml"
)

echo "Sandbox HOME: $SANDBOX"
echo "Creating config directories for $((${#AGENT_CONFIGS[@]} + 1)) agents..."
for entry in "${AGENT_CONFIGS[@]}"; do
    mkdir -p "$(dirname "${entry#*|}")"
done
# Claude Code is detected by ~/.claude existing, not by a config file.
mkdir -p "$SANDBOX/.claude"

echo ""
echo "=== Running install ==="
INSTALL_ARGS=(install --non-interactive)
[ "$WITH_KNOWLEDGE" -eq 1 ] && INSTALL_ARGS+=(--with-knowledge)

set +e
env HOME="$SANDBOX" USERPROFILE="$SANDBOX" XDG_CONFIG_HOME="$SANDBOX/.config" \
    "$BIN" "${INSTALL_ARGS[@]}"
INSTALL_EXIT=$?
set -e
echo "install exit code: $INSTALL_EXIT"

summarize() {
    local label=$1
    echo ""
    echo "=== $label ==="
    printf '%-16s %-10s %-10s %s\n' AGENT SCANNER KNOWLEDGE CONFIG
    for entry in "${AGENT_CONFIGS[@]}"; do
        local id=${entry%%|*} cfg=${entry#*|}
        local scanner="-" knowledge="-" state="(no file)"
        if [ -f "$cfg" ]; then
            state="ok"
            # Codex uses TOML section headers; the rest are JSON server keys.
            if [ "$id" = "codex" ]; then
                grep -q 'mcp_servers.armis_scanner' "$cfg" && scanner="yes"
                grep -q 'mcp_servers.armis_knowledge' "$cfg" && knowledge="yes"
            else
                grep -q '"armis-appsec"' "$cfg" && scanner="yes"
                grep -q '"armis-knowledge"' "$cfg" && knowledge="yes"
                python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$cfg" 2>/dev/null \
                    || state="INVALID JSON"
            fi
        fi
        printf '%-16s %-10s %-10s %s\n' "$id" "$scanner" "$knowledge" "$state"
    done

    local ck="$SANDBOX/.claude/plugins/known_marketplaces.json"
    local cs="-" ckn="-"
    if [ -f "$ck" ]; then
        grep -q 'armis-appsec-mcp' "$ck" && cs="yes"
        grep -q 'armis-knowledge' "$ck" && ckn="yes"
    fi
    printf '%-16s %-10s %-10s %s\n' "claude-code" "$cs" "$ckn" "$([ -f "$ck" ] && echo ok || echo '(no file)')"

    echo ""
    echo "Plugin dirs:"
    for d in armis-appsec-mcp armis-knowledge-mcp; do
        if [ -d "$SANDBOX/.armis/plugins/$d" ]; then
            echo "  $d: present"
        else
            echo "  $d: absent"
        fi
    done
}

summarize "After install"

if [ "$RUN_UNINSTALL" -eq 1 ]; then
    echo ""
    echo "=== Running uninstall ==="
    set +e
    env HOME="$SANDBOX" USERPROFILE="$SANDBOX" XDG_CONFIG_HOME="$SANDBOX/.config" \
        "$BIN" uninstall --force
    echo "uninstall exit code: $?"
    set -e
    summarize "After uninstall"
fi

#!/usr/bin/env bats
# Hermetic tests for scripts/enterprise-setup.sh.
#
# Every test runs the script under /bin/bash (3.2 on macOS) with a temporary
# HOME, log directory and install directory, and with fake armis-cli, curl,
# sudo, id and pgrep first on PATH. Nothing touches the real machine.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/enterprise-setup.sh"
STUBS="$BATS_TEST_DIRNAME/stubs"
PYSTUB="$BATS_TEST_DIRNAME/pystub"
SECRET="SUPERSECRET_abc123"

setup() {
    T="$BATS_TEST_TMPDIR"
    export HOME="$T/home"
    export TMPDIR="$T/tmp"
    export STUB_LOG="$T/stublog"
    INSTALL_DIR="$T/bin"
    LOG_DIR="$T/logs"
    mkdir -p "$HOME" "$TMPDIR" "$STUB_LOG" "$INSTALL_DIR" "$LOG_DIR"

    export PATH="$STUBS:/usr/bin:/bin:/usr/sbin:/sbin"
    export ARMIS_SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
    export ARMIS_EXTRA_PATH="$STUBS:$PYSTUB"
    export ARMIS_INSTALL_DIR="$INSTALL_DIR"
    export ARMIS_LOG_DIR="$LOG_DIR"
    export ARMIS_CLI_VERSION="1.27.0"
    export ARMIS_SAMPLE_SCAN=0
    export ARMIS_CLIENT_ID="test-id"
    export ARMIS_CLIENT_SECRET="$SECRET"
    unset ARMIS_TENANT_ID ARMIS_REGION ARMIS_MCP_VERSION ARMIS_CREDENTIALS_FILE ARMIS_API_URL
    unset ARMIS_JETBRAINS_PROJECTS ARMIS_HOOK_ENABLE ARMIS_HOOK_REPOS HTTPS_PROXY SSL_CERT_FILE

    install_fake_cli
}

# The CLI is already installed at the pinned version unless a test removes it.
install_fake_cli() {
    cp "$STUBS/armis-cli" "$STUBS/merge.js" "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/armis-cli"
}

make_clients() {
    mkdir -p "$HOME/.cursor" "$HOME/.codex" "$HOME/.claude" "$HOME/.copilot" "$HOME/.junie/mcp" \
        "$HOME/.gemini/config" "$HOME/Library/Application Support/Code/User"
}

setup_run() {
    run /bin/bash "$SCRIPT" --non-interactive "$@"
}

tree_hash() {
    (cd "$1" && find . -type f -exec shasum {} + | LC_ALL=C sort | shasum)
}

backups() {
    find "$HOME" -name '*.armis-bak.*' 2>/dev/null | LC_ALL=C sort
}

@test "unknown flag exits 3" {
    run /bin/bash "$SCRIPT" --bogus
    [ "$status" -eq 3 ]
    [[ "$output" == *"unknown option"* ]]
}

@test "unknown component in --only exits 3" {
    setup_run --only emacs
    [ "$status" -eq 3 ]
}

@test "--non-interactive without a CLI version exits 3" {
    unset ARMIS_CLI_VERSION
    setup_run
    [ "$status" -eq 3 ]
    [[ "$output" == *"ARMIS_CLI_VERSION is required"* ]]
}

@test "ARMIS_ALLOW_LATEST permits an unpinned CLI" {
    unset ARMIS_CLI_VERSION
    export ARMIS_ALLOW_LATEST=1
    rm -f "$INSTALL_DIR/armis-cli"
    make_clients
    setup_run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"would download"* ]]
}

@test "--help prints the usage and the config block" {
    run /bin/bash "$SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Exit codes:"* ]]
    [[ "$output" == *"ARMIS_AUTH_MODE"* ]]
    [[ "$output" == *"ARMIS_JETBRAINS_PROJECTS"* ]]
}

@test "preflight failure (no network) exits 3" {
    export STUB_CURL_FAIL=1
    setup_run
    [ "$status" -eq 3 ]
    [[ "$output" == *"cannot reach"* ]]
    [[ "$output" == *"ARMIS_STATUS=failed"* ]]
}

@test "dry run changes nothing under HOME or the install dir" {
    make_clients
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/.cursor/mcp.json"
    rm -f "$INSTALL_DIR/armis-cli" "$INSTALL_DIR/merge.js"
    before_home=$(tree_hash "$HOME")
    before_bin=$(tree_hash "$INSTALL_DIR")
    setup_run --dry-run --report "$T/dry"
    [ "$status" -eq 0 ]
    [ "$before_home" = "$(tree_hash "$HOME")" ]
    [ "$before_bin" = "$(tree_hash "$INSTALL_DIR")" ]
    [ ! -e "$T/dry.json" ]
    [ -z "$(ls -A "$LOG_DIR")" ]
}

@test "installs the CLI from the matching tag when missing" {
    rm -f "$INSTALL_DIR/armis-cli" "$INSTALL_DIR/merge.js"
    setup_run --only cursor
    [ "$status" -eq 0 ]
    [ -x "$INSTALL_DIR/armis-cli" ]
    grep -q 'armis-cli/v1.27.0/scripts/install.sh' "$STUB_LOG/curl.urls"
}

@test "a checksum failure in the installer exits 3" {
    rm -f "$INSTALL_DIR/armis-cli"
    export STUB_CHECKSUM_FAIL=1
    setup_run
    [ "$status" -eq 3 ]
    [[ "$output" == *"checksum"* ]]
}

@test "a signature failure in the installer exits 3" {
    rm -f "$INSTALL_DIR/armis-cli"
    export STUB_SIGNATURE_FAIL=1
    setup_run
    [ "$status" -eq 3 ]
    [[ "$output" == *"signature verification failed"* ]]
}

@test "an installed CLI whose version only contains the pin is reinstalled" {
    export STUB_CLI_VERSION=11.27.0
    make_clients
    setup_run --only cursor
    grep -q 'armis-cli/v1.27.0/scripts/install.sh' "$STUB_LOG/curl.urls"
    [ "$status" -eq 2 ]
    [[ "$output" == *"does not report version 1.27.0"* ]]
}

@test "registers every detected client and exits 0" {
    make_clients
    setup_run --report "$T/rep"
    [ "$status" -eq 0 ]
    [[ "$output" == *"ARMIS_STATUS=ok"* ]]
    grep -q armis-appsec "$HOME/.cursor/mcp.json"
    grep -q armis-appsec "$HOME/Library/Application Support/Code/User/mcp.json"
    grep -q armis-appsec "$HOME/.copilot/mcp-config.json"
    grep -q armis-appsec "$HOME/.gemini/config/mcp_config.json"
    grep -q armis-appsec "$HOME/.junie/mcp/mcp.json"
    grep -q armis_scanner "$HOME/.codex/config.toml"
    grep -q 'armis-appsec@armis-appsec-mcp' "$HOME/.claude/plugins/installed_plugins.json"
}

@test "clients that are not installed are reported as skipped" {
    mkdir -p "$HOME/.cursor"
    setup_run
    [ "$status" -eq 0 ]
    [[ "$output" == *"skip (not installed)"* ]]
    ! grep -q 'install .*vscode' "$STUB_LOG/armis-cli.argv"
}

@test "a second run makes no new backups and does not reinstall the CLI" {
    make_clients
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/.cursor/mcp.json"
    setup_run
    [ "$status" -eq 0 ]
    first=$(backups)
    : > "$STUB_LOG/curl.urls"
    sleep 1
    setup_run
    [ "$status" -eq 0 ]
    [ "$first" = "$(backups)" ]
    ! grep -q 'install.sh' "$STUB_LOG/curl.urls"
}

@test "servers already in a config are kept" {
    make_clients
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/.cursor/mcp.json"
    setup_run
    [ "$status" -eq 0 ]
    grep -q '"other"' "$HOME/.cursor/mcp.json"
    grep -q armis-appsec "$HOME/.cursor/mcp.json"
    [ -n "$(backups)" ]
}

@test "a malformed config is skipped and left untouched" {
    make_clients
    printf '{broken' > "$HOME/.cursor/mcp.json"
    cp "$HOME/.cursor/mcp.json" "$T/original"
    setup_run
    [ "$status" -eq 1 ]
    cmp "$HOME/.cursor/mcp.json" "$T/original"
    [[ "$output" == *"is not valid JSON"* ]]
    grep -q armis-appsec "$HOME/.copilot/mcp-config.json"
}

@test "a config with comments and trailing commas is accepted" {
    make_clients
    printf '// mine\n{"mcpServers": {"other": {"command": "x", },},}\n' > "$HOME/.cursor/mcp.json"
    run /bin/bash "$SCRIPT" --non-interactive --only copilot
    [ "$status" -eq 0 ]
}

@test "a client failure in the install report is recorded and restored, even with exit 0" {
    make_clients
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/.cursor/mcp.json"
    cp "$HOME/.cursor/mcp.json" "$T/original"
    export STUB_FAIL_TARGETS="cursor" STUB_FAIL_EXIT=0
    setup_run --only cursor,vscode --report "$T/rep"
    [ "$status" -eq 1 ]
    cmp "$HOME/.cursor/mcp.json" "$T/original"
    grep -q armis-appsec "$HOME/Library/Application Support/Code/User/mcp.json"
    rep=$(tr -d ' \n' < "$T/rep.json")
    [[ "$rep" == *'"user":"-","component":"armis-cli"'* ]]
    [[ "$rep" == *'"component":"cursor","detected":"yes","installed":"fail","auth":"ok","verified":"","action":"boom'* ]]
    [[ "$rep" == *'"component":"vscode","detected":"yes","installed":"ok"'* ]]
}

@test "a failing doctor check exits 2" {
    make_clients
    cat > "$T/doctor.json" <<'EOF'
{"checks":[{"component":"scanner","editor":"Cursor","name":"Cursor","status":"fail","detail":"server did not start","remediation":"Run: armis-cli mcp doctor --fix"}]}
EOF
    export STUB_DOCTOR_JSON="$T/doctor.json" STUB_DOCTOR_EXIT=1
    setup_run --only cursor
    [ "$status" -eq 2 ]
    [[ "$output" == *"server did not start"* ]]
}

@test "missing Python is a warning with exit 1 and no registration" {
    make_clients
    export ARMIS_EXTRA_PATH="$STUBS"
    setup_run --only cursor
    [ "$status" -eq 1 ]
    [[ "$output" == *"Python 3.11+"* ]]
    ! grep -q armis-appsec "$HOME/.cursor/mcp.json" 2>/dev/null
}

@test "missing Python skips mcp doctor, so a failing doctor does not turn it into exit 2" {
    make_clients
    export ARMIS_EXTRA_PATH="$STUBS"
    cat > "$T/doctor.json" <<'EOF'
{"checks":[{"component":"scanner","name":"python venv","status":"fail","detail":"no venv"}]}
EOF
    export STUB_DOCTOR_JSON="$T/doctor.json" STUB_DOCTOR_EXIT=1
    setup_run --only cursor
    [ "$status" -eq 1 ]
    ! grep -q '^mcp doctor -f json' "$STUB_LOG/armis-cli.argv"
}

@test "the client secret never reaches logs, reports or arguments" {
    make_clients
    export STUB_ROOT=1
    setup_run --report "$T/rep"
    [ "$status" -eq 0 ]
    [[ "$output" != *"$SECRET"* ]]
    ! grep -rq "$SECRET" "$LOG_DIR" "$T/rep.json" "$STUB_LOG/armis-cli.argv" "$STUB_LOG/sudo.argv"
    grep -q 'preserve-env=.*ARMIS_CLIENT_SECRET' "$STUB_LOG/sudo.argv"
    grep -q '^secret-in-env: install' "$STUB_LOG/env.flags"
}

@test "as root, files in the developer's home are written by the developer, not root" {
    make_clients
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/.cursor/mcp.json"
    mkdir -p "$HOME/.armis/plugins/armis-appsec-mcp"
    printf 'ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=OLDSECRET\n' > "$HOME/.armis/plugins/armis-appsec-mcp/.env"
    export STUB_ROOT=1 ARMIS_TENANT_ID=acme
    setup_run --only cursor
    [ "$status" -eq 0 ]
    grep -q "^-n -H -u $(id -un) .* /bin/sh -c umask 077; cp -p .*/.cursor/mcp.json " "$STUB_LOG/sudo.argv"
    # sudo.argv holds one line per argv line; the multi-line scripts end in "exit $rc".
    grep -q 'exit $rc sh .*/\.zshenv # >>> armis-cli' "$STUB_LOG/sudo.argv"
    grep -q 'install cursor --format json --rotate-credentials' "$STUB_LOG/sudo.argv"
    grep -q '^ARMIS_CLIENT_ID=test-id$' "$HOME/.armis/plugins/armis-appsec-mcp/.env"
    grep -q "ARMIS_TENANT_ID='acme'" "$HOME/.zshenv"
}

@test "as root, ARMIS_API_URL and lowercase proxy variables reach armis-cli" {
    make_clients
    export STUB_ROOT=1
    setup_run --only cursor
    [ "$status" -eq 0 ]
    grep -q 'preserve-env=.*ARMIS_API_URL' "$STUB_LOG/sudo.argv"
    grep -q 'preserve-env=.*https_proxy' "$STUB_LOG/sudo.argv"
    grep -q 'preserve-env=.*no_proxy' "$STUB_LOG/sudo.argv"
}

@test "credentials are written at 0600 and rotated in every .env without leaving .bak copies" {
    make_clients
    plugin="$HOME/.armis/plugins/armis-appsec-mcp"
    claude="$HOME/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/latest"
    mkdir -p "$plugin" "$claude"
    for d in "$plugin" "$claude"; do
        printf 'ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=OLDSECRET\nHTTPS_PROXY=http://proxy:3128\n' > "$d/.env"
        cp "$d/.env" "$d/.env.bak"
        chmod 644 "$d/.env"
    done
    setup_run --only cursor,claude
    [ "$status" -eq 0 ]
    for d in "$plugin" "$claude"; do
        grep -q '^ARMIS_CLIENT_ID=test-id$' "$d/.env"
        grep -q "^ARMIS_CLIENT_SECRET=$SECRET\$" "$d/.env"
        grep -q '^HTTPS_PROXY=http://proxy:3128$' "$d/.env"
        [ "$(stat -f %Lp "$d/.env")" = 600 ]
        [ ! -e "$d/.env.bak" ]
    done
    ! grep -rq OLDSECRET "$HOME"
}

@test "a dry run leaves .env files and their .bak copies alone" {
    make_clients
    plugin="$HOME/.armis/plugins/armis-appsec-mcp"
    mkdir -p "$plugin"
    printf 'ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=OLDSECRET\n' > "$plugin/.env"
    cp "$plugin/.env" "$plugin/.env.bak"
    chmod 644 "$plugin/.env"
    before=$(tree_hash "$HOME")
    setup_run --dry-run --only cursor
    [ "$status" -eq 0 ]
    [ "$before" = "$(tree_hash "$HOME")" ]
    [ "$(stat -f %Lp "$plugin/.env")" = 644 ]
}

@test "credentials from a file need mode 0600" {
    unset ARMIS_CLIENT_ID ARMIS_CLIENT_SECRET
    printf 'ARMIS_CLIENT_ID=file-id\nARMIS_CLIENT_SECRET=file-secret\n' > "$T/creds"
    chmod 644 "$T/creds"
    export ARMIS_CREDENTIALS_FILE="$T/creds"
    setup_run
    [ "$status" -eq 3 ]
    [[ "$output" == *"must be 600 or 400"* ]]
    chmod 600 "$T/creds"
    make_clients
    setup_run --only cursor
    [ "$status" -eq 0 ]
    grep -q '^ARMIS_CLIENT_ID=file-id$' "$HOME/.armis/plugins/armis-appsec-mcp/.env"
}

@test "rejected credentials mark auth as failed" {
    make_clients
    export STUB_WHOAMI_FAIL=1
    setup_run --only cursor
    [ "$status" -eq 1 ]
    [[ "$output" == *"credentials were rejected"* ]]
}

@test "sso mode without a session reports a pending sign-in" {
    make_clients
    unset ARMIS_CLIENT_ID ARMIS_CLIENT_SECRET
    export ARMIS_AUTH_MODE=sso ARMIS_TENANT_ID=acme ARMIS_SSO_LOGIN=skip
    setup_run --only cursor
    [ "$status" -eq 1 ]
    [[ "$output" == *"armis-cli auth login"* ]]
    grep -q "ARMIS_DEFAULT_AUTH_METHOD='SSO'" "$HOME/.zshenv"
}

@test "--only and --skip choose the clients" {
    make_clients
    setup_run --only cursor,junie
    [ "$status" -eq 0 ]
    grep -q 'install cursor junie ' "$STUB_LOG/armis-cli.argv"
    : > "$STUB_LOG/armis-cli.argv"
    setup_run --skip cursor,codex,claude
    [ "$status" -eq 0 ]
    line=$(grep '^install .*--format json' "$STUB_LOG/armis-cli.argv" | head -n 1)
    [[ "$line" != *cursor* ]]
    [[ "$line" == *vscode* ]]
}

@test "--report writes the JSON report" {
    make_clients
    setup_run --only cursor --report "$T/out.json"
    [ "$status" -eq 0 ]
    [ -f "$T/out.json" ] && [ ! -e "$T/out.csv" ]
    grep -q '"exit_code": 0' "$T/out.json"
    grep -q '"component": "cursor"' "$T/out.json"
}

@test "the MCP version is passed through when the CLI supports pinning" {
    make_clients
    export ARMIS_MCP_VERSION=v1.4.2
    setup_run --only cursor
    [ "$status" -eq 0 ]
    grep -q 'install cursor --format json --plugin-version 1.4.2' "$STUB_LOG/armis-cli.argv"
}

@test "a CLI version older than the minimum is rejected before any download" {
    export ARMIS_CLI_VERSION=1.26.0
    setup_run --only cursor
    [ "$status" -eq 3 ]
    [[ "$output" == *"needs 1.27.0 or later"* ]]
    [ ! -e "$STUB_LOG/curl.urls" ]
}

@test "a native hook warning is reported for the client" {
    make_clients
    export STUB_HOOK_WARN=cursor
    setup_run --only cursor
    [ "$status" -eq 1 ]
    [[ "$output" == *"native hook not installed: adapter missing"* ]]
}

@test "restart hints appear only for running editors whose config changed" {
    make_clients
    export STUB_RUNNING="Cursor.app"
    setup_run --only cursor,vscode
    [ "$status" -eq 0 ]
    [[ "$output" == *"restart Cursor"* ]]
    [[ "$output" != *"restart VS Code"* ]]
}

@test "JetBrains projects are registered through install jetbrains --project" {
    make_clients
    mkdir -p "$HOME/repo"
    echo '{"mcpServers":{"other":{"command":"x"}}}' > "$HOME/repo/.jb-mcp.json"
    export ARMIS_JETBRAINS_PROJECTS="$HOME/repo"
    setup_run --only jetbrains
    [ "$status" -eq 0 ]
    grep -q "install jetbrains --project $HOME/repo" "$STUB_LOG/armis-cli.argv"
    grep -q '"other"' "$HOME/repo/.jb-mcp.json"
    grep -q armis-appsec "$HOME/repo/.jb-mcp.json"
}

@test "JetBrains without projects tells the admin what to do" {
    make_clients
    mkdir -p "$HOME/Library/Application Support/JetBrains/IntelliJIdea2025.1"
    setup_run --only jetbrains
    [ "$status" -eq 1 ]
    [[ "$output" == *"install jetbrains --project"* ]]
}

@test "the commit gate is installed in the listed repositories" {
    make_clients
    mkdir -p "$HOME/repo"
    git -C "$HOME/repo" init -q
    export ARMIS_HOOK_ENABLE=1 ARMIS_HOOK_REPOS="$HOME/repo"
    setup_run --only hook
    [ "$status" -eq 0 ]
    [ -x "$HOME/repo/.git/hooks/pre-commit" ]
}

@test "the commit gate without repositories warns that it is per repository" {
    make_clients
    export ARMIS_HOOK_ENABLE=1
    setup_run --only hook
    [ "$status" -eq 1 ]
    [[ "$output" == *"per repository"* ]]
}

@test "full uninstall runs armis-cli uninstall --force" {
    make_clients
    setup_run --uninstall
    [ "$status" -eq 0 ]
    grep -q '^uninstall --force --format json$' "$STUB_LOG/armis-cli.argv"
}

@test "targeted uninstall passes only the chosen targets" {
    make_clients
    setup_run --uninstall --only cursor,vscode
    [ "$status" -eq 0 ]
    grep -q '^uninstall cursor vscode --format json$' "$STUB_LOG/armis-cli.argv"
}

@test "uninstall of only the commit gate does not run a bare armis-cli uninstall" {
    make_clients
    setup_run --uninstall --only hook
    [ "$status" -eq 0 ]
    ! grep -q '^uninstall' "$STUB_LOG/armis-cli.argv"
}

@test "a partial uninstall keeps the managed profile block" {
    make_clients
    export ARMIS_TENANT_ID=acme
    setup_run --only cursor,vscode
    grep -q 'armis-cli (managed)' "$HOME/.zshenv"
    setup_run --uninstall --only cursor
    [ "$status" -eq 0 ]
    grep -q 'armis-cli (managed)' "$HOME/.zshenv"
    setup_run --uninstall --skip hook
    [ "$status" -eq 0 ]
    ! grep -q 'armis-cli (managed)' "$HOME/.zshenv"
}

@test "uninstall works without network access" {
    make_clients
    export STUB_CURL_FAIL=1
    setup_run --uninstall
    [ "$status" -eq 0 ]
    grep -q '^uninstall --force --format json$' "$STUB_LOG/armis-cli.argv"
}

@test "uninstall removes the managed profile block and keeps other content" {
    make_clients
    printf 'export FOO=bar\n' > "$HOME/.zshenv"
    export ARMIS_TENANT_ID=acme
    setup_run --only cursor
    grep -q 'armis-cli (managed)' "$HOME/.zshenv"
    setup_run --uninstall
    [ "$status" -eq 0 ]
    ! grep -q 'armis-cli (managed)' "$HOME/.zshenv"
    grep -q 'export FOO=bar' "$HOME/.zshenv"
}

@test "as root, uninstall removes the .env.bak copies as the developer" {
    make_clients
    mkdir -p "$HOME/.armis/plugins/armis-appsec-mcp"
    : > "$HOME/.armis/plugins/armis-appsec-mcp/.env.bak"
    export STUB_ROOT=1
    setup_run --uninstall
    [ "$status" -eq 0 ]
    [ ! -e "$HOME/.armis/plugins/armis-appsec-mcp/.env.bak" ]
    grep -q "^-n -H -u $(id -un) .* /bin/rm -f .*/armis-appsec-mcp/\.env\.bak" "$STUB_LOG/sudo.argv"
}

@test "uninstall dry run changes nothing" {
    make_clients
    setup_run --only cursor
    before=$(tree_hash "$HOME")
    setup_run --uninstall --dry-run
    [ "$status" -eq 0 ]
    [ "$before" = "$(tree_hash "$HOME")" ]
}

@test "the script runs under bash 3.2 without bash 4 features" {
    [ "$(/bin/bash -c 'echo ${BASH_VERSINFO[0]}')" -le 3 ] || skip "/bin/bash is not 3.x on this machine"
    make_clients
    setup_run
    [ "$status" -eq 0 ]
}

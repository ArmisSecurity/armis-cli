# Enterprise deployment on macOS

`scripts/enterprise-setup.sh` installs armis-cli and the Armis AppSec MCP server on macOS developer machines, registers the server in the editors and code agents it finds, checks the result, and reports per machine, user and component. You can run it by hand or push it from an MDM (Jamf, Kandji, Intune for macOS).

It does these things in order, and each stage checks its own result:

1. **preflight**: macOS version, tools, disk space, network, proxy and certificate settings.
2. **cli**: installs a pinned armis-cli, verified with the release checksum (and cosign when it is installed).
3. **auth**: client credentials or browser sign-in (SSO).
4. **mcp**: registers the MCP server in each detected client.
5. **jetbrains**: JetBrains AI Assistant projects you list.
6. **hook**: the commit gate in repositories you list (off by default).
7. **verify**: `armis-cli mcp doctor`. With `ARMIS_SAMPLE_SCAN=1` it runs with `--deep`, which scans a sample through the MCP server. Users without Python 3.11+ get a CLI sample scan instead. The scan is skipped while a user's sign-in is pending.
8. **report**: a table on stdout, plus a JSON file.

A component that fails does not stop the others. Only a preflight failure or a failed armis-cli install stops the run.

## Supported clients

| Client name | What gets configured | Detected by |
|---|---|---|
| `cursor` | `~/.cursor/mcp.json`, `~/.cursor/hooks.json` | `~/.cursor` exists |
| `vscode` | `~/Library/Application Support/Code/User/mcp.json` (VS Code with GitHub Copilot Chat) | the `Code/User` directory exists |
| `copilot` | `~/.copilot/mcp-config.json`, `~/.copilot/settings.json` (GitHub Copilot CLI) | `~/.copilot` exists |
| `codex` | `~/.codex/config.toml`, `~/.codex/hooks.json` | `~/.codex` exists |
| `claude` | the Claude Code plugin (`~/.claude/plugins/...`, `~/.claude/settings.json`) | `~/.claude` exists |
| `antigravity` | `~/.gemini/config/mcp_config.json` | `~/.gemini/config` exists |
| `junie` | `~/.junie/mcp/mcp.json` (JetBrains Junie) | `~/.junie/mcp` exists |
| `jetbrains` | `<project>/.jb-mcp.json` for each project you list (JetBrains AI Assistant) | see [JetBrains](#jetbrains) |

A client that is not installed is reported as `skip (not installed)` and is not an error.

## Prerequisites

- macOS 12 or later, on Apple silicon or Intel. The script runs on the stock `/bin/bash` (3.2). You can start it from zsh.
- `curl`, `git` and `osascript`, which ship with macOS.
- Python 3.11 or later on each developer's `PATH` (the MCP server runs on it). If it is missing, the script reports it per user and exits 1; armis-cli still installs. Install it with `brew install python@3.12` or the python.org installer, then re-run.
- Network access to the endpoints below, directly or through your proxy:
  - `moose.armis.com` (`eu.moose.armis.com` for region `eu1`)
  - `github.com` and `raw.githubusercontent.com`. Set `ARMIS_INSTALLER_URL` to an internal mirror of `scripts/install.sh` if you cannot reach `raw.githubusercontent.com`.
- A proxy or TLS inspection is supported through `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (upper or lower case) and `SSL_CERT_FILE` (a PEM file with your root CA). The script passes them, and `ARMIS_API_URL` when set, to `curl` and to every armis-cli command.
- armis-cli 1.27.0 or later. The script reads the `install --format json` report and uses `--rotate-credentials`, and it exits 3 when `ARMIS_CLI_VERSION` is older.

## Quick start

```bash
# Interactive, as the developer
ARMIS_CLI_VERSION=1.27.0 ARMIS_CLIENT_ID=... ARMIS_CLIENT_SECRET=... ./scripts/enterprise-setup.sh

# See what would change first
ARMIS_CLI_VERSION=1.27.0 ./scripts/enterprise-setup.sh --dry-run

# From an MDM, as root, for the logged-in user
sudo ARMIS_CLI_VERSION=1.27.0 ARMIS_CREDENTIALS_FILE=/var/db/armis/credentials \
    ./scripts/enterprise-setup.sh --non-interactive --report /Library/Logs/Armis/last
```

The script reads its settings from the environment. Run `./scripts/enterprise-setup.sh --help` to see the commented configuration block.

## Flags

| Flag | Effect |
|---|---|
| `--dry-run` | Prints what would change and writes nothing: no files, no backups, no logs, no reports. Read-only probes still run. |
| `--uninstall` | Removes what the script installed. See [Uninstall](#uninstall-and-rollback). |
| `--non-interactive` | Never prompts. Implied when stdin is not a terminal. Requires `ARMIS_CLI_VERSION` unless `ARMIS_ALLOW_LATEST=1`. |
| `--only a,b` | Only these components: `cursor`, `vscode`, `copilot`, `codex`, `claude`, `antigravity`, `junie`, `jetbrains`, `hook`. |
| `--skip a,b` | Everything except these. |
| `--report PATH` | Writes the JSON report to `PATH.json` (a `.json` extension is ignored). Default: next to the log. |
| `--bundle` | Also writes an `armis-cli mcp doctor` support bundle per user, next to the log. It contains no credentials. |
| `--verbose` | Logs every command the script runs. |
| `--help` | Usage and the configuration block. |

An unknown flag or component exits 3.

## Configuration

Every value can come from the environment, so an MDM can set them as script parameters or variables.

| Variable | Default | Meaning |
|---|---|---|
| `ARMIS_CLI_VERSION` | none | armis-cli release to install, `1.27.0` or later. The installer is fetched from the same tag. |
| `ARMIS_ALLOW_LATEST` | `0` | `1` allows an unpinned install with `--non-interactive`. The script resolves the latest release tag and downloads the installer from that tag, never from `main`. |
| `ARMIS_MCP_VERSION` | latest | MCP server release to pin. A pin is saved and kept by `armis-cli mcp update` and `armis-cli mcp doctor --fix`. |
| `ARMIS_TENANT_ID` | none | Tenant. Required for `sso`. |
| `ARMIS_REGION` | default region | For example `eu1`. |
| `ARMIS_AUTH_MODE` | `client-credentials` | `client-credentials` or `sso`. |
| `ARMIS_CLIENT_ID`, `ARMIS_CLIENT_SECRET` | none | Client credentials. |
| `ARMIS_CREDENTIALS_FILE` | none | A file with `ARMIS_CLIENT_ID=` and `ARMIS_CLIENT_SECRET=` lines. Used when the variables are not set. |
| `ARMIS_SSO_LOGIN` | `auto` | `now` opens the sign-in page, `skip` leaves it, `auto` signs in when a developer runs the script in a terminal. |
| `ARMIS_CLIENTS` | all seven clients | Which clients to configure. |
| `ARMIS_JETBRAINS_PROJECTS` | none | Comma-separated project directories for JetBrains AI Assistant. |
| `ARMIS_HOOK_ENABLE`, `ARMIS_HOOK_REPOS` | `0`, none | Install the commit gate in these repositories (comma-separated). |
| `ARMIS_HOOK_FAIL_OPEN` | `0` | `1` makes the gate warn instead of block. |
| `ARMIS_WITH_KNOWLEDGE` | `0` | Also install Armis Knowledge. It cannot be pinned. |
| `ARMIS_SAMPLE_SCAN` | `1` | Scan a two-line sample once per user to prove the whole path. This uses tenant scan quota. `0` skips it, including `mcp doctor --deep`. |
| `ARMIS_TARGET_USERS` | console user | Comma-separated accounts to configure. |
| `ARMIS_INSTALL_DIR` | `/usr/local/bin` as root, `~/.local/bin` otherwise | Where armis-cli goes. |
| `ARMIS_INSTALLER_URL` | GitHub raw | Internal mirror of `scripts/install.sh`. |
| `ARMIS_EXTRA_PATH` | none | Extra directories to search for Python. |
| `ARMIS_LOG_DIR` | `/Library/Logs/Armis` as root, `~/Library/Logs/Armis` otherwise | Log and report location. |
| `ARMIS_KEEP_CREDENTIALS`, `ARMIS_REMOVE_CLI` | `0`, `0` | Uninstall options. |

## Credentials

Do not pass credentials as MDM policy parameters, because Jamf and Kandji show parameters in their logs and consoles. Use one of:

- Secret variables that your MDM injects into the script's environment at run time.
- A credentials file owned by the user running the script, with mode `0600` or `0400`, for example `/var/db/armis/credentials` owned by root. The script refuses a file with wider permissions.

The script never puts credentials in command-line arguments, so they do not appear in `ps`. They reach armis-cli only through the process environment. They are not written to the log or the report; a masking filter also hides the secret value if a command echoes it.

Each editor starts the MCP server without your shell environment, so credentials must also be in the `.env` files that armis-cli writes. armis-cli does not overwrite an existing `.env` on its own, so the script runs `armis-cli install --rotate-credentials`. That rewrites every `.env` armis-cli manages (the shared plugin, the Claude Code plugin cache and Knowledge) at mode `0600`, keeps other keys such as `HTTPS_PROXY`, and deletes the `.env.bak` copies that hold the old secret. Rotating a credential is therefore a re-run with the new value.

With `ARMIS_AUTH_MODE=sso`, developers sign in through the identity provider you registered (see [SSO-SETUP.md](SSO-SETUP.md)). Under `--non-interactive` the script does not open a browser unless `ARMIS_SSO_LOGIN=now`. A user who has not signed in is reported as `sign-in pending: run 'armis-cli auth login'`. When run as root, a browser sign-in only works for the user logged in at the console. In `sso` mode and during `--uninstall`, `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` in the environment are removed before any armis-cli command runs, so they cannot take precedence over the SSO session.

## What changes on disk

For each user (the home directory is that user's):

| Path | Change |
|---|---|
| `ARMIS_INSTALL_DIR/armis-cli` | The binary. |
| `~/.armis/plugins/armis-appsec-mcp/` | The MCP server, its Python environment and `.env` (mode 0600). |
| The client files in the [table above](#supported-clients) | One `armis-appsec` entry added. Other servers are kept. |
| `~/.zshenv`, `~/.profile` or `~/.bash_profile`, `~/.bashrc` | A block between `# >>> armis-cli (managed) >>>` and `# <<< armis-cli (managed) <<<` with `ARMIS_TENANT_ID`, `ARMIS_REGION`, `ARMIS_DEFAULT_AUTH_METHOD` (sso) and `PATH`. Written only when it has content. Everything outside the markers is untouched. A file with the begin marker but no end marker is left unchanged and reported, so a hand-edited block cannot truncate it. |
| `<project>/.jb-mcp.json`, `<repo>/.git/hooks/pre-commit` | Only for the projects and repositories you list. |
| `ARMIS_LOG_DIR` | `enterprise-setup-<timestamp>.log` and `.json`. |

The script also reads, but never edits, VS Code's `settings.json` to check that Copilot Agent mode and MCP are not switched off.

### Backups and safety

Before changing a file the script copies it to `<file>.armis-bak.<timestamp>` (mode 0600, owned by the user). Then:

- A config that does not parse as JSON is **skipped** and left byte-for-byte as it was. armis-cli would otherwise replace it and delete the user's other servers. Comments and trailing commas (as VS Code allows) are accepted.
- After the install the script checks that the file parses, that `armis-appsec` is present and that every earlier server is still there. If not, it restores the backup for that client and reports it as failed. Other clients are not affected.
- A backup whose original did not change is deleted, so re-running the script does not pile up backups.
- VS Code's `mcp.json` loses its comments the first time armis-cli rewrites it. The backup keeps them.

## Idempotent re-runs

A second run with the same settings makes no new backups, does not download armis-cli again (the installed version matches the pin) and, when `ARMIS_MCP_VERSION` is set, does not call GitHub or rebuild the Python environment.

## Results and exit codes

The matrix has one row per endpoint, user and component, with these columns: Endpoint, User, Component, Detected, Installed, Auth, Verified, Action needed. Statuses are `ok`, `warn` (needs attention), `fail` and `skip`; `-` means not applicable. The last line is `ARMIS_STATUS=<ok|partial|failed> components=<n> failing=<n>`.

| Exit code | Meaning |
|---|---|
| 0 | Everything succeeded. |
| 1 | Partial: something needs attention (a client failed, Python is missing, sign-in is pending, a JetBrains project is not set up). |
| 2 | A verification failed (`mcp doctor`, the sample scan), or armis-cli could not be installed. |
| 3 | Bad arguments, an unreadable credentials file, a checksum or signature mismatch, or a preflight failure. |

The JSON report has `endpoint`, `serial`, `timestamp`, `script_version`, `cli_version`, `mcp_version`, `exit_code`, `status` and a `components` list with `user`, `component`, `detected`, `installed`, `auth`, `verified` and `action`.

### Jamf Extension Attribute

```bash
#!/bin/bash
last=$(ls -t /Library/Logs/Armis/enterprise-setup-*.json 2>/dev/null | head -n 1)
[ -n "$last" ] || { echo "<result>not run</result>"; exit 0; }
status=$(sed -n 's/.*"status": "\(.*\)",/\1/p' "$last" | head -n 1)
echo "<result>$status</result>"
```

## JetBrains

Junie is automatic (`junie` above). JetBrains AI Assistant reads a `.jb-mcp.json` in each project, so list the projects:

```bash
ARMIS_JETBRAINS_PROJECTS="$HOME/code/api,$HOME/code/web" ./scripts/enterprise-setup.sh --only jetbrains
```

The script runs `armis-cli install jetbrains --project <path>` for each project that belongs to the user. The developer then enables the server in the IDE's AI Assistant MCP settings. Without a project list, the script reports `run 'armis-cli install jetbrains --project <repo>' in each repo, or use Junie`. On a run without `--only` this is a hint and does not change the exit code; with `--only jetbrains` it is a warning (exit 1).

## Commit gate

`armis-cli hook init` installs a pre-commit hook in one repository, so the gate is per repository. Set `ARMIS_HOOK_ENABLE=1` and `ARMIS_HOOK_REPOS` to the repositories to cover. The script backs up an existing `pre-commit`, installs the hook where Git resolves the hooks directory (`core.hooksPath` is honoured) and checks that it is executable.

## Uninstall and rollback

```bash
./scripts/enterprise-setup.sh --uninstall --non-interactive
```

- **Without `--only`, `--skip` or an `ARMIS_CLIENTS` subset**: runs `armis-cli uninstall --force`, which removes the MCP server from every client and deletes the plugin directory and its `.env`. Add `ARMIS_KEEP_CREDENTIALS=1` to keep credentials.
- **With `--only`, `--skip`, or `ARMIS_CLIENTS` naming fewer than all clients**: runs `armis-cli uninstall <clients>`. This removes only those registrations and leaves the shared plugin directory and `.env` in place. When the selection names no client (for example `--only hook`), armis-cli is not called.
- The managed profile blocks are removed by a full uninstall, or when the selection covers every client. A partial uninstall keeps them, because the remaining clients need `ARMIS_TENANT_ID`, `ARMIS_REGION` and the sign-in method.
- Uninstall skips the network and disk-space checks, so it also works offline.
- Also removed: hooks in `ARMIS_HOOK_REPOS` (`hook init --remove`, run before the plugin directory is deleted; `ARMIS_HOOK_ENABLE` is not needed) and the `armis-appsec` entry in `.jb-mcp.json` of the listed JetBrains projects. With `ARMIS_REMOVE_CLI=1` as root, `/usr/local/bin/armis-cli` too.
- The result is checked: a client that armis-cli reports as failed, that is missing from its report, or whose JSON config still has the `armis-appsec` entry is reported as failed.

The script never restores `*.armis-bak.*` files by itself, because that could undo changes the developer made later. To roll a file back by hand, copy the backup over the original, for example `cp -p ~/.cursor/mcp.json.armis-bak.20260101-120000 ~/.cursor/mcp.json`, then restart the editor.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `cannot reach https://...` in preflight | Check the network, `HTTPS_PROXY` and `SSL_CERT_FILE`. Run `armis-cli mcp doctor --network` as the user for a step-by-step report (proxy, DNS, TLS, certificate issuer). |
| `Python 3.11+ is missing` | `brew install python@3.12` or the python.org installer, then re-run. If Python is in an unusual place, add it to `ARMIS_EXTRA_PATH`. |
| `client credentials were rejected` | Check `ARMIS_CLIENT_ID`, `ARMIS_CLIENT_SECRET` and `ARMIS_REGION`. Run `armis-cli auth whoami` as the user. |
| `sign-in pending` | The user runs `armis-cli auth login`, or you re-run with `ARMIS_SSO_LOGIN=now` while they are logged in. |
| `config at ... is not valid JSON` | The file was left untouched. Fix or remove it and re-run. |
| The editor does not show the Armis tools | Restart the editor (the matrix says `restart <editor>` when it is running). For VS Code, open "MCP: List Servers". |
| VS Code: `chat.mcp.enabled`, `chat.mcp.access` or `chat.agent.enabled` in an `mcp doctor` failure | A VS Code setting or a GitHub organization policy turns MCP or Agent mode off. The script only reports this and never edits settings. |
| `mcp doctor` failures | Run `armis-cli mcp doctor` as the user. Use `--bundle` here, or `armis-cli mcp doctor --bundle`, to produce a support bundle. In an editor, call the `debug_config` tool. |
| The sample scan fails | Check `armis-cli auth whoami` and the network. Set `ARMIS_SAMPLE_SCAN=0` to skip it. |
| `only the checksum was verified` | Install [cosign](https://docs.sigstore.dev/cosign/installation/) to also verify the release signature. This is advice and does not change the exit code. |

Exit code 1 for a missing Python is deliberate: armis-cli itself installed correctly, so the run is partial rather than failed.

The log is at `ARMIS_LOG_DIR/enterprise-setup-<timestamp>.log`. Add `--verbose` to see every command.

## Example output

A re-run on a machine where the CLI is already installed, with one malformed Junie config. The endpoint and paths are shortened.

```
[armis-setup] armis enterprise-setup 1.0.0
[armis-setup] Preflight
[armis-setup] macOS 26.7.1 on arm64
[armis-setup] armis-cli
[armis-setup] armis-cli 9.9.9 already installed at ~/bin/armis-cli
[armis-setup] [alice] auth (client-credentials)
[armis-setup] [alice] MCP server
[armis-setup] [alice] JetBrains
[armis-setup] [alice] verify
Endpoint  User       Component    Detected  Installed             Auth  Verified  Action needed
MBP-0042  (machine)  armis-cli    yes       ok                    -     ok        -
MBP-0042  alice      cursor       yes       ok                    ok    ok        -
MBP-0042  alice      vscode       yes       ok                    ok    ok        -
MBP-0042  alice      copilot      no        skip (not installed)  -     -         -
MBP-0042  alice      codex        yes       ok                    ok    ok        -
MBP-0042  alice      claude       yes       ok                    ok    ok        restart Claude Code
MBP-0042  alice      antigravity  no        skip (not installed)  -     -         -
MBP-0042  alice      junie        yes       fail                  ok    -         config at ~/.junie/mcp/mcp.json is not valid JSON; fix or remove it, then re-run
MBP-0042  alice      mcp-server   -         ok                    ok    ok        -
MBP-0042  alice      jetbrains    no        skip (not installed)  -     -         -
MBP-0042  alice      sample-scan  yes       ok                    ok    ok        -
ARMIS_STATUS=partial components=11 failing=1
```

The exit code of that run is 1. Fixing the Junie file and re-running turns the row green and the exit code to 0.

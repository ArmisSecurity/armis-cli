# AppSec Security Scanner -- MCP Server

AI-powered code security scanner exposed as an MCP server. Any MCP-compatible coding agent (Claude Code, Cursor, Windsurf, etc.) can connect and scan code for vulnerabilities in real-time.

Uses LLM-based SAST via direct Cerebras calls with qwen-3-235b.

## Quick Start

```bash
# Install dependencies (Python 3.11+)
pip install -r dev_tools/appsec-mcp/requirements.txt

# Set your Cerebras API key
export CEREBRAS_API_KEY=<your-key>
```

Then in Claude Code, enable the plugin:

1. Run `/plugins` in Claude Code
2. Enable `armis-appsec` from `dev_tools/appsec-mcp/`
3. Done — MCP tools + auto-scan hook are both active

The plugin auto-registers the MCP server (3 scanning tools) and the Stop hook (auto-scans code Claude writes). No manual config file editing needed.

## Tools

### `scan_code`

Scan a code snippet inline. Pass the code directly.

```text
"Scan this code for vulnerabilities: [paste code]"
```

### `scan_file`

Scan a file on disk by path.

```text
"Scan path/to/your/file.py"
```

### `scan_diff`

Scan git changes only. Supports unstaged, staged, or diff against a branch/ref.

- `scan_diff()` -- scan unstaged changes
- `scan_diff(staged=True)` -- scan staged changes
- `scan_diff(ref="main")` -- scan all changes vs main (PR review)

```text
"Scan my changes before I commit"
"Scan the diff against main"
```

## Scan Modes

| Mode | What it includes | Best for |
|------|-----------------|----------|
| `fast` | Core CWE detection + exploit-based FP reduction | Demos, quick checks |
| `standard` | Fast + taint tracking (source-to-sink data flow) | Thorough review |
| `full` | Standard + CWE-specific hints (production prompt) | Production-grade scans |

**Set the default** via env var:

```bash
export APPSEC_SCAN_MODE=fast  # or standard, full
```

**Override per-call** via the `mode` parameter on any tool.

## Auto-Scan Hook (Stop Hook)

The Stop hook makes Claude automatically scan every file it writes before responding. No user action needed — it's auto-registered when you enable the plugin.

**How it works:**

1. Claude writes/edits code as usual
2. When Claude is about to finish responding, the Stop hook fires
3. The hook injects a system message telling Claude to scan modified files
4. Claude calls `scan_file` on each file it touched
5. If critical/high findings are found, Claude fixes them and rescans

## Demo Scripts

### Demo 1: Manual Scan (MCP)

1. Open Claude Code in this repo, enable the `armis-appsec` plugin
2. Ask Claude to write a Flask auth endpoint
3. Then say: "scan that code for vulnerabilities"
4. Claude calls `scan_code` -> gets findings -> offers to fix them
5. After fixing, scan again -> clean

### Demo 2: Auto-Scan (Stop Hook) -- the money shot

1. Enable the `armis-appsec` plugin (MCP + hook both auto-register)
2. Ask Claude to write a Flask auth endpoint with user login
3. Claude writes the code -> finishes -> **Stop hook fires automatically**
4. Claude scans all files it just wrote -> finds SQL injection
5. Claude fixes the vulnerability -> rescans -> clean
6. **The developer never asked for a scan. Claude reviewed its own work.**

### Demo 3: PR Review (scan_diff)

1. Make some changes to a file with a known vulnerability
2. Say: "scan my changes before I commit"
3. Claude calls `scan_diff` -> findings scoped to the diff only
4. Or: "scan the diff against main" -> `scan_diff(ref="main")` for full PR review

### Demo 4: Known Vulnerable File

1. Say: "scan path/to/suspicious_file.py"
2. Claude calls `scan_file` -> finds vulnerabilities and suggests fixes

### The Pitch
>
> "The agent reviews its own work automatically. You can scan any snippet, any file, or just your changes. Same engine, zero config."

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `CEREBRAS_API_KEY` | (required) | Cerebras API key |
| `APPSEC_MODEL` | `qwen-3-235b-a22b-instruct-2507` | Model to use |
| `APPSEC_SCAN_MODE` | `fast` | Default scan mode |
| `FASTMCP_LOG_LEVEL` | `ERROR` | MCP framework log level |

## Architecture

```text
              +---------------------+
              |   Scanner Core       |
              |  scanner_core.py     |
              +--------+------------+
                 +-----+------+
                 |            |
           +-----v-----+ +---v---------+
           | MCP Server | | Stop Hook   |
           | server.py  | | hooks/      |
           +------------+ +-------------+
```

## For Armis Developers

### What's temporary

The following are marked with `# TEMPORARY:` comments in the code. They work for local development and demos but will be replaced:

- **Cerebras direct call** (`call_cerebras()` in `scanner_core.py`): In production, this should call the Moose scanning API instead of a raw LLM.
- **Hardcoded model ID**: Will be platform-configurable.
- **Scanner prompt in Python**: In production, the prompt lives in the Moose-AI pipeline and is versioned there.
- **SSL workaround**: The macOS system trust store hack for corporate VPN.

### What's permanent

- **Tool signatures**: `scan_code`, `scan_file`, `scan_diff` with their current parameter shapes
- **Output format**: Compact plain text optimized for LLM consumption
- **Finding schema**: severity, confidence, line, cwe, cwe_name, explanation, has_secret, tainted_function_references
- **Stop hook pattern**: Auto-scan on completion
- **Plugin structure**: `.claude-plugin/marketplace.json` + `hooks/hooks.json` + `.mcp.json`

### Replacing Cerebras with Moose API

When ready to connect to the full platform, only `scanner_core.py` changes:

1. Replace `call_cerebras(code, mode)` with an HTTP call to `POST /api/v1/scan` (or a dedicated AI scan endpoint)
2. Replace `parse_findings()` with parsing the Moose normalized results format
3. Remove `CEREBRAS_API_KEY` / `MODEL_ID` / prompt constants
4. Add `MOOSE_API_URL` and `MOOSE_API_KEY` env vars

The MCP server (`server.py`) and hooks stay unchanged.

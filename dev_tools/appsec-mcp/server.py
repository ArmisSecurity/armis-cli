"""
Armis AppSec Scanner -- MCP Server

A lightweight MCP server that exposes AI-powered vulnerability discovery
as tools any coding agent can call. Calls the Moose scanning API which
handles model selection and prompt versioning server-side.

Usage:
    APPSEC_API_TOKEN=<token> python server.py
    # or via MCP stdio transport:
    APPSEC_API_TOKEN=<token> mcp run server.py
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time

# Ensure scanner_core is importable regardless of cwd
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _plugin_dir)

# Load .env from plugin directory if it exists (for APPSEC_API_TOKEN etc.)
_env_file = os.path.join(_plugin_dir, ".env")
if os.path.isfile(_env_file):
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip())

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from scanner_core import call_appsec_api, format_findings, parse_findings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("appsec-mcp")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "Armis AppSec Scanner",
    instructions=(
        "Use this server to scan code for security vulnerabilities using "
        "AI-powered SAST -- the same engine that powers the production "
        "scanning pipeline.\n\n"
        "WHEN TO USE:\n"
        "- When the user asks to scan, review, or check code for vulnerabilities "
        "or security issues\n"
        "- When the user pastes a code snippet and asks about its security\n"
        "- When the user asks to review a file or diff for security concerns\n\n"
        "ALWAYS use these tools instead of analyzing code for vulnerabilities "
        "yourself. The scanner uses taint tracking and CWE-aware analysis that "
        "goes beyond what manual review can catch."
    ),
)

# ---------------------------------------------------------------------------
# Security: path validation for scan_file
# ---------------------------------------------------------------------------
_BLOCKED_PREFIXES = ("/etc/", "/proc/", "/sys/", "/private/etc/")
_BLOCKED_DOTDIRS = {".ssh", ".gnupg", ".aws", ".config/gcloud"}
_MAX_CODE_CHARS = 90_000

# Git ref validation: alphanumeric + common ref chars (branch, tag, SHA, HEAD~3)
_VALID_GIT_REF = re.compile(r"^[a-zA-Z0-9_./\-~^@{}]+$")

def _validate_file_path(file_path: str) -> str:
    """Resolve and validate a file path. Returns the resolved path or raises ToolError."""
    resolved = os.path.realpath(file_path)

    for prefix in _BLOCKED_PREFIXES:
        normalized = prefix.rstrip("/")
        if resolved == normalized or resolved.startswith(normalized + "/"):
            raise ToolError(f"Scanning system path '{resolved}' is not allowed.")

    home = os.path.expanduser("~")
    for dotdir in _BLOCKED_DOTDIRS:
        if resolved.startswith(os.path.join(home, dotdir)):
            raise ToolError(f"Scanning '{resolved}' is blocked (sensitive directory).")

    return resolved


@mcp.tool()
async def scan_code(
    code: str,
    filename: str = "snippet",
    ctx: Context | None = None,
) -> str:
    """Scan a code snippet for security vulnerabilities.

    Use this tool when you want to check code for security issues before
    committing, during code review, or when writing security-sensitive code.

    Args:
        code: The source code to scan.
        filename: Optional filename for context (e.g. "auth.py").

    Returns:
        A formatted report of any vulnerabilities found, including CWE IDs,
        severity, affected lines, and explanations.
    """
    if len(code) > _MAX_CODE_CHARS:
        code = code[:_MAX_CODE_CHARS]
        logger.warning(f"Truncated code input to {_MAX_CODE_CHARS} chars")

    if ctx:
        await ctx.info(f"Scanning {filename} ({len(code)} chars)")
    logger.info(f"Scanning code snippet: {filename} ({len(code)} chars)")

    t0 = time.monotonic()
    try:
        raw = await asyncio.to_thread(call_appsec_api, code)
    except RuntimeError as e:
        raise ToolError(str(e)) from e
    except Exception as e:
        raise ToolError(f"Scan failed: {e}") from e

    findings = parse_findings(raw)
    report = format_findings(findings, filename)
    _cache_scan(report, findings, filename)

    if ctx:
        elapsed = time.monotonic() - t0
        await ctx.info(f"Scan complete: {len(findings)} finding(s) in {elapsed:.1f}s")

    return report


@mcp.tool()
async def scan_file(
    file_path: str,
    ctx: Context | None = None,
) -> str:
    """Scan a file on disk for security vulnerabilities.

    Use this tool to scan an existing source file. The file is read and
    analyzed for vulnerabilities using AI-powered SAST.

    Args:
        file_path: Absolute path to the file to scan.

    Returns:
        A formatted report of any vulnerabilities found.
    """
    resolved = _validate_file_path(file_path)

    if not os.path.isfile(resolved):
        raise ToolError(f"File not found: {file_path}")

    _MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB
    try:
        file_size = os.path.getsize(resolved)
    except OSError as e:
        raise ToolError(f"Cannot stat {file_path}: {e}")
    if file_size > _MAX_FILE_BYTES:
        raise ToolError(f"File too large ({file_size // 1024 // 1024}MB). Max: 10MB.")

    try:
        with open(resolved, "rb") as f:
            if b"\x00" in f.read(8192):
                raise ToolError(f"File '{file_path}' appears to be binary -- skipping scan.")
        with open(resolved, encoding="utf-8", errors="replace") as f:
            code = f.read()
    except PermissionError:
        raise ToolError(f"Permission denied reading {file_path}")
    except ToolError:
        raise
    except OSError as e:
        raise ToolError(f"Cannot read {file_path}: {e}")

    if not code.strip():
        raise ToolError(f"File '{file_path}' is empty -- nothing to scan.")

    # Limit to ~90k chars (same as production CHUNK_CHAR_LIMIT)
    if len(code) > _MAX_CODE_CHARS:
        code = code[:_MAX_CODE_CHARS]
        logger.warning(f"Truncated {file_path} to {_MAX_CODE_CHARS} chars")

    filename = os.path.basename(file_path)
    if ctx:
        await ctx.info(f"Scanning {filename} ({len(code)} chars)")
    logger.info(f"Scanning file: {file_path} ({len(code)} chars)")

    t0 = time.monotonic()
    try:
        raw = await asyncio.to_thread(call_appsec_api, code)
    except RuntimeError as e:
        raise ToolError(str(e)) from e
    except Exception as e:
        raise ToolError(f"Scan failed: {e}") from e

    findings = parse_findings(raw)
    report = format_findings(findings, filename)
    _cache_scan(report, findings, filename)

    if ctx:
        elapsed = time.monotonic() - t0
        await ctx.info(f"Scan complete: {len(findings)} finding(s) in {elapsed:.1f}s")

    return report


@mcp.tool()
async def scan_diff(
    repo_path: str = "",
    ref: str = "",
    staged: bool = False,
    ctx: Context | None = None,
) -> str:
    """Scan git changes for security vulnerabilities.

    Use this tool to scan only the code that changed -- perfect for
    pre-commit checks, PR reviews, or scanning your work-in-progress.

    Args:
        repo_path: Path to the git repository. Defaults to current directory.
        ref: Git ref to diff against (e.g. "main", "HEAD~3", a commit SHA).
             If empty, diffs unstaged changes (or staged if staged=True).
        staged: If True, scan staged changes only (git diff --cached).
                Ignored if ref is provided.

    Returns:
        A formatted report of vulnerabilities found in the changed code.
    """
    if ref and not _VALID_GIT_REF.match(ref):
        raise ToolError(
            f"Invalid git ref: '{ref}'. "
            "Use branch names, tags, SHAs, or relative refs like HEAD~3."
        )

    if repo_path:
        cwd = _validate_file_path(repo_path)
        if not os.path.isdir(cwd):
            raise ToolError(f"Not a directory: {repo_path}")
    else:
        cwd = os.getcwd()

    # Build the git diff command
    cmd = ["git", "diff"]
    if ref:
        cmd.append(ref)
    elif staged:
        cmd.append("--cached")
    # Show enough context for the scanner to understand the code
    cmd.extend(["-U10"])

    logger.info(f"Running: {' '.join(cmd)} in {cwd}")

    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise ToolError("git diff timed out after 30 seconds. Try a narrower ref or smaller repo.")

    if result.returncode != 0:
        raise ToolError(f"git diff failed: {result.stderr.strip()}")

    diff_text = result.stdout.strip()
    if not diff_text:
        return "No changes to scan."

    # Truncate large diffs
    if len(diff_text) > _MAX_CODE_CHARS:
        diff_text = diff_text[:_MAX_CODE_CHARS]
        logger.warning(f"Truncated diff to {_MAX_CODE_CHARS} chars")

    label = f"diff against {ref}" if ref else ("staged changes" if staged else "unstaged changes")
    if ctx:
        await ctx.info(f"Scanning {label} ({len(diff_text)} chars)")
    logger.info(f"Scanning {label} ({len(diff_text)} chars)")

    t0 = time.monotonic()
    try:
        raw = await asyncio.to_thread(call_appsec_api, diff_text)
    except RuntimeError as e:
        raise ToolError(str(e)) from e
    except Exception as e:
        raise ToolError(f"Scan failed: {e}") from e

    findings = parse_findings(raw)
    report = format_findings(findings, label)
    _cache_scan(report, findings, label)

    if ctx:
        elapsed = time.monotonic() - t0
        await ctx.info(f"Scan complete: {len(findings)} finding(s) in {elapsed:.1f}s")

    return report


# ---------------------------------------------------------------------------
# Resource: last scan results (re-read without re-scanning)
# ---------------------------------------------------------------------------
_last_scan: dict = {"report": "", "findings": [], "filename": "", "timestamp": None}


def _cache_scan(report: str, findings: list[dict], filename: str):
    """Update the last scan cache."""
    _last_scan.update({
        "report": report,
        "findings": findings,
        "filename": filename,
        "timestamp": time.time(),
    })


@mcp.resource("appsec://last-scan")
def last_scan_results() -> str:
    """Last scan results. Re-read without re-scanning."""
    if not _last_scan["timestamp"]:
        return "No scan has been performed yet."
    return json.dumps(_last_scan, indent=2, default=str)


# ---------------------------------------------------------------------------
# Prompt: security review template
# ---------------------------------------------------------------------------
@mcp.prompt()
def security_review(code: str, language: str = "auto") -> str:
    """Structured security review prompt."""
    return (
        f"Perform a thorough security review of this {language} code. "
        f"Use scan_code to identify vulnerabilities, then provide: "
        f"summary, risk assessment, fixes with code, and architectural concerns.\n\n"
        f"```\n{code}\n```"
    )


if __name__ == "__main__":
    transport = os.environ.get("APPSEC_TRANSPORT", "stdio")
    mcp.run(transport=transport)

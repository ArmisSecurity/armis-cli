#!/usr/bin/env python3
"""
AppSec MCP Test Harness

Tests the MCP server plumbing -- tool registration, argument passing, response
formatting, error handling, and the full stdio transport. The LLM is mocked
out so tests are fast, deterministic, and need no API key.

  python test_mcp.py           # run all tests
  python test_mcp.py -v        # verbose
  python test_mcp.py -t scan_code  # filter by name
  python test_mcp.py --list    # list tests
"""

import asyncio
import json
import os
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from unittest.mock import patch


def run(coro):
    """Run an async function synchronously (for calling async tools in tests)."""
    return asyncio.run(coro)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ---------------------------------------------------------------------------
# Canned LLM responses -- returned by the mock instead of calling Cerebras
# ---------------------------------------------------------------------------

MOCK_RESPONSE_ONE_FINDING = textwrap.dedent("""\
    Found a vulnerability.

    ```json
    [
        {
            "severity": "HIGH",
            "confidence": 0.95,
            "line": 10,
            "cwe": 89,
            "cwe_name": "SQL Injection",
            "explanation": "User input directly interpolated into SQL query.",
            "has_secret": false,
            "tainted_function_references": ["get_user"]
        }
    ]
    ```
""")

MOCK_RESPONSE_MULTI_FINDING = textwrap.dedent("""\
    Multiple issues found.

    ```json
    [
        {
            "severity": "CRITICAL",
            "confidence": 0.99,
            "line": 5,
            "cwe": 798,
            "cwe_name": "Hardcoded Credentials",
            "explanation": "API key hardcoded in source.",
            "has_secret": true,
            "tainted_function_references": []
        },
        {
            "severity": "HIGH",
            "confidence": 0.90,
            "line": 12,
            "cwe": 78,
            "cwe_name": "OS Command Injection",
            "explanation": "User input passed to shell command.",
            "has_secret": false,
            "tainted_function_references": ["search"]
        },
        {
            "severity": "MEDIUM",
            "confidence": 0.85,
            "line": 13,
            "cwe": 79,
            "cwe_name": "Cross-site Scripting",
            "explanation": "User input reflected in HTML.",
            "has_secret": false,
            "tainted_function_references": []
        }
    ]
    ```
""")

MOCK_RESPONSE_CLEAN = textwrap.dedent("""\
    No vulnerabilities found in this code.

    ```json
    []
    ```
""")

MOCK_RESPONSE_MALFORMED_JSON = "Some text without valid json block"

MOCK_RESPONSE_CWE_ZERO = textwrap.dedent("""\
    ```json
    [
        {"severity": "LOW", "confidence": 0.3, "line": 1, "cwe": 0,
         "cwe_name": "", "explanation": "not real", "has_secret": false,
         "tainted_function_references": []}
    ]
    ```
""")


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
ERR  = "\033[33mERROR\033[0m"


@dataclass
class TestResult:
    name: str
    passed: bool
    duration: float
    failures: list[str] = field(default_factory=list)
    error: str | None = None


def print_result(r: TestResult):
    if r.error:
        print(f"  {ERR}   {r.name} ({r.duration:.2f}s) -- {r.error}")
    elif r.passed:
        print(f"  {PASS}  {r.name} ({r.duration:.2f}s)")
    else:
        print(f"  {FAIL}  {r.name} ({r.duration:.2f}s)")
        for f in r.failures:
            print(f"          -> {f}")


def make_mock_cerebras(response: str):
    """Return a function that replaces call_cerebras with a canned response."""
    def _mock(code: str, mode: str = "") -> str:
        return response
    return _mock


# ---------------------------------------------------------------------------
# Direct tests -- mock the LLM, test everything else
# ---------------------------------------------------------------------------

def test_tool_registration():
    """Server registers exactly 3 tools with correct names."""
    from server import mcp as server_mcp
    tools = {name for name in server_mcp._tool_manager._tools}
    failures = []
    expected = {"scan_code", "scan_file", "scan_diff"}
    if tools != expected:
        failures.append(f"Expected tools {expected}, got {tools}")
    return TestResult(name="tool_registration", passed=not failures, duration=0, failures=failures)


def test_scan_code_returns_report_and_raw():
    """scan_code returns a compact report with findings."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_ONE_FINDING)):
        result = run(scan_code(code="x = 1", filename="test.py"))
    failures = []
    if "SCAN test.py" not in result:
        failures.append("Missing SCAN header")
    if "CWE-89" not in result:
        failures.append("Missing CWE-89 in report")
    if "1 finding" not in result:
        failures.append("Missing finding count")
    return TestResult(name="scan_code_report_structure", passed=not failures, duration=0, failures=failures)


def test_scan_code_clean():
    """scan_code with no findings shows clean message."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_CLEAN)):
        result = run(scan_code(code="x = 1", filename="clean.py"))
    failures = []
    if "clean" not in result.lower() or "no findings" not in result.lower():
        failures.append(f"Expected 'clean, no findings' message, got: {result[:100]}")
    return TestResult(name="scan_code_clean", passed=not failures, duration=0, failures=failures)


def test_scan_code_multi_findings():
    """Multiple findings are all present with correct metadata."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_MULTI_FINDING)):
        result = run(scan_code(code="x = 1", filename="multi.py"))
    failures = []
    if "3 finding" not in result:
        failures.append("Missing finding count")
    for expected_cwe in [798, 78, 79]:
        if f"CWE-{expected_cwe}" not in result:
            failures.append(f"CWE-{expected_cwe} not in report")
    if "CRITICAL" not in result:
        failures.append("CRITICAL severity not in report text")
    if "[SECRET]" not in result:
        failures.append("Secret detection not flagged in report")
    return TestResult(name="scan_code_multi_findings", passed=not failures, duration=0, failures=failures)


def test_scan_code_malformed_response():
    """Malformed LLM output produces 0 findings, not a crash."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_MALFORMED_JSON)):
        result = run(scan_code(code="x = 1", filename="bad.py"))
    failures = []
    if "clean" not in result.lower() or "no findings" not in result.lower():
        failures.append(f"Should show clean report when parsing fails, got: {result[:100]}")
    return TestResult(name="scan_code_malformed_response", passed=not failures, duration=0, failures=failures)


def test_scan_code_cwe_zero_filtered():
    """Findings with cwe=0 are filtered out."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_CWE_ZERO)):
        result = run(scan_code(code="x = 1", filename="zero.py"))
    failures = []
    if "clean" not in result.lower() or "no findings" not in result.lower():
        failures.append(f"CWE-0 findings should be filtered, got: {result[:100]}")
    return TestResult(name="scan_code_cwe_zero_filtered", passed=not failures, duration=0, failures=failures)


def test_scan_code_filename_in_report():
    """The filename argument appears in the report header."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_CLEAN)):
        result = run(scan_code(code="x = 1", filename="my_module.py"))
    failures = []
    if "my_module.py" not in result:
        failures.append("Filename not in report")
    return TestResult(name="scan_code_filename_in_report", passed=not failures, duration=0, failures=failures)


def test_scan_code_mode_passed_through():
    """The mode argument is forwarded to call_cerebras."""
    from server import scan_code
    captured = {}
    def mock_cerebras(code, mode=""):
        captured["mode"] = mode
        return MOCK_RESPONSE_CLEAN
    with patch("server.call_cerebras", mock_cerebras):
        run(scan_code(code="x = 1", filename="test.py", mode="full"))
    failures = []
    if captured.get("mode") != "full":
        failures.append(f"Expected mode='full', got '{captured.get('mode')}'")
    return TestResult(name="scan_code_mode_passed_through", passed=not failures, duration=0, failures=failures)


def test_scan_code_mode_in_report():
    """The mode label appears in the formatted report."""
    from server import scan_code
    with patch("server.call_cerebras", make_mock_cerebras(MOCK_RESPONSE_ONE_FINDING)):
        result = run(scan_code(code="x = 1", filename="test.py", mode="standard"))
    failures = []
    if "standard" not in result.lower():
        failures.append("Mode 'standard' not shown in report")
    return TestResult(name="scan_code_mode_in_report", passed=not failures, duration=0, failures=failures)


def test_scan_file_reads_and_scans():
    """scan_file reads a real file and passes contents to the scanner."""
    from server import scan_file
    captured = {}
    def mock_cerebras(code, mode=""):
        captured["code"] = code
        return MOCK_RESPONSE_ONE_FINDING

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("print('hello')\n")
        tmp_path = f.name
    try:
        with patch("server.call_cerebras", mock_cerebras):
            result = run(scan_file(file_path=tmp_path))
        failures = []
        if "print('hello')" not in captured.get("code", ""):
            failures.append("File contents not passed to scanner")
        if "SCAN" not in result or "finding" not in result:
            failures.append("Missing scan report in response")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="scan_file_reads_and_scans", passed=not failures, duration=0, failures=failures)


def test_scan_file_not_found():
    """scan_file raises ToolError for missing files."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_file
    failures = []
    try:
        run(scan_file(file_path="/tmp/appsec_nonexistent_99999.py"))
        failures.append("Expected ToolError for missing file")
    except ToolError as e:
        if "not found" not in str(e).lower():
            failures.append(f"Expected 'not found' in error, got: {e}")
    return TestResult(name="scan_file_not_found", passed=not failures, duration=0, failures=failures)


def test_scan_file_empty():
    """scan_file raises ToolError for empty files."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        tmp_path = f.name
    try:
        failures = []
        try:
            run(scan_file(file_path=tmp_path))
            failures.append("Expected ToolError for empty file")
        except ToolError as e:
            if "empty" not in str(e).lower():
                failures.append(f"Expected 'empty' in error, got: {e}")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="scan_file_empty", passed=not failures, duration=0, failures=failures)


def test_scan_file_truncates_large():
    """scan_file truncates files over 90k chars."""
    from server import scan_file
    captured = {}
    def mock_cerebras(code, mode=""):
        captured["len"] = len(code)
        return MOCK_RESPONSE_CLEAN

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("x = 1\n" * 20_000)  # ~120k chars
        tmp_path = f.name
    try:
        with patch("server.call_cerebras", mock_cerebras):
            run(scan_file(file_path=tmp_path))
        failures = []
        if captured.get("len", 0) > 90_001:
            failures.append(f"Code not truncated: {captured['len']} chars passed to scanner")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="scan_file_truncates_large", passed=not failures, duration=0, failures=failures)


def test_scan_diff_no_changes():
    """scan_diff returns 'No changes' when git diff is empty."""
    from server import scan_diff
    mock_result = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch("subprocess.run", return_value=mock_result):
        result = run(scan_diff(repo_path="/tmp", ref="HEAD"))
    failures = []
    if "no changes" not in result.lower():
        failures.append(f"Expected 'No changes', got: {result[:100]}")
    return TestResult(name="scan_diff_no_changes", passed=not failures, duration=0, failures=failures)


def test_scan_diff_with_changes():
    """scan_diff passes diff output to the scanner."""
    from server import scan_diff
    captured = {}
    fake_diff = "diff --git a/foo.py b/foo.py\n+print('hi')"

    def mock_cerebras(code, mode=""):
        captured["code"] = code
        return MOCK_RESPONSE_ONE_FINDING

    mock_result = type("R", (), {"returncode": 0, "stdout": fake_diff, "stderr": ""})()
    with patch("subprocess.run", return_value=mock_result):
        with patch("server.call_cerebras", mock_cerebras):
            result = run(scan_diff(repo_path="/tmp", ref="main"))
    failures = []
    if fake_diff not in captured.get("code", ""):
        failures.append("Diff output not passed to scanner")
    if "SCAN" not in result or "finding" not in result:
        failures.append("Missing scan report in response")
    return TestResult(name="scan_diff_with_changes", passed=not failures, duration=0, failures=failures)


def test_scan_diff_staged_flag():
    """scan_diff with staged=True passes --cached to git."""
    from server import scan_diff
    captured = {}
    def mock_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch("subprocess.run", mock_run):
        run(scan_diff(repo_path="/tmp", staged=True))
    failures = []
    if "--cached" not in captured.get("cmd", []):
        failures.append(f"Expected --cached in git command, got: {captured.get('cmd')}")
    return TestResult(name="scan_diff_staged_flag", passed=not failures, duration=0, failures=failures)


def test_scan_diff_ref_argument():
    """scan_diff with ref='main' passes 'main' to git diff."""
    from server import scan_diff
    captured = {}
    def mock_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch("subprocess.run", mock_run):
        run(scan_diff(repo_path="/tmp", ref="main"))
    failures = []
    cmd = captured.get("cmd", [])
    if "main" not in cmd:
        failures.append(f"Expected 'main' in git command, got: {cmd}")
    if "--cached" in cmd:
        failures.append("--cached should not be present when ref is specified")
    return TestResult(name="scan_diff_ref_argument", passed=not failures, duration=0, failures=failures)


def test_scan_diff_git_error():
    """scan_diff raises ToolError when git fails."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_diff
    mock_result = type("R", (), {"returncode": 128, "stdout": "", "stderr": "fatal: not a git repo"})()
    failures = []
    with patch("subprocess.run", return_value=mock_result):
        try:
            run(scan_diff(repo_path="/tmp"))
            failures.append("Expected ToolError for git failure")
        except ToolError as e:
            if "fatal" not in str(e).lower():
                failures.append(f"Expected git error message, got: {e}")
    return TestResult(name="scan_diff_git_error", passed=not failures, duration=0, failures=failures)


def test_scan_diff_truncates_large():
    """scan_diff truncates diffs over 90k chars."""
    from server import scan_diff
    captured = {}
    big_diff = "+" * 100_000
    def mock_cerebras(code, mode=""):
        captured["len"] = len(code)
        return MOCK_RESPONSE_CLEAN
    mock_result = type("R", (), {"returncode": 0, "stdout": big_diff, "stderr": ""})()
    with patch("subprocess.run", return_value=mock_result):
        with patch("server.call_cerebras", mock_cerebras):
            run(scan_diff(repo_path="/tmp", ref="main"))
    failures = []
    if captured.get("len", 0) > 90_001:
        failures.append(f"Diff not truncated: {captured['len']} chars")
    return TestResult(name="scan_diff_truncates_large", passed=not failures, duration=0, failures=failures)


def test_format_findings_clean_report():
    """Formatted report for zero findings shows clean message."""
    from scanner_core import format_findings
    result = format_findings([], "test.py", mode="fast")
    failures = []
    if "SCAN test.py" not in result:
        failures.append("Missing SCAN header")
    if "clean" not in result.lower():
        failures.append("Missing 'clean' in empty report")
    return TestResult(name="format_findings_clean_report", passed=not failures, duration=0, failures=failures)


def test_format_findings_taint_display():
    """Tainted function references are displayed in the report."""
    from scanner_core import format_findings
    findings = [{
        "severity": "HIGH", "confidence": 0.9, "line": 5, "cwe": 89,
        "cwe_name": "SQL Injection", "explanation": "bad",
        "has_secret": False, "tainted_function_references": ["get_user", "query_db"],
    }]
    result = format_findings(findings, "test.py", mode="standard")
    failures = []
    if "get_user" not in result:
        failures.append("Tainted function 'get_user' not in report")
    if "query_db" not in result:
        failures.append("Tainted function 'query_db' not in report")
    return TestResult(name="format_findings_taint_display", passed=not failures, duration=0, failures=failures)


def test_parse_findings_filters_cwe_zero():
    """parse_findings drops entries with cwe=0."""
    from scanner_core import parse_findings
    raw = '```json\n[{"cwe": 0, "severity": "LOW"}, {"cwe": 89, "severity": "HIGH"}]\n```'
    findings = parse_findings(raw)
    failures = []
    if len(findings) != 1:
        failures.append(f"Expected 1 finding after filtering, got {len(findings)}")
    if findings and findings[0].get("cwe") != 89:
        failures.append(f"Wrong finding survived filter: {findings[0]}")
    return TestResult(name="parse_findings_filters_cwe_zero", passed=not failures, duration=0, failures=failures)


def test_parse_findings_no_json():
    """parse_findings returns empty list when no JSON block exists."""
    from scanner_core import parse_findings
    findings = parse_findings("This response has no json at all")
    failures = []
    if findings:
        failures.append(f"Expected empty list, got {findings}")
    return TestResult(name="parse_findings_no_json", passed=not failures, duration=0, failures=failures)


# ---------------------------------------------------------------------------
# Error path and security tests
# ---------------------------------------------------------------------------

def test_scan_code_cerebras_failure():
    """scan_code raises ToolError when Cerebras call fails."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_code
    def mock_raise(code, mode=""):
        raise ConnectionError("Network unreachable")
    failures = []
    with patch("server.call_cerebras", mock_raise):
        try:
            run(scan_code(code="x = 1", filename="test.py"))
            failures.append("Expected ToolError for Cerebras failure")
        except ToolError as e:
            if "scan failed" not in str(e).lower():
                failures.append(f"Expected 'Scan failed' in error, got: {e}")
    return TestResult(name="scan_code_cerebras_failure", passed=not failures, duration=0, failures=failures)


def test_scan_code_missing_api_key():
    """scan_code raises ToolError when API key is missing."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_code
    def mock_raise(code, mode=""):
        raise RuntimeError("CEREBRAS_API_KEY not set.")
    failures = []
    with patch("server.call_cerebras", mock_raise):
        try:
            run(scan_code(code="x = 1", filename="test.py"))
            failures.append("Expected ToolError for missing API key")
        except ToolError as e:
            if "CEREBRAS_API_KEY" not in str(e):
                failures.append(f"Expected API key message, got: {e}")
    return TestResult(name="scan_code_missing_api_key", passed=not failures, duration=0, failures=failures)


def test_scan_code_truncates_large():
    """scan_code truncates code over 90k chars."""
    from server import scan_code
    captured = {}
    def mock_cerebras(code, mode=""):
        captured["len"] = len(code)
        return MOCK_RESPONSE_CLEAN
    with patch("server.call_cerebras", mock_cerebras):
        run(scan_code(code="x" * 100_000, filename="big.py"))
    failures = []
    if captured.get("len", 0) > 90_001:
        failures.append(f"Code not truncated: {captured['len']} chars")
    return TestResult(name="scan_code_truncates_large", passed=not failures, duration=0, failures=failures)


def test_scan_file_blocked_path():
    """scan_file raises ToolError for sensitive system paths."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_file
    failures = []
    try:
        run(scan_file(file_path="/etc/passwd"))
        failures.append("Expected ToolError for /etc/passwd")
    except ToolError as e:
        if "not allowed" not in str(e).lower():
            failures.append(f"Expected 'not allowed' in error, got: {e}")
    return TestResult(name="scan_file_blocked_path", passed=not failures, duration=0, failures=failures)


def test_scan_diff_timeout():
    """scan_diff raises ToolError when git times out."""
    import subprocess as sp
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_diff
    def mock_timeout(cmd, **kwargs):
        raise sp.TimeoutExpired(cmd, 30)
    failures = []
    with patch("subprocess.run", mock_timeout):
        try:
            run(scan_diff(repo_path="/tmp", ref="main"))
            failures.append("Expected ToolError for timeout")
        except ToolError as e:
            if "timed out" not in str(e).lower():
                failures.append(f"Expected 'timed out' in error, got: {e}")
    return TestResult(name="scan_diff_timeout", passed=not failures, duration=0, failures=failures)


def test_scan_diff_invalid_ref():
    """scan_diff raises ToolError for shell injection in ref."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_diff
    failures = []
    try:
        run(scan_diff(repo_path="/tmp", ref="$(rm -rf /)"))
        failures.append("Expected ToolError for invalid ref")
    except ToolError as e:
        if "invalid git ref" not in str(e).lower():
            failures.append(f"Expected 'Invalid git ref' in error, got: {e}")
    return TestResult(name="scan_diff_invalid_ref", passed=not failures, duration=0, failures=failures)


def test_scan_code_no_language_param():
    """scan_code no longer accepts a 'language' parameter."""
    from server import mcp as server_mcp
    tools = server_mcp._tool_manager._tools
    failures = []
    if "scan_code" in tools:
        props = tools["scan_code"].parameters.get("properties", {})
        if "language" in props:
            failures.append("'language' param should be removed from scan_code")
    return TestResult(name="scan_code_no_language_param", passed=not failures, duration=0, failures=failures)


def test_scan_file_binary():
    """scan_file raises ToolError for binary files."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_file
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(b"\x00\x01\x02\x03binary content")
        tmp_path = f.name
    try:
        failures = []
        try:
            run(scan_file(file_path=tmp_path))
            failures.append("Expected ToolError for binary file")
        except ToolError as e:
            if "binary" not in str(e).lower():
                failures.append(f"Expected 'binary' in error, got: {e}")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="scan_file_binary", passed=not failures, duration=0, failures=failures)


def test_scan_file_too_large():
    """scan_file raises ToolError for files exceeding 10MB."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        tmp_path = f.name
    try:
        # Mock os.path.getsize to return a large value without creating a real large file
        with patch("server.os.path.getsize", return_value=11 * 1024 * 1024):
            failures = []
            try:
                run(scan_file(file_path=tmp_path))
                failures.append("Expected ToolError for large file")
            except ToolError as e:
                if "too large" not in str(e).lower():
                    failures.append(f"Expected 'too large' in error, got: {e}")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="scan_file_too_large", passed=not failures, duration=0, failures=failures)


def test_scan_diff_blocked_repo_path():
    """scan_diff raises ToolError for sensitive repo paths."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import scan_diff
    failures = []
    try:
        run(scan_diff(repo_path="/etc/"))
        failures.append("Expected ToolError for /etc/ repo_path")
    except ToolError as e:
        if "not allowed" not in str(e).lower():
            failures.append(f"Expected 'not allowed' in error, got: {e}")
    return TestResult(name="scan_diff_blocked_repo_path", passed=not failures, duration=0, failures=failures)


def test_format_findings_sorted_by_severity():
    """Findings are sorted CRITICAL > HIGH > MEDIUM > LOW in the report."""
    from scanner_core import format_findings
    findings = [
        {"severity": "LOW", "confidence": 0.5, "line": 1, "cwe": 200,
         "cwe_name": "Info Exposure", "explanation": "low issue",
         "has_secret": False, "tainted_function_references": []},
        {"severity": "CRITICAL", "confidence": 0.99, "line": 2, "cwe": 89,
         "cwe_name": "SQL Injection", "explanation": "critical issue",
         "has_secret": False, "tainted_function_references": []},
        {"severity": "HIGH", "confidence": 0.9, "line": 3, "cwe": 78,
         "cwe_name": "Command Injection", "explanation": "high issue",
         "has_secret": False, "tainted_function_references": []},
    ]
    result = format_findings(findings, "test.py", mode="fast")
    failures = []
    crit_pos = result.find("CRITICAL")
    high_pos = result.find("HIGH")
    low_pos = result.find("LOW")
    if crit_pos == -1 or high_pos == -1 or low_pos == -1:
        failures.append("Missing severity labels in report")
    elif not (crit_pos < high_pos < low_pos):
        failures.append(f"Findings not sorted by severity: CRITICAL@{crit_pos} HIGH@{high_pos} LOW@{low_pos}")
    return TestResult(name="format_findings_sorted_by_severity", passed=not failures, duration=0, failures=failures)


# ---------------------------------------------------------------------------
# Hook tests -- stop_scan.py
# ---------------------------------------------------------------------------

HOOKS_DIR = os.path.join(HERE, "hooks")
sys.path.insert(0, HOOKS_DIR)


def test_hook_detects_code_write():
    """stop_scan detects Write() with .py extension."""
    from stop_scan import detect_code_writes
    failures = []
    if not detect_code_writes('Wrote to /tmp/app.py'):
        failures.append("Should detect 'Wrote' + .py")
    if not detect_code_writes('Edit(/tmp/main.go)'):
        failures.append("Should detect 'Edit(' + .go")
    if not detect_code_writes('Created /tmp/index.ts'):
        failures.append("Should detect 'Created' + .ts")
    return TestResult(name="hook_detects_code_write", passed=not failures, duration=0, failures=failures)


def test_hook_ignores_non_code():
    """stop_scan does not fire for .txt, .md, .json writes."""
    from stop_scan import detect_code_writes
    failures = []
    if detect_code_writes('Wrote to /tmp/notes.txt'):
        failures.append("Should not trigger for .txt")
    if detect_code_writes('Created /tmp/README.md'):
        failures.append("Should not trigger for .md")
    if detect_code_writes('Updated /tmp/config.json'):
        failures.append("Should not trigger for .json")
    return TestResult(name="hook_ignores_non_code", passed=not failures, duration=0, failures=failures)


def test_hook_already_scanned_variants():
    """already_scanned recognizes scan_code, scan_file, scan_diff, SCAN header, CWE-."""
    from stop_scan import already_scanned
    failures = []
    for text, label in [
        ("Called scan_code on snippet", "scan_code"),
        ("Used scan_file to check app.py", "scan_file"),
        ("Ran scan_diff against main", "scan_diff"),
        ("SCAN app.py (fast): 1 finding(s)", "SCAN header"),
        ("Found CWE-89 SQL Injection", "CWE- reference"),
    ]:
        if not already_scanned(text):
            failures.append(f"Should recognize: {label}")
    return TestResult(name="hook_already_scanned_variants", passed=not failures, duration=0, failures=failures)


def test_hook_extension_matching():
    """has_code_extension does not match .cppunit, .css as code extensions."""
    from stop_scan import has_code_extension
    failures = []
    # Should NOT match
    if has_code_extension("Wrote to example.cppunit"):
        failures.append(".cppunit should not match as code extension")
    if has_code_extension("Updated styles.css"):
        failures.append(".css should not match as code extension")
    if has_code_extension("Changed config.csv"):
        failures.append(".csv should not match as code extension")
    # Should match
    if not has_code_extension("Wrote to app.py"):
        failures.append("app.py should match")
    if not has_code_extension("Created main.cpp"):
        failures.append("main.cpp should match")
    if not has_code_extension("Updated server.go"):
        failures.append("server.go should match")
    return TestResult(name="hook_extension_matching", passed=not failures, duration=0, failures=failures)


def test_hook_transcript_code_write():
    """Hook detects code writes from transcript JSONL file."""
    from stop_scan import _read_transcript_tail, detect_code_writes
    # Create a mock transcript JSONL with a Write tool call
    transcript_lines = [
        json.dumps({"role": "user", "message": {"content": "Write a python function"}}),
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "text", "text": "I'll create that function for you."},
            {"type": "tool_use", "name": "Write", "input": {"file_path": "/tmp/app.py", "content": "def hello(): pass"}},
        ]}}),
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "text", "text": "Created the file."},
        ]}}),
    ]
    failures = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(transcript_lines) + "\n")
        tmp_path = f.name
    try:
        text = _read_transcript_tail(tmp_path)
        if "Write(/tmp/app.py)" not in text:
            failures.append(f"Expected 'Write(/tmp/app.py)' in transcript text, got: {text[:200]}")
        if not detect_code_writes(text):
            failures.append("detect_code_writes should return True for transcript with Write tool call")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="hook_transcript_code_write", passed=not failures, duration=0, failures=failures)


def test_hook_transcript_already_scanned():
    """Hook recognizes scan_file tool use in transcript."""
    from stop_scan import _read_transcript_tail, already_scanned
    transcript_lines = [
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Write", "input": {"file_path": "/tmp/app.py", "content": "x"}},
        ]}}),
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "mcp__plugin_armis-appsec_scanner__scan_file",
             "input": {"file_path": "/tmp/app.py"}},
        ]}}),
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "text", "text": "SCAN app.py (fast): 1 finding(s)\nCWE-89 SQL Injection"},
        ]}}),
    ]
    failures = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(transcript_lines) + "\n")
        tmp_path = f.name
    try:
        text = _read_transcript_tail(tmp_path)
        if not already_scanned(text):
            failures.append(f"Should recognize scan evidence in transcript. Text: {text[:300]}")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="hook_transcript_already_scanned", passed=not failures, duration=0, failures=failures)


def test_hook_non_dict_input():
    """Hook handles non-dict JSON input gracefully (no crash)."""
    from stop_scan import main as hook_main
    failures = []
    # Simulate non-dict input (a JSON list)
    import io
    try:
        original_stdin = sys.stdin
        sys.stdin = io.StringIO('[1, 2, 3]')
        # Should not raise
        try:
            hook_main()
        except SystemExit:
            pass  # hook calls sys.exit(0)
    except Exception as e:
        failures.append(f"Hook crashed on non-dict input: {e}")
    finally:
        sys.stdin = original_stdin
    return TestResult(name="hook_non_dict_input", passed=not failures, duration=0, failures=failures)


def test_hook_empty_input():
    """Hook handles empty stdin gracefully."""
    from stop_scan import main as hook_main
    failures = []
    import io
    try:
        original_stdin = sys.stdin
        sys.stdin = io.StringIO('')
        try:
            hook_main()
        except SystemExit:
            pass
    except Exception as e:
        failures.append(f"Hook crashed on empty input: {e}")
    finally:
        sys.stdin = original_stdin
    return TestResult(name="hook_empty_input", passed=not failures, duration=0, failures=failures)


# --- Hook integration tests (run stop_scan.py as subprocess) --------------

def _run_hook_subprocess(stdin_json: str) -> dict:
    """Run stop_scan.py as a subprocess with JSON stdin, return parsed output."""
    import subprocess as sp
    result = sp.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stop_scan.py")],
        input=stdin_json, capture_output=True, text=True, timeout=10,
    )
    if result.stdout.strip():
        return json.loads(result.stdout)
    return {}


def test_hook_e2e_blocks_on_code_write():
    """E2E: hook blocks when last_assistant_message mentions writing a code file."""
    failures = []
    out = _run_hook_subprocess(json.dumps({
        "last_assistant_message": "I'll create that function. Wrote to /tmp/app.py"
    }))
    if out.get("decision") != "block":
        failures.append(f"Expected block decision, got: {out}")
    return TestResult(name="hook_e2e_blocks_on_code_write", passed=not failures, duration=0, failures=failures)


def test_hook_e2e_allows_after_scan():
    """E2E: hook allows when code was written AND scan evidence exists."""
    failures = []
    out = _run_hook_subprocess(json.dumps({
        "last_assistant_message": "Wrote to app.py with the fix. I ran scan_file and found CWE-89."
    }))
    if out.get("decision") == "block":
        failures.append(f"Should allow after scan, got: {out}")
    return TestResult(name="hook_e2e_allows_after_scan", passed=not failures, duration=0, failures=failures)


def test_hook_e2e_allows_no_code():
    """E2E: hook allows when no code was written."""
    failures = []
    out = _run_hook_subprocess(json.dumps({
        "last_assistant_message": "Here's how you could implement that feature."
    }))
    if out.get("decision") == "block":
        failures.append(f"Should allow no-code message, got: {out}")
    return TestResult(name="hook_e2e_allows_no_code", passed=not failures, duration=0, failures=failures)


def test_hook_e2e_allows_stop_hook_active():
    """E2E: hook allows when stop_hook_active is True (loop prevention)."""
    failures = []
    out = _run_hook_subprocess(json.dumps({
        "last_assistant_message": "Wrote to /tmp/app.py",
        "stop_hook_active": True,
    }))
    if out.get("decision") == "block":
        failures.append(f"Should allow when stop_hook_active=True, got: {out}")
    return TestResult(name="hook_e2e_allows_stop_hook_active", passed=not failures, duration=0, failures=failures)


def test_hook_e2e_empty_input():
    """E2E: hook allows gracefully on empty JSON input."""
    failures = []
    out = _run_hook_subprocess("{}")
    if out.get("decision") == "block":
        failures.append(f"Should allow empty input, got: {out}")
    return TestResult(name="hook_e2e_empty_input", passed=not failures, duration=0, failures=failures)


def test_hook_e2e_with_transcript():
    """E2E: hook blocks when transcript contains Write tool call to code file."""
    transcript_lines = [
        json.dumps({"role": "user", "message": {"content": "Write a function"}}),
        json.dumps({"role": "assistant", "message": {"content": [
            {"type": "text", "text": "I'll create that."},
            {"type": "tool_use", "name": "Write", "input": {"file_path": "/tmp/app.py", "content": "def f(): pass"}},
        ]}}),
    ]
    failures = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(transcript_lines))
        tmp_path = f.name
    try:
        out = _run_hook_subprocess(json.dumps({"transcript_path": tmp_path}))
        if out.get("decision") != "block":
            failures.append(f"Expected block from transcript Write, got: {out}")
    finally:
        os.unlink(tmp_path)
    return TestResult(name="hook_e2e_with_transcript", passed=not failures, duration=0, failures=failures)


# --- MCP protocol tests (spawn server.py, talk stdio) --------------------

async def _mcp_list_tools() -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {**os.environ, "CEREBRAS_API_KEY": "fake-key-for-test"}
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(HERE, "server.py")],
        env=env,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            return {t.name: t for t in tools_result.tools}


async def _mcp_call_tool(tool_name: str, args: dict) -> str:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {**os.environ, "CEREBRAS_API_KEY": "fake-key-for-test"}
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(HERE, "server.py")],
        env=env,
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=args)
            text_parts = [b.text for b in result.content if hasattr(b, "text")]
            return "\n".join(text_parts)


def test_mcp_tool_listing():
    """MCP server advertises exactly 3 tools with expected parameter schemas."""
    try:
        tools = asyncio.run(_mcp_list_tools())
    except Exception as e:
        return TestResult(name="mcp_tool_listing", passed=False, duration=0, error=str(e))

    failures = []
    expected = {"scan_code", "scan_file", "scan_diff"}
    if set(tools.keys()) != expected:
        failures.append(f"Expected {expected}, got {set(tools.keys())}")

    if "scan_code" in tools:
        props = tools["scan_code"].inputSchema.get("properties", {})
        for param in ["code", "filename", "mode"]:
            if param not in props:
                failures.append(f"scan_code missing '{param}' parameter")

    if "scan_file" in tools:
        props = tools["scan_file"].inputSchema.get("properties", {})
        if "file_path" not in props:
            failures.append("scan_file missing 'file_path' parameter")

    if "scan_diff" in tools:
        props = tools["scan_diff"].inputSchema.get("properties", {})
        for param in ["repo_path", "ref", "staged"]:
            if param not in props:
                failures.append(f"scan_diff missing '{param}' parameter")

    return TestResult(name="mcp_tool_listing", passed=not failures, duration=0, failures=failures)


def test_mcp_scan_file_not_found():
    """MCP call to scan_file with missing file returns error, not crash."""
    try:
        result = asyncio.run(_mcp_call_tool(
            "scan_file", {"file_path": "/tmp/appsec_mcp_test_no_exist.py"}
        ))
    except Exception as e:
        return TestResult(name="mcp_scan_file_not_found", passed=False, duration=0, error=str(e))
    failures = []
    if "not found" not in result.lower() and "error" not in result.lower():
        failures.append(f"Expected error message, got: {result[:100]}")
    return TestResult(name="mcp_scan_file_not_found", passed=not failures, duration=0, failures=failures)


def test_mcp_scan_file_empty():
    """MCP call to scan_file with empty file returns 'empty' message."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        tmp_path = f.name
    try:
        result = asyncio.run(_mcp_call_tool("scan_file", {"file_path": tmp_path}))
    except Exception as e:
        os.unlink(tmp_path)
        return TestResult(name="mcp_scan_file_empty", passed=False, duration=0, error=str(e))
    os.unlink(tmp_path)
    failures = []
    if "empty" not in result.lower():
        failures.append(f"Expected 'empty' message, got: {result[:100]}")
    return TestResult(name="mcp_scan_file_empty", passed=not failures, duration=0, failures=failures)


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

ALL_TESTS = [
    # Direct / unit tests (no transport, instant)
    ("direct", test_tool_registration),
    ("direct", test_scan_code_returns_report_and_raw),
    ("direct", test_scan_code_clean),
    ("direct", test_scan_code_multi_findings),
    ("direct", test_scan_code_malformed_response),
    ("direct", test_scan_code_cwe_zero_filtered),
    ("direct", test_scan_code_filename_in_report),
    ("direct", test_scan_code_mode_passed_through),
    ("direct", test_scan_code_mode_in_report),
    ("direct", test_scan_file_reads_and_scans),
    ("direct", test_scan_file_not_found),
    ("direct", test_scan_file_empty),
    ("direct", test_scan_file_truncates_large),
    ("direct", test_scan_diff_no_changes),
    ("direct", test_scan_diff_with_changes),
    ("direct", test_scan_diff_staged_flag),
    ("direct", test_scan_diff_ref_argument),
    ("direct", test_scan_diff_git_error),
    ("direct", test_scan_diff_truncates_large),
    ("direct", test_format_findings_clean_report),
    ("direct", test_format_findings_taint_display),
    ("direct", test_parse_findings_filters_cwe_zero),
    ("direct", test_parse_findings_no_json),
    # Error path and security tests
    ("direct", test_scan_code_cerebras_failure),
    ("direct", test_scan_code_missing_api_key),
    ("direct", test_scan_code_truncates_large),
    ("direct", test_scan_file_blocked_path),
    ("direct", test_scan_diff_timeout),
    ("direct", test_scan_diff_invalid_ref),
    ("direct", test_scan_code_no_language_param),
    # New behavior tests
    ("direct", test_scan_file_binary),
    ("direct", test_scan_file_too_large),
    ("direct", test_scan_diff_blocked_repo_path),
    ("direct", test_format_findings_sorted_by_severity),
    # Hook tests
    ("direct", test_hook_detects_code_write),
    ("direct", test_hook_ignores_non_code),
    ("direct", test_hook_already_scanned_variants),
    ("direct", test_hook_extension_matching),
    ("direct", test_hook_transcript_code_write),
    ("direct", test_hook_transcript_already_scanned),
    ("direct", test_hook_non_dict_input),
    ("direct", test_hook_empty_input),
    # Hook integration tests (subprocess)
    ("direct", test_hook_e2e_blocks_on_code_write),
    ("direct", test_hook_e2e_allows_after_scan),
    ("direct", test_hook_e2e_allows_no_code),
    ("direct", test_hook_e2e_allows_stop_hook_active),
    ("direct", test_hook_e2e_empty_input),
    ("direct", test_hook_e2e_with_transcript),
    # MCP transport tests (spawn server.py via stdio)
    ("mcp", test_mcp_tool_listing),
    ("mcp", test_mcp_scan_file_not_found),
    ("mcp", test_mcp_scan_file_empty),
]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AppSec MCP Test Harness (no LLM needed)")
    parser.add_argument("-t", "--test", nargs="*", help="Filter tests by name substring")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--list", action="store_true", help="List tests and exit")
    parser.add_argument("--direct-only", action="store_true", help="Skip MCP transport tests")
    parser.add_argument("--mcp-only", action="store_true", help="Only MCP transport tests")
    args = parser.parse_args()

    tests = ALL_TESTS
    if args.direct_only:
        tests = [(c, f) for c, f in tests if c == "direct"]
    if args.mcp_only:
        tests = [(c, f) for c, f in tests if c == "mcp"]
    if args.test:
        tests = [(c, f) for c, f in tests if any(p in f.__name__ for p in args.test)]

    if args.list:
        print(f"\n  {'Cat':<8s} {'Test'}")
        print(f"  {'-'*8} {'-'*50}")
        for cat, fn in tests:
            print(f"  {cat:<8s} {fn.__name__}")
        print(f"\n  {len(tests)} test(s)")
        return

    if not tests:
        print("No tests matched.")
        sys.exit(1)

    print(f"\n  Running {len(tests)} test(s)...\n")
    results: list[TestResult] = []
    for cat, fn in tests:
        t0 = time.time()
        try:
            r = fn()
            r.duration = time.time() - t0
        except Exception as e:
            r = TestResult(name=fn.__name__, passed=False, duration=time.time() - t0, error=str(e))
        print_result(r)
        results.append(r)

    passed = sum(1 for r in results if r.passed and not r.error)
    failed = sum(1 for r in results if not r.passed and not r.error)
    errors = sum(1 for r in results if r.error)
    total = sum(r.duration for r in results)

    print(f"\n  {'='*55}")
    print(f"  {passed} passed, {failed} failed, {errors} errors  ({total:.2f}s)")
    if failed == 0 and errors == 0:
        print(f"  \033[32mAll tests passed!\033[0m")
    print(f"  {'='*55}\n")
    sys.exit(1 if (failed + errors) > 0 else 0)


if __name__ == "__main__":
    main()

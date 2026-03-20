"""
Armis AppSec Scanner Core

Shared scanning logic used by the MCP server, hooks, and any other surface.

Calls the Moose scanning API (POST /api/v1/scan/fast) which proxies the LLM
call server-side. No API keys needed client-side — just APPSEC_API_TOKEN.
"""

import json
import logging
import os
import re

import httpx

logger = logging.getLogger("appsec-mcp")

# ---------------------------------------------------------------------------
# Output formatting constants
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ---------------------------------------------------------------------------
# API configuration
# ---------------------------------------------------------------------------
_API_URLS = {
    "dev": "https://moose-dev.armis.com/api/v1",
    "prod": "https://moose.armis.com/api/v1",
}
_APPSEC_ENV = os.environ.get("APPSEC_ENV", "dev")
APPSEC_API_URL = os.environ.get("APPSEC_API_URL", _API_URLS.get(_APPSEC_ENV, _API_URLS["dev"]))
APPSEC_API_TOKEN = os.environ.get("APPSEC_API_TOKEN", "")

# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------
def call_appsec_api(code: str) -> str:
    """Send code to the AppSec scanning API and return raw LLM response."""
    if not APPSEC_API_TOKEN:
        raise RuntimeError(
            "APPSEC_API_TOKEN not set. Run install.sh or export APPSEC_API_TOKEN."
        )

    url = f"{APPSEC_API_URL.rstrip('/')}/scan/fast"

    if not url.startswith("https://") and "localhost" not in url and "127.0.0.1" not in url:
        raise RuntimeError("APPSEC_API_URL must use HTTPS (except localhost).")

    response = httpx.post(
        url,
        json={"code": code},
        headers={"Authorization": f"Basic {APPSEC_API_TOKEN}"},
        timeout=120.0,
    )
    response.raise_for_status()
    return response.json()["raw_response"]


def parse_findings(raw: str) -> list[dict]:
    """Extract the JSON findings array from the LLM response."""
    match = re.search(r"```json([\s\S]*?)```", raw, re.MULTILINE)
    if not match:
        logger.warning("No JSON block found in LLM response")
        return []

    try:
        findings = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        snippet = match.group(1)[:200]
        logger.warning(f"Failed to parse JSON: {exc}\nContent: {snippet}")
        return []

    # Filter out findings with invalid CWEs (same as production pipeline)
    return [f for f in findings if f.get("cwe") and f.get("cwe") != 0]


def format_findings(findings: list[dict], filename: str) -> str:
    """Format findings as compact plain text optimized for LLM consumption.

    No markdown decoration, emojis, or formatting — just the data Claude
    needs to understand and act on the results. Minimizes token usage.
    """
    if not findings:
        return f"SCAN {filename}: clean, no findings."

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "").upper(), 99))

    lines = [f"SCAN {filename}: {len(findings)} finding(s)"]

    for i, f in enumerate(findings):
        severity = f.get("severity", "unknown").upper()
        cwe = f.get("cwe", "?")
        cwe_name = f.get("cwe_name", "")
        confidence = f.get("confidence", 0)
        line_num = f.get("line", "?")
        explanation = f.get("explanation", "")
        has_secret = f.get("has_secret", False)
        tainted = f.get("tainted_function_references", [])

        parts = [f"[{i+1}] {severity} CWE-{cwe} L{line_num}: {explanation}"]
        if has_secret:
            parts[0] += " [SECRET]"
        if tainted:
            parts.append(f"    tainted: {', '.join(tainted)}")

        lines.extend(parts)

    return "\n".join(lines)


def scan(code: str, filename: str = "snippet") -> tuple[str, list[dict]]:
    """Scan code and return (formatted_report, raw_findings)."""
    raw = call_appsec_api(code)
    findings = parse_findings(raw)
    report = format_findings(findings, filename)
    return report, findings

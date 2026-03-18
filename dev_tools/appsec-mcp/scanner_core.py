"""
Armis AppSec Scanner Core

Shared scanning logic used by the MCP server, hooks, and any other surface.

TEMPORARY: This module calls Cerebras directly with hardcoded prompts.
In production, replace call_cerebras() with a call to the Moose scanning API.
The rest of the module (parsing, formatting) is permanent.
"""

import json
import logging
import os
import re
import ssl

import httpx
from cerebras.cloud.sdk import Cerebras

logger = logging.getLogger("appsec-mcp")

# ---------------------------------------------------------------------------
# Output formatting constants
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ---------------------------------------------------------------------------
# Cerebras client
# TEMPORARY: Direct LLM call. In production, this should go through the
# Moose scanning API which manages model selection, prompt versioning,
# and result normalization.
# ---------------------------------------------------------------------------
# TEMPORARY: Model ID will be platform-configurable in production.
MODEL_ID = os.environ.get("APPSEC_MODEL", "qwen-3-235b-a22b-instruct-2507")

_client: Cerebras | None = None


def _get_client() -> Cerebras:
    """Lazily create the Cerebras client on first use."""
    global _client
    if _client is None:
        api_key = os.environ.get("CEREBRAS_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "CEREBRAS_API_KEY not set. Export it before starting the server."
            )
        # TEMPORARY: macOS system trust store workaround for corporate VPN.
        # Replace with proper cert configuration in production.
        ssl_ctx = ssl.create_default_context()
        http_client = httpx.Client(verify=ssl_ctx)
        _client = Cerebras(api_key=api_key, http_client=http_client)
    return _client

# ---------------------------------------------------------------------------
# Scanner prompt -- composable parts assembled per scan mode
# TEMPORARY: In production, the prompt lives in the Moose-AI pipeline
# and is versioned there. Having it here is a pragmatic shortcut for
# local-first operation without the full platform.
# ---------------------------------------------------------------------------
_PROMPT_INTRO = """\
Determine what checks are needed to find all the possible CWEs, path traversal, \
resource/memory leaks, logical flaws leading to security issues or data protection \
flaw or cryptographic issues or plaintext passwords in the code below.
Read the code first. Return the most accurate CWE or empty list if all \
issues are not vulnerable. Reduce False positives by verifying exploitability \
-- confirm whether a real attack path exists from user-controlled input to \
the vulnerable sink before reporting the CWE."""

_TAINT_TRACKING = """

For each vulnerability found, trace the data flow from source to sink and identify \
all user-defined functions that sanitize, validate, encode, or transform tainted \
data along the path. Record these function names in the `tainted_function_references` \
field. Only include user-defined functions, not built-in or standard library functions. \
Return an empty list if none."""

_JSON_TEMPLATE = """

You will list the found vulnerabilities in a JSON format using the **EXACT** template below.
**DO NOT INCLUDE CODE** in explanation.
**DO NOT OMIT** the triple backticks (```json at the beginning and ``` at the end).
If provided code has exposed secrets has_secret is true regardless of CWE.

```json
[
    {"severity": string, "confidence": float, "line": int, "cwe": int, \
"cwe_name": str, "explanation": string, "has_secret": bool, \
"tainted_function_references": ["func1", "func2"]},
    ...
]
```"""

_CWE_HINTS = """

Additionally,
If dealing with Error Conditions, Return Values, Status Codes, and asserts, \
test CWE-253: Incorrect Check of Function Return Value and CWE-617: Reachable Assertion.
If dealing with credentials, test CWE-522: Insufficiently Protected Credentials.
If dealing with recursion, test CWE-674: Uncontrolled Recursion.
If dealing with race conditions, test CWE-362: Race Condition.
If dealing with pointer issues: test CWE-761: Free of Pointer not at Start of Buffer \
and CWE-822: Untrusted Pointer Dereference
If dealing with type confusion, test CWE-843: Access of Resource Using Incompatible Type \
('Type Confusion')
If incorrect arguments in function calls resulting in further issues, \
test CWE-628: Function Call with Incorrectly Specified Arguments
If dealing with Resource Management Errors, test CWE-770: Allocation of Resources \
Without Limits or Throttling"""

# Three scan modes: full (production), standard (with taint), fast (minimal)
PROMPTS = {
    "full": _PROMPT_INTRO + _TAINT_TRACKING + _JSON_TEMPLATE + _CWE_HINTS,
    "standard": _PROMPT_INTRO + _TAINT_TRACKING + _JSON_TEMPLATE,
    "fast": _PROMPT_INTRO + _JSON_TEMPLATE,
}

DEFAULT_MODE = os.environ.get("APPSEC_SCAN_MODE", "fast")
if DEFAULT_MODE not in PROMPTS:
    logger.warning(f"Unknown scan mode '{DEFAULT_MODE}', falling back to 'fast'")
    DEFAULT_MODE = "fast"


def _build_prompt(mode: str) -> str:
    """Assemble the scanner prompt for the given mode, with model-specific tweaks."""
    prompt = PROMPTS.get(mode, PROMPTS[DEFAULT_MODE])
    # Inject /think for Qwen models (enables extended reasoning)
    if "qwen" in MODEL_ID.lower():
        prompt = prompt.replace(
            "Read the code first. Return",
            "Read the code first. /think Return",
        )
    return prompt


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------
def call_cerebras(code: str, mode: str = "") -> str:
    """Send code to Cerebras and return the raw LLM response.

    TEMPORARY: This function calls Cerebras directly. In production,
    replace with a call to the Moose scanning API endpoint.
    """
    c = _get_client()

    effective_mode = mode if mode in PROMPTS else DEFAULT_MODE
    prompt = _build_prompt(effective_mode)

    response = c.chat.completions.create(
        model=MODEL_ID,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"code\n{code}"},
        ],
        temperature=0.2,
        max_completion_tokens=4096,
    )
    return response.choices[0].message.content or ""


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


def format_findings(findings: list[dict], filename: str, mode: str = "") -> str:
    """Format findings as compact plain text optimized for LLM consumption.

    No markdown decoration, emojis, or formatting — just the data Claude
    needs to understand and act on the results. Minimizes token usage.
    """
    mode_label = f" ({mode})" if mode else ""

    if not findings:
        return f"SCAN {filename}{mode_label}: clean, no findings."

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "").upper(), 99))

    lines = [f"SCAN {filename}{mode_label}: {len(findings)} finding(s)"]

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


def scan(code: str, filename: str = "snippet", mode: str = "") -> tuple[str, list[dict]]:
    """Scan code and return (formatted_report, raw_findings)."""
    raw = call_cerebras(code, mode)
    findings = parse_findings(raw)
    report = format_findings(findings, filename, mode=mode or DEFAULT_MODE)
    return report, findings

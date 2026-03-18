#!/usr/bin/env python3
"""
Claude Code Stop Hook -- Auto-scan on completion

Fires when Claude is about to finish responding. Uses "decision: block"
to prevent Claude from stopping until it scans any code it wrote using
the AppSec MCP scanner tools.

This is a command-based hook: it reads hook input from stdin, checks
deterministically whether code files were written, and outputs JSON
with {"decision": "block", "reason": "..."} or {} to allow stopping.
"""

import json
import os
import re
import sys

# Source code extensions that should trigger a scan
CODE_EXTENSIONS = {
    ".py", ".go", ".js", ".ts", ".tsx", ".jsx",
    ".java", ".rb", ".c", ".cpp", ".h", ".hpp",
    ".rs", ".php", ".swift", ".kt", ".scala", ".sql",
    ".cs", ".sh", ".bash", ".zsh",
}

# Structural markers from transcript parsing that indicate a Write/Edit tool was used.
# These are emitted by _read_transcript_tail() when it finds tool_use blocks.
TOOL_WRITE_MARKERS = [
    "tool:Write",
    "tool:Edit",
    "tool:MultiEdit",
    "tool:NotebookEdit",
]


_CODE_EXT_PATTERN = re.compile(
    r'[\w.-]+(' + '|'.join(re.escape(e) for e in CODE_EXTENSIONS) + r')(?:[)\s"\'`,;:\].\n]|$)'
)


def has_code_extension(text):
    """Check if text contains a file path with a code extension."""
    return bool(_CODE_EXT_PATTERN.search(text))


def detect_code_writes(text):
    """Check if a Write/Edit tool actually wrote a code file.

    Only triggers on structural evidence from the transcript: tool:Write or
    tool:Edit paired with a code file extension in the Write(path) entry.
    Does NOT trigger on fenced code blocks or natural-language keywords like
    "Created" or "Updated" — those cause false positives on explanations.
    """
    if not text:
        return False

    # Require both: a Write/Edit tool call AND a code file extension in the path
    has_write_tool = any(marker in text for marker in TOOL_WRITE_MARKERS)
    if has_write_tool and has_code_extension(text):
        return True

    return False


def already_scanned(text):
    """Check if the AppSec MCP scanner was actually invoked in this turn.

    Only matches on structural evidence — actual MCP tool calls — to avoid
    false negatives when Claude discusses security topics in natural language.
    """
    # MCP scanner tool calls (the definitive signal)
    MCP_TOOL_MARKERS = [
        "mcp__plugin_armis-appsec_scanner__scan_file",
        "mcp__plugin_armis-appsec_scanner__scan_code",
        "mcp__plugin_armis-appsec_scanner__scan_diff",
        # Short forms from transcript parsing (tool:X entries)
        "tool:scan_file",
        "tool:scan_code",
        "tool:scan_diff",
    ]
    for marker in MCP_TOOL_MARKERS:
        if marker in text:
            return True
    return False


def _debug_log(msg):
    """Append debug info to a log file for diagnosing hook input."""
    log_path = os.path.join(os.path.dirname(__file__), "hook_debug.log")
    try:
        with open(log_path, "a") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def _read_transcript_tail(transcript_path, max_lines=50):
    """Read the last N lines of the transcript JSONL and extract text content.

    The transcript is a JSONL file where each line is a JSON object with
    "role" and "message" fields. We read the tail to get the most recent
    assistant messages, tool uses, and tool results.
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return ""

    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""

    # Take the tail — we only care about the current turn
    tail = lines[-max_lines:] if len(lines) > max_lines else lines

    parts = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Extract text from message content blocks
        message = entry.get("message", {})
        if isinstance(message, dict):
            content = message.get("content", [])
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        # Text blocks
                        if block.get("type") == "text":
                            parts.append(block.get("text", ""))
                        # Tool use blocks — capture tool name and input
                        elif block.get("type") == "tool_use":
                            parts.append(f"tool:{block.get('name', '')}")
                            tool_input = block.get("input", {})
                            if isinstance(tool_input, dict):
                                # Capture file_path from Write/Edit tool calls
                                fp = tool_input.get("file_path", "")
                                if fp:
                                    parts.append(f"Write({fp})")
                        # Tool result blocks
                        elif block.get("type") == "tool_result":
                            for sub in block.get("content", []):
                                if isinstance(sub, dict) and sub.get("type") == "text":
                                    parts.append(sub.get("text", ""))

    return "\n".join(parts)


def main():
    # Read hook input from stdin
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except Exception:
        hook_input = {}

    if not isinstance(hook_input, dict):
        hook_input = {}

    _debug_log("=== Hook fired ===")
    _debug_log(f"Input keys: {list(hook_input.keys())}")

    # If this is a re-fire after a previous block, allow to prevent infinite loops
    if hook_input.get("stop_hook_active"):
        _debug_log("DECISION: allow (stop_hook_active=True, avoiding loop)")
        print(json.dumps({}))
        sys.exit(0)

    # Primary: last_assistant_message (most reliably populated)
    last_msg = hook_input.get("last_assistant_message", "")

    # Secondary: transcript tail (richer context with tool call structure)
    transcript_path = hook_input.get("transcript_path", "")
    transcript_text = _read_transcript_tail(transcript_path)

    # Tertiary: dump all hook input for keyword matching
    combined = "\n".join(filter(None, [last_msg, transcript_text, json.dumps(hook_input)]))

    _debug_log(f"transcript_path={transcript_path}")
    _debug_log(f"last_assistant_message (last 300 chars): {last_msg[-300:]}")
    _debug_log(f"transcript_text (last 500 chars): {transcript_text[-500:]}")

    code_detected = detect_code_writes(combined)
    scan_found = already_scanned(combined)
    _debug_log(f"code_detected={code_detected}, already_scanned={scan_found}")

    if code_detected and not scan_found:
        _debug_log("DECISION: block")
        print(json.dumps({
            "decision": "block",
            "reason": (
                "Code was written but not scanned for security vulnerabilities. "
                "Please use scan_file or scan_code to check the code before finishing."
            ),
        }))
    else:
        _debug_log(f"DECISION: allow (code={code_detected}, scanned={scan_found})")
        # No code detected or already scanned -- let Claude finish normally
        print(json.dumps({}))

    sys.exit(0)


if __name__ == "__main__":
    main()

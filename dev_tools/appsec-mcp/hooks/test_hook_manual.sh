#!/bin/bash
# Manual smoke tests for stop_scan.py
# Run: bash dev_tools/appsec-mcp/hooks/test_hook_manual.sh

HOOK="$(dirname "$0")/stop_scan.py"
PASS=0
FAIL=0

check() {
    local label="$1" expect="$2" input="$3"
    output=$(echo "$input" | python3 "$HOOK" 2>/dev/null)
    if echo "$output" | grep -q "$expect"; then
        echo "  PASS  $label"
        ((PASS++))
    else
        echo "  FAIL  $label"
        echo "        expected '$expect' in: $output"
        ((FAIL++))
    fi
}

echo "Stop hook smoke tests"
echo "---------------------"

# ── SHOULD BLOCK: tool:Write with code file, no scan ──

check "blocks on tool:Write + .py" '"decision": "block"' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/app.py)"}'

check "blocks on tool:Edit + .go" '"decision": "block"' \
    '{"last_assistant_message": "tool:Edit\nWrite(/tmp/handler.go)"}'

check "blocks on tool:Write + .js (with discussion)" '"decision": "block"' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/server.js)\nHere is your Express server."}'

# ── SHOULD BLOCK: security discussion does NOT count as scan ──

check "blocks despite security discussion" '"decision": "block"' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/auth.py)\nThis has potential vulnerabilities: SQL injection (severity high) and the scan shows findings."}'

check "blocks despite CWE mention" '"decision": "block"' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/vuln.py)\nNote: this pattern is related to CWE-79 cross-site scripting."}'

# ── SHOULD ALLOW: tool:Write + actual MCP scan ──

check "allows after MCP scan_file" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/app.py)\ntool:mcp__plugin_armis-appsec_scanner__scan_file"}'

check "allows after MCP scan_code" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/app.go)\nmcp__plugin_armis-appsec_scanner__scan_code"}'

check "allows after MCP scan_diff" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/handler.py)\nmcp__plugin_armis-appsec_scanner__scan_diff"}'

check "allows after tool:scan_file (short form)" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/app.py)\ntool:scan_file found no issues."}'

# ── SHOULD ALLOW: no code written ──

check "allows no code" '{}' \
    '{"last_assistant_message": "Here is how you could approach that."}'

check "allows empty input" '{}' '{}'

# ── SHOULD ALLOW: fenced code blocks (explanations, NOT file writes) ──

# shellcheck disable=SC2016
check "allows fenced python block (no file write)" '{}' \
    '{"last_assistant_message": "Here is the code:\n```python\ndef foo(): pass\n```"}'

# shellcheck disable=SC2016
check "allows fenced go block with security discussion" '{}' \
    '{"last_assistant_message": "```go\ndb.Query(\"SELECT * FROM users WHERE id = ?\", id)\n```\nThis prevents SQL injection."}'

# ── SHOULD ALLOW: non-code file writes ──

check "allows JSON file write" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/config.json)"}'

check "allows YAML file write" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/deploy.yaml)"}'

# ── SHOULD ALLOW: stop_hook_active loop prevention ──

check "allows stop_hook_active" '{}' \
    '{"last_assistant_message": "tool:Write\nWrite(/tmp/app.py)", "stop_hook_active": true}'

echo "---------------------"
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "  All passed!" || exit 1

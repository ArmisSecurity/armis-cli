#!/bin/bash
# Supply Chain Attack Detection Demo
# Shows how armis-cli supply-chain blocks real attack patterns in real-time.
#
# What this demonstrates:
#   1. Proxy strips young (malicious) versions from registry metadata
#   2. Old (legitimate) versions pass through normally
#   3. The block summary on stderr tells the developer exactly what happened
#
# Prerequisites: make build
set -e

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CLI="$ROOT/bin/armis-cli"

if [ ! -f "$CLI" ]; then
  echo "Build first: make build" >&2
  exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   armis-cli supply-chain — Supply Chain Attack Demo              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Mock registry simulates freshly-published attack packages. ║"
echo "║  The proxy blocks young versions, passes old ones through.  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Start mock registry
echo "[*] Starting mock registry on :4873..."
go run "$ROOT/internal/supplychain/demo/mock_registry.go" &
MOCK_PID=$!
sleep 1
echo ""

# ─── event-stream: maintainer handoff attack ───────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attack 1: event-stream (maintainer handoff, Nov 2018)"
echo ""
echo "  Real story: A trusted maintainer handed off the package to an"
echo "  attacker who published v3.3.6 with code that stole Bitcoin"
echo "  wallets from Copay users. 8M weekly downloads."
echo ""
echo "  Simulated: v3.3.6 published 2h ago, v3.3.5 published 1yr ago"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "$ armis-cli supply-chain wrap npm view event-stream versions"
echo ""
npm_config_registry=http://127.0.0.1:4873 "$CLI" supply-chain wrap npm view event-stream versions 2>&1 || true
echo ""

# ─── ua-parser-js: account compromise ─────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attack 2: ua-parser-js (account compromise, Oct 2021)"
echo ""
echo "  Real story: Attacker hijacked the maintainer's npm account and"
echo "  pushed v1.0.33 with a cryptominer. 7M weekly downloads. GitHub"
echo "  advisory GHSA-pjwm-rvh2-c87w."
echo ""
echo "  Simulated: v1.0.33 published 3h ago, v1.0.32 published 6mo ago"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "$ armis-cli supply-chain wrap npm view ua-parser-js versions"
echo ""
npm_config_registry=http://127.0.0.1:4873 "$CLI" supply-chain wrap npm view ua-parser-js versions 2>&1 || true
echo ""

# ─── node-hide-console-windows: typosquat ─────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attack 3: node-hide-console-windows (typosquat, 2023)"
echo ""
echo "  Real story: Typosquat of legitimate 'node-hide-console-window'"
echo "  (note the extra 's'). Exfiltrated env vars and credentials."
echo "  Part of a campaign that published 1200+ malicious packages."
echo ""
echo "  Simulated: published 6h ago (only version)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "$ armis-cli supply-chain wrap npm view node-hide-console-windows version"
echo ""
npm_config_registry=http://127.0.0.1:4873 "$CLI" supply-chain wrap npm view node-hide-console-windows version 2>&1 || true
echo ""

# ─── Legitimate package: express ───────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Legitimate: express (published 1yr ago)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "$ armis-cli supply-chain wrap npm view express version"
echo ""
npm_config_registry=http://127.0.0.1:4873 "$CLI" supply-chain wrap npm view express version 2>&1 || true
echo ""

# ─── Summary ──────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Results:"
echo "  ✗ event-stream@3.3.6         BLOCKED (2h old)"
echo "  ✗ ua-parser-js@1.0.33        BLOCKED (3h old)"
echo "  ✗ node-hide-console-windows  BLOCKED (6h old)"
echo "  ✓ event-stream@3.3.5         PASSED  (1yr old)"
echo "  ✓ ua-parser-js@1.0.32        PASSED  (6mo old)"
echo "  ✓ express@4.18.2             PASSED  (1yr old)"
echo ""
echo "The 72h policy would have prevented all 3 real-world attacks."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

kill $MOCK_PID 2>/dev/null || true

package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// TestAttackDemo demonstrates how the proxy blocks real supply chain attack
// patterns. Each sub-test simulates a real incident with a freshly-published
// malicious package version.
func TestAttackDemo(t *testing.T) {
	now := time.Now()

	// Mock registry with attack packages
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pkg := r.URL.Path[1:]
		packages := map[string]map[string]interface{}{
			// event-stream: maintainer handoff attack (Nov 2018)
			// Attacker convinced maintainer to hand over publishing rights,
			// then injected flatmap-stream which stole Bitcoin wallets.
			"event-stream": {
				"time": map[string]string{
					"3.3.5": now.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
					"3.3.6": now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
				},
				"versions": map[string]interface{}{
					"3.3.5": map[string]string{"name": "event-stream", "version": "3.3.5"},
					"3.3.6": map[string]string{"name": "event-stream", "version": "3.3.6"},
				},
			},
			// ua-parser-js: account compromise (Oct 2021)
			// Attacker hijacked npm account, published versions with cryptominer.
			// 7M weekly downloads affected.
			"ua-parser-js": {
				"time": map[string]string{
					"1.0.32": now.Add(-180 * 24 * time.Hour).UTC().Format(time.RFC3339),
					"1.0.33": now.Add(-3 * time.Hour).UTC().Format(time.RFC3339),
				},
				"versions": map[string]interface{}{
					"1.0.32": map[string]string{"name": "ua-parser-js", "version": "1.0.32"},
					"1.0.33": map[string]string{"name": "ua-parser-js", "version": "1.0.33"},
				},
			},
			// node-hide-console-windows: typosquat (2023)
			// Typosquat of node-hide-console-window that exfiltrated credentials.
			"node-hide-console-windows": {
				"time": map[string]string{
					"2.0.6": now.Add(-6 * time.Hour).UTC().Format(time.RFC3339),
				},
				"versions": map[string]interface{}{
					"2.0.6": map[string]string{"name": "node-hide-console-windows", "version": "2.0.6"},
				},
			},
			// Legitimate package — old, should pass
			"express": {
				"time": map[string]string{
					"4.18.2": now.Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339),
				},
				"versions": map[string]interface{}{
					"4.18.2": map[string]string{"name": "express", "version": "4.18.2"},
				},
			},
		}

		data, ok := packages[pkg]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data) //nolint:errcheck,gosec
	}))
	defer mock.Close()

	// Start supply-chain proxy pointed at mock upstream
	proxy, err := supplychain.NewProxy(supplychain.ProxyConfig{
		Policy:      supplychain.Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: mock.URL,
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close() //nolint:errcheck,gosec

	t.Run("event-stream: maintainer handoff blocked", func(t *testing.T) {
		body := fetchMetadata(t, addr, "event-stream")

		var result map[string]json.RawMessage
		json.Unmarshal(body, &result) //nolint:errcheck,gosec

		var versions map[string]json.RawMessage
		json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

		if _, ok := versions["3.3.6"]; ok {
			t.Error("ATTACK NOT BLOCKED: event-stream@3.3.6 should be filtered (published 2h ago)")
		}
		if _, ok := versions["3.3.5"]; !ok {
			t.Error("legitimate version 3.3.5 should pass through")
		}

		t.Log("✓ event-stream@3.3.6 BLOCKED (published 2h ago — maintainer handoff attack)")
		t.Log("✓ event-stream@3.3.5 PASSED (published 1yr ago — safe)")
	})

	t.Run("ua-parser-js: account compromise blocked", func(t *testing.T) {
		body := fetchMetadata(t, addr, "ua-parser-js")

		var result map[string]json.RawMessage
		json.Unmarshal(body, &result) //nolint:errcheck,gosec

		var versions map[string]json.RawMessage
		json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

		if _, ok := versions["1.0.33"]; ok {
			t.Error("ATTACK NOT BLOCKED: ua-parser-js@1.0.33 should be filtered (published 3h ago)")
		}
		if _, ok := versions["1.0.32"]; !ok {
			t.Error("legitimate version 1.0.32 should pass through")
		}

		t.Log("✓ ua-parser-js@1.0.33 BLOCKED (published 3h ago — account compromise)")
		t.Log("✓ ua-parser-js@1.0.32 PASSED (published 6mo ago — safe)")
	})

	t.Run("node-hide-console-windows: typosquat fully blocked", func(t *testing.T) {
		body := fetchMetadata(t, addr, "node-hide-console-windows")

		var result map[string]json.RawMessage
		json.Unmarshal(body, &result) //nolint:errcheck,gosec

		var versions map[string]json.RawMessage
		json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

		if len(versions) != 0 {
			t.Errorf("ATTACK NOT BLOCKED: all versions of typosquat should be filtered, got %d", len(versions))
		}

		t.Log("✓ node-hide-console-windows FULLY BLOCKED (only version published 6h ago — typosquat)")
	})

	t.Run("express: legitimate package passes through", func(t *testing.T) {
		body := fetchMetadata(t, addr, "express")

		var result map[string]json.RawMessage
		json.Unmarshal(body, &result) //nolint:errcheck,gosec

		var versions map[string]json.RawMessage
		json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

		if _, ok := versions["4.18.2"]; !ok {
			t.Error("express@4.18.2 should pass through (published 1yr ago)")
		}

		t.Log("✓ express@4.18.2 PASSED (published 1yr ago — legitimate)")
	})

	// Summary
	blocked := proxy.Blocked()
	t.Logf("\n=== PROXY SUMMARY ===")
	t.Logf("Packages checked: %d", proxy.Checked())
	t.Logf("Versions blocked: %d", len(blocked))
	for _, b := range blocked {
		t.Logf("  BLOCKED: %s@%s (age: %s)", b.Name, b.Version, formatAge(b.Age))
	}
}

func fetchMetadata(t *testing.T, proxyAddr, pkg string) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/%s", proxyAddr, pkg), nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch %s: %v", pkg, err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	body, _ := io.ReadAll(resp.Body)
	return body
}

func formatAge(d time.Duration) string {
	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dd%dh", hours/24, hours%24)
}

//go:build ignore

// Mock registry that simulates freshly-published attack packages.
// Run: go run ./internal/supplychain/demo/mock_registry.go
// Then: npm_config_registry=http://127.0.0.1:4873 bin/armis-cli supply-chain wrap npm view event-stream versions
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	fmt.Fprintln(os.Stderr, "Mock registry on http://127.0.0.1:4873")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Simulated attacks (all published <72h ago):")
	fmt.Fprintln(os.Stderr, "  event-stream@3.3.6         — maintainer handoff (2018 incident)")
	fmt.Fprintln(os.Stderr, "  ua-parser-js@1.0.33        — account compromise (2021 incident)")
	fmt.Fprintln(os.Stderr, "  node-hide-console-windows  — typosquat (2023 campaign)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Safe packages (old):")
	fmt.Fprintln(os.Stderr, "  event-stream@3.3.5         — 1 year old")
	fmt.Fprintln(os.Stderr, "  ua-parser-js@1.0.32        — 6 months old")
	fmt.Fprintln(os.Stderr, "  express@4.18.2             — 1 year old")
	fmt.Fprintln(os.Stderr, "  lodash@4.17.21             — 2 years old")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Test with:")
	fmt.Fprintln(os.Stderr, "  npm_config_registry=http://127.0.0.1:4873 bin/armis-cli supply-chain wrap npm view event-stream versions")

	if err := http.ListenAndServe("127.0.0.1:4873", mux); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Path[1:]
	now := time.Now()

	packages := map[string]packageData{
		// Real attack: maintainer of event-stream handed off to attacker who published
		// a compromised version that stole cryptocurrency wallets (Nov 2018).
		"event-stream": {
			Time: map[string]string{
				"3.3.5": now.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"3.3.6": now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		// Real attack: attacker compromised the npm account of ua-parser-js maintainer
		// and published versions with cryptominer payloads (Oct 2021).
		"ua-parser-js": {
			Time: map[string]string{
				"1.0.32": now.Add(-180 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"1.0.33": now.Add(-3 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		// Real attack: typosquat package that exfiltrated environment variables
		// and credentials. Part of a larger campaign targeting Node.js devs (2023).
		"node-hide-console-windows": {
			Time: map[string]string{
				"2.0.6": now.Add(-6 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		// Legitimate packages — old, pass policy
		"express": {
			Time: map[string]string{
				"4.18.2": now.Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		"lodash": {
			Time: map[string]string{
				"4.17.21": now.Add(-800 * 24 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
	}

	data, ok := packages[pkg]
	if !ok {
		http.NotFound(w, r)
		return
	}

	versions := make(map[string]interface{})
	for v := range data.Time {
		versions[v] = map[string]interface{}{
			"name":    pkg,
			"version": v,
			"dist": map[string]string{
				"tarball": fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", pkg, pkg, v),
			},
		}
	}

	resp := map[string]interface{}{
		"name":     pkg,
		"time":     data.Time,
		"versions": versions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

type packageData struct {
	Time map[string]string
}

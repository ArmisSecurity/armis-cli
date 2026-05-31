package supplychain

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyFilterMetadata(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]interface{}{
		"name": "express",
		"time": map[string]string{
			"created":  oldTime,
			"modified": youngTime,
			"4.18.2":   oldTime,
			"4.19.0":   youngTime,
		},
		"versions": map[string]interface{}{
			"4.18.2": map[string]string{"name": "express", "version": "4.18.2"},
			"4.19.0": map[string]string{"name": "express", "version": "4.19.0"},
		},
	}

	body, _ := json.Marshal(metadata)

	policy := Policy{MinReleaseAge: 72 * time.Hour}
	proxy := &Proxy{policy: policy}

	filtered, blocked := proxy.filterMetadata(body, "express")

	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(blocked))
	}
	if blocked[0].Name != "express" || blocked[0].Version != "4.19.0" { //nolint:goconst // test value
		t.Errorf("unexpected blocked: %+v", blocked[0])
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	var versions map[string]json.RawMessage
	if err := json.Unmarshal(result["versions"], &versions); err != nil {
		t.Fatalf("unmarshal versions: %v", err)
	}

	if _, ok := versions["4.18.2"]; !ok {
		t.Error("old version 4.18.2 should remain")
	}
	if _, ok := versions["4.19.0"]; ok {
		t.Error("young version 4.19.0 should be removed")
	}

	var timeMap map[string]string
	if err := json.Unmarshal(result["time"], &timeMap); err != nil {
		t.Fatalf("unmarshal time: %v", err)
	}
	if _, ok := timeMap["4.19.0"]; ok {
		t.Error("young version should be removed from time map")
	}
	if _, ok := timeMap["created"]; !ok {
		t.Error("created field should be preserved")
	}
}

func TestProxyFilterMetadata_AllOld(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]interface{}{
		"name": "lodash",
		"time": map[string]string{
			"4.17.21": oldTime,
		},
		"versions": map[string]interface{}{
			"4.17.21": map[string]string{"name": "lodash"},
		},
	}
	body, _ := json.Marshal(metadata)

	proxy := &Proxy{policy: Policy{MinReleaseAge: 72 * time.Hour}}

	filtered, blocked := proxy.filterMetadata(body, "lodash")

	if len(blocked) != 0 {
		t.Errorf("expected no blocked, got %d", len(blocked))
	}
	if string(filtered) != string(body) {
		t.Error("body should be unchanged when no versions are blocked")
	}
}

func TestProxyFilterMetadata_InvalidJSON(t *testing.T) {
	proxy := &Proxy{policy: Policy{MinReleaseAge: 72 * time.Hour}}

	body := []byte(`not json`)
	filtered, blocked := proxy.filterMetadata(body, "test")

	if blocked != nil {
		t.Error("expected nil blocked for invalid JSON")
	}
	if string(filtered) != string(body) {
		t.Error("invalid JSON should be returned as-is")
	}
}

func TestProxyStartAndServe(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metadata := map[string]interface{}{
			"name": "express",
			"time": map[string]string{
				"4.18.2": oldTime,
				"4.19.0": youngTime,
			},
			"versions": map[string]interface{}{
				"4.18.2": map[string]string{"name": "express"},
				"4.19.0": map[string]string{"name": "express"},
			},
		}
		json.NewEncoder(w).Encode(metadata) //nolint:errcheck,gosec,gosec
	}))
	defer upstream.Close()

	proxy, err := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: upstream.URL,
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

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express", nil)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	body, _ := io.ReadAll(resp.Body)

	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var versions map[string]json.RawMessage
	json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

	if _, ok := versions["4.19.0"]; ok {
		t.Error("young version should be filtered by proxy")
	}
	if _, ok := versions["4.18.2"]; !ok {
		t.Error("old version should pass through")
	}

	blocked := proxy.Blocked()
	if len(blocked) != 1 || blocked[0].Version != "4.19.0" {
		t.Errorf("unexpected blocked: %+v", blocked)
	}
	if proxy.Checked() != 1 {
		t.Errorf("expected 1 checked, got %d", proxy.Checked())
	}
}

func TestProxySkipPackages(t *testing.T) {
	now := time.Now()
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metadata := map[string]interface{}{
			"name": "skipped-pkg",
			"time": map[string]string{"1.0.0": youngTime},
			"versions": map[string]interface{}{
				"1.0.0": map[string]string{"name": "skipped-pkg"},
			},
		}
		json.NewEncoder(w).Encode(metadata) //nolint:errcheck,gosec,gosec
	}))
	defer upstream.Close()

	proxy, err := NewProxy(ProxyConfig{
		Policy:       Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL:  upstream.URL,
		SkipPackages: []string{"skipped-pkg"},
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/skipped-pkg", nil)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	body, _ := io.ReadAll(resp.Body)

	var result map[string]json.RawMessage
	json.Unmarshal(body, &result) //nolint:errcheck,gosec

	var versions map[string]json.RawMessage
	json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

	if _, ok := versions["1.0.0"]; !ok {
		t.Error("skipped package should NOT be filtered")
	}

	if proxy.Checked() != 0 {
		t.Errorf("skipped packages should not increment checked counter, got %d", proxy.Checked())
	}
}

func TestProxyTarballPassThrough(t *testing.T) {
	tarballContent := []byte("fake tarball content")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(tarballContent) //nolint:errcheck,gosec
	}))
	defer upstream.Close()

	proxy, _ := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: upstream.URL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	resp, err := http.Get("http://" + addr + "/express/-/express-4.18.2.tgz") //nolint:gosec
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(tarballContent) {
		t.Error("tarball should pass through unmodified")
	}

	if proxy.Checked() != 0 {
		t.Error("tarball requests should not be checked")
	}
}

func TestProxyPolicyExclusion(t *testing.T) {
	now := time.Now()
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metadata := map[string]interface{}{
			"name": "@myorg/utils",
			"time": map[string]string{"1.0.0": youngTime},
			"versions": map[string]interface{}{
				"1.0.0": map[string]string{"name": "@myorg/utils"},
			},
		}
		json.NewEncoder(w).Encode(metadata) //nolint:errcheck,gosec,gosec
	}))
	defer upstream.Close()

	proxy, _ := NewProxy(ProxyConfig{
		Policy: Policy{
			MinReleaseAge: 72 * time.Hour,
			Exclusions:    []string{"@myorg/*"},
		},
		UpstreamURL: upstream.URL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/@myorg/utils", nil)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	body, _ := io.ReadAll(resp.Body)
	var result map[string]json.RawMessage
	json.Unmarshal(body, &result) //nolint:errcheck,gosec

	var versions map[string]json.RawMessage
	json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

	if _, ok := versions["1.0.0"]; !ok {
		t.Error("excluded package should not be filtered")
	}
}

func TestExtractPackageNameFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/express", "express"},
		{"/@types/node", "@types/node"},
		{"/@scope/pkg/1.0.0", "@scope/pkg"},
		{"/lodash", "lodash"},
		{"/", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractPackageNameFromPath(tt.path)
			if got != tt.expected {
				t.Errorf("extractPackageNameFromPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtractTarballVersion(t *testing.T) {
	tests := []struct {
		path    string
		wantPkg string
		wantVer string
	}{
		{"/zod/-/zod-3.22.4.tgz", "zod", "3.22.4"},
		{"/express/-/express-4.18.2.tgz", "express", "4.18.2"},
		{"/@types/node/-/node-20.11.0.tgz", "@types/node", "20.11.0"},
		{"/@scope/pkg/-/pkg-1.0.0-beta.1.tgz", "@scope/pkg", "1.0.0-beta.1"},
		{"/zod/-/zod-4.5.0-canary.20260504T165552.tgz", "zod", "4.5.0-canary.20260504T165552"},
		{"/express", "", ""},
		{"/@types/node", "", ""},
		{"/", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			pkg, ver := extractTarballVersion(tt.path)
			if pkg != tt.wantPkg || ver != tt.wantVer {
				t.Errorf("extractTarballVersion(%q) = (%q, %q), want (%q, %q)", tt.path, pkg, ver, tt.wantPkg, tt.wantVer)
			}
		})
	}
}

func TestIsMetadataRequest(t *testing.T) {
	tests := []struct {
		path   string
		accept string
		want   bool
	}{
		{"/express", "application/json", true},
		{"/express", "", true},
		{"/express/-/express-4.18.2.tgz", "application/json", false},
		{"/-/npm/v1/security/audits", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://localhost"+tt.path, nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			got := isMetadataRequest(r)
			if got != tt.want {
				t.Errorf("isMetadataRequest(%q, accept=%q) = %v, want %v", tt.path, tt.accept, got, tt.want)
			}
		})
	}
}

func TestProxyFilterMetadata_DistTagsUpdated(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]interface{}{
		"name": "express",
		"dist-tags": map[string]string{
			"latest": "4.19.0",
			"next":   "5.0.0-alpha",
		},
		"time": map[string]string{
			"created":     oldTime,
			"modified":    youngTime,
			"4.18.2":      oldTime,
			"4.19.0":      youngTime,
			"5.0.0-alpha": youngTime,
		},
		"versions": map[string]interface{}{
			"4.18.2":      map[string]string{"name": "express", "version": "4.18.2"},
			"4.19.0":      map[string]string{"name": "express", "version": "4.19.0"},
			"5.0.0-alpha": map[string]string{"name": "express", "version": "5.0.0-alpha"},
		},
	}

	body, _ := json.Marshal(metadata)

	proxy := &Proxy{
		policy:  Policy{MinReleaseAge: 72 * time.Hour},
		allowed: make(map[string]string),
	}

	filtered, blocked := proxy.filterMetadata(body, "express")

	if len(blocked) != 2 {
		t.Fatalf("expected 2 blocked, got %d", len(blocked))
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	var distTags map[string]string
	if err := json.Unmarshal(result["dist-tags"], &distTags); err != nil {
		t.Fatalf("unmarshal dist-tags: %v", err)
	}

	if distTags["latest"] == "4.19.0" {
		t.Error("dist-tags.latest should not point to blocked version 4.19.0")
	}
	if distTags["latest"] != "4.18.2" {
		t.Errorf("dist-tags.latest should point to 4.18.2, got %s", distTags["latest"])
	}
	if distTags["next"] != "4.18.2" {
		t.Errorf("dist-tags.next should point to 4.18.2 (only allowed version), got %s", distTags["next"])
	}
}

func TestProxyFilterMetadata_AllBlocked(t *testing.T) {
	now := time.Now()
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]interface{}{
		"name": "evil-pkg",
		"dist-tags": map[string]string{
			"latest": "1.0.0",
		},
		"time": map[string]string{
			"1.0.0": youngTime,
		},
		"versions": map[string]interface{}{
			"1.0.0": map[string]string{"name": "evil-pkg"},
		},
	}

	body, _ := json.Marshal(metadata)

	proxy := &Proxy{
		policy:  Policy{MinReleaseAge: 72 * time.Hour},
		allowed: make(map[string]string),
	}

	filtered, blocked := proxy.filterMetadata(body, "evil-pkg")

	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(blocked))
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	var versions map[string]json.RawMessage
	json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec

	if len(versions) != 0 {
		t.Errorf("all versions should be blocked, got %d remaining", len(versions))
	}

	// dist-tags should remain pointing to blocked version (no safe alternative)
	var distTags map[string]string
	json.Unmarshal(result["dist-tags"], &distTags) //nolint:errcheck,gosec
	if distTags["latest"] != "1.0.0" {
		t.Errorf("dist-tags.latest should remain unchanged when all versions blocked, got %s", distTags["latest"])
	}
}

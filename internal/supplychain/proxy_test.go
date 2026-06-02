package supplychain

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: request targets the local test proxy on 127.0.0.1
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

// TestProxyForwardsQueryString verifies the filtered metadata branch preserves
// the original query string when proxying to the upstream registry, matching the
// reverse-proxy passthrough. npm clients append params like ?write=true.
func TestProxyForwardsQueryString(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	var gotRawQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		metadata := map[string]interface{}{
			"name": "express",
			"time": map[string]string{"4.18.2": oldTime},
			"versions": map[string]interface{}{
				"4.18.2": map[string]string{"name": "express"},
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
	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express?write=true&cache_bust=42", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: local test proxy on 127.0.0.1
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if gotRawQuery != "write=true&cache_bust=42" {
		t.Errorf("upstream should receive the original query string, got %q", gotRawQuery)
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

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: request targets the local test proxy on 127.0.0.1
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

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: request targets the local test proxy on 127.0.0.1
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
		// URL-encoded scoped package (npm clients commonly request this form).
		{"/@scope%2Fname", "@scope/name"},
		{"/@scope%2fname", "@scope/name"},
		{"/@types%2Fnode", "@types/node"},
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

func TestIsMetadataRequest(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/express", true},
		{"/express/-/express-4.18.2.tgz", false},
		{"/-/npm/v1/security/audits", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isMetadataRequest(tt.path)
			if got != tt.want {
				t.Errorf("isMetadataRequest(%q) = %v, want %v", tt.path, got, tt.want)
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
	// The "next" channel tag pointed at a blocked prerelease (5.0.0-alpha). It must
	// be dropped, not repointed to the stable fallback — rewriting it to 4.18.2
	// would mislead `npm install express@next` into installing a stable release.
	if ver, ok := distTags["next"]; ok {
		t.Errorf("dist-tags.next should be removed when its version is blocked, got %s", ver)
	}
}

// TestProxyFilterMetadata_UnblockedChannelTagPreserved verifies that a channel
// tag (e.g. "beta") pointing at a version that is NOT blocked is left untouched,
// while "latest" is still repointed away from a blocked version. This guards the
// dist-tag rewrite from being over-aggressive.
func TestProxyFilterMetadata_UnblockedChannelTagPreserved(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]interface{}{
		"name": "express",
		"dist-tags": map[string]string{
			"latest": "4.19.0",      // blocked → must be repointed to 4.18.2
			"beta":   "4.18.0-beta", // old prerelease, NOT blocked → must remain
		},
		"time": map[string]string{
			"4.18.0-beta": oldTime,
			"4.18.2":      oldTime,
			"4.19.0":      youngTime,
		},
		"versions": map[string]interface{}{
			"4.18.0-beta": map[string]string{"name": "express", "version": "4.18.0-beta"},
			"4.18.2":      map[string]string{"name": "express", "version": "4.18.2"},
			"4.19.0":      map[string]string{"name": "express", "version": "4.19.0"},
		},
	}

	body, _ := json.Marshal(metadata)

	proxy := &Proxy{
		policy:  Policy{MinReleaseAge: 72 * time.Hour},
		allowed: make(map[string]string),
	}

	filtered, blocked := proxy.filterMetadata(body, "express")
	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(blocked))
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	var distTags map[string]string
	if err := json.Unmarshal(result["dist-tags"], &distTags); err != nil {
		t.Fatalf("unmarshal dist-tags: %v", err)
	}

	if distTags["latest"] != "4.18.2" {
		t.Errorf("dist-tags.latest should be repointed to 4.18.2, got %q", distTags["latest"])
	}
	if distTags["beta"] != "4.18.0-beta" {
		t.Errorf("unblocked dist-tags.beta should be preserved untouched, got %q", distTags["beta"])
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

// newUnreachableProxy returns a proxy whose upstream points at a closed port so
// that age-check requests fail, exercising the registry-unreachable branch.
func newUnreachableProxy(t *testing.T, failOpen bool) *Proxy {
	t.Helper()

	// Bind then immediately close a listener to obtain a port nothing is serving.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close() //nolint:errcheck,gosec

	proxy, err := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour, FailOpen: failOpen},
		UpstreamURL: "http://" + deadAddr,
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	// Keep the failure fast so the test doesn't wait on the 30s client timeout.
	proxy.httpClient = &http.Client{Timeout: 2 * time.Second}
	return proxy
}

func TestProxyFailClosed_RegistryUnreachable(t *testing.T) {
	proxy := newUnreachableProxy(t, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: local test proxy on 127.0.0.1
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("fail-closed should return 502 when registry is unreachable, got %d", resp.StatusCode)
	}
}

func TestProxyFailOpen_RegistryUnreachable(t *testing.T) {
	proxy := newUnreachableProxy(t, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: local test proxy on 127.0.0.1
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	// With fail-open the request falls through to the reverse proxy. The dead
	// upstream still can't answer, so the reverse proxy reports 502 too — but
	// the distinguishing signal is that we did NOT short-circuit with our own
	// "registry unreachable" age-check error. Assert that fail-open took the
	// passthrough path by checking the body is not our age-check error message.
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "supply-chain: registry unreachable") {
		t.Errorf("fail-open should not emit the age-check unreachable error; got body %q", string(body))
	}
}

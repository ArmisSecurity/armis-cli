package supplychain

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// TestProxyPreservesCacheHeaders verifies the filtered 200 response carries
// upstream cache headers (Cache-Control, Vary) forward so npm/pnpm/yarn can
// populate their HTTP cache, while the now-incorrect Content-Length is dropped.
func TestProxyPreservesCacheHeaders(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	youngTime := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2025 07:28:00 GMT")
		w.Header().Set("Vary", "Accept-Encoding")
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
	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: local test proxy on 127.0.0.1
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	body, _ := io.ReadAll(resp.Body)

	// Cache-Control and Vary describe caching/negotiation independent of the
	// body, so they must survive filtering.
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control should be preserved, got %q", got)
	}
	if got := resp.Header.Get("Vary"); got != "Accept-Encoding" {
		t.Errorf("Vary should be preserved, got %q", got)
	}

	// The filtered body differs from upstream's, so the validators that describe
	// upstream's body (ETag, Last-Modified) must be dropped — otherwise the client
	// could revalidate, get a 304, and keep serving the stale-filtered snapshot
	// even after a blocked version ages past the threshold.
	if got := resp.Header.Get("ETag"); got != "" {
		t.Errorf("ETag should be dropped on a filtered response, got %q", got)
	}
	if got := resp.Header.Get("Last-Modified"); got != "" {
		t.Errorf("Last-Modified should be dropped on a filtered response, got %q", got)
	}

	// The served body length differs from upstream's; the response must reflect
	// the filtered length, never the stale upstream Content-Length.
	if cl := resp.Header.Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length %q does not match filtered body length %d", cl, len(body))
	}

	// Sanity: the young version really was filtered out (so the body did change).
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var versions map[string]json.RawMessage
	json.Unmarshal(result["versions"], &versions) //nolint:errcheck,gosec
	if _, ok := versions["4.19.0"]; ok {
		t.Error("young version should have been filtered (precondition for header assertions)")
	}
}

// TestProxyForwardsValidatorsWhenUnfiltered verifies that when no version is
// removed the body matches upstream byte-for-byte, so ETag/Last-Modified are
// accurate and forwarded — enabling conditional-request revalidation.
func TestProxyForwardsValidatorsWhenUnfiltered(t *testing.T) {
	now := time.Now()
	oldTime := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"unchanged"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2025 07:28:00 GMT")
		w.Header().Set("Cache-Control", "public, max-age=300")
		metadata := map[string]interface{}{
			"name":     "express",
			"time":     map[string]string{"4.18.2": oldTime},
			"versions": map[string]interface{}{"4.18.2": map[string]string{"name": "express"}},
		}
		json.NewEncoder(w).Encode(metadata) //nolint:errcheck,gosec,gosec
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

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/express", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: local test proxy on 127.0.0.1
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()        //nolint:errcheck,gosec
	io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec

	// Nothing was filtered (the only version is 30 days old), so validators are
	// accurate for the served body and must be forwarded.
	if got := resp.Header.Get("ETag"); got != `"unchanged"` {
		t.Errorf("ETag should be forwarded on an unfiltered response, got %q", got)
	}
	if got := resp.Header.Get("Last-Modified"); got != "Wed, 21 Oct 2025 07:28:00 GMT" {
		t.Errorf("Last-Modified should be forwarded on an unfiltered response, got %q", got)
	}

	if proxy.Checked() != 1 {
		t.Errorf("expected 1 checked, got %d", proxy.Checked())
	}
	if len(proxy.Blocked()) != 0 {
		t.Errorf("expected nothing blocked, got %+v", proxy.Blocked())
	}
}

func TestCopyCacheHeaders(t *testing.T) {
	t.Run("strips CRLF from forwarded values", func(t *testing.T) {
		upstream := http.Header{}
		// A malicious upstream tries to smuggle a second header by embedding CRLF.
		upstream.Set("Cache-Control", "public\r\nX-Injected: evil")

		dst := http.Header{}
		copyCacheHeaders(dst, upstream, false)

		got := dst.Get("Cache-Control")
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("forwarded header value must not contain CR/LF, got %q", got)
		}
		if dst.Get("X-Injected") != "" {
			t.Errorf("CRLF injection must not produce a smuggled header, got %q", dst.Get("X-Injected"))
		}
	})

	t.Run("omits validators when versions removed", func(t *testing.T) {
		upstream := http.Header{}
		upstream.Set("ETag", `"x"`)
		upstream.Set("Last-Modified", "Wed, 21 Oct 2025 07:28:00 GMT")
		upstream.Set("Cache-Control", "max-age=60")

		dst := http.Header{}
		copyCacheHeaders(dst, upstream, true)

		if dst.Get("ETag") != "" || dst.Get("Last-Modified") != "" {
			t.Errorf("validators must be omitted when body was filtered, got ETag=%q Last-Modified=%q",
				dst.Get("ETag"), dst.Get("Last-Modified"))
		}
		if dst.Get("Cache-Control") != "max-age=60" {
			t.Errorf("Cache-Control should still be forwarded, got %q", dst.Get("Cache-Control"))
		}
	})

	t.Run("drops payload-describing headers", func(t *testing.T) {
		upstream := http.Header{}
		upstream.Set("Content-Length", "9999")
		upstream.Set("Content-Encoding", "br")

		dst := http.Header{}
		copyCacheHeaders(dst, upstream, false)

		if dst.Get("Content-Length") != "" {
			t.Errorf("Content-Length must not be forwarded (body was re-marshaled), got %q", dst.Get("Content-Length"))
		}
		if dst.Get("Content-Encoding") != "" {
			t.Errorf("Content-Encoding must not be forwarded (body is plain JSON), got %q", dst.Get("Content-Encoding"))
		}
	})
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

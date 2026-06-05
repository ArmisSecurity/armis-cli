package supplychain

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestProxyPassThroughRewritesHost guards the fix for tarball downloads failing
// with 403. NewSingleHostReverseProxy does not rewrite the Host header, so
// without the Director wrapper the upstream registry receives the local proxy's
// Host (e.g. 127.0.0.1:PORT) and a CDN that routes on Host rejects it. Assert
// the passed-through request carries the upstream host, not the proxy's.
func TestProxyPassThroughRewritesHost(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok")) //nolint:errcheck,gosec
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
	defer resp.Body.Close()        //nolint:errcheck,gosec
	io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec

	upstreamURL, _ := url.Parse(upstream.URL)
	if gotHost != upstreamURL.Host {
		t.Errorf("passthrough Host = %q, want upstream host %q (proxy addr was %q)", gotHost, upstreamURL.Host, addr)
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
		// Fully percent-encoded scope, including %40 for "@". Without decoding
		// "@", "%40types" would be misread as an unscoped package.
		{"/%40types%2Fnode", "@types/node"},
		{"/%40scope%2Fname", "@scope/name"},
		{"/%40scope%2Fname%2F1.0.0", "@scope/name"},
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

// oversizeUpstream returns an httptest server whose metadata response exceeds
// maxProxyResponseSize, so handleMetadataFiltering's truncation guard fires.
func oversizeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		filler := make([]byte, maxProxyResponseSize+1)
		for i := range filler {
			filler[i] = 'a'
		}
		_, _ = w.Write(filler)
	}))
	return srv
}

func TestProxyFailClosed_ResponseTooLarge(t *testing.T) {
	upstream := oversizeUpstream(t)
	defer upstream.Close()

	proxy, err := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour, FailOpen: false},
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

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("fail-closed should return 502 when upstream response is too large, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "too large") {
		t.Errorf("expected 'too large' error body, got %q", string(body))
	}
}

func TestProxyFailOpen_ResponseTooLarge(t *testing.T) {
	upstream := oversizeUpstream(t)
	defer upstream.Close()

	proxy, err := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour, FailOpen: true},
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

	// With fail-open an oversize upstream response falls through to the reverse
	// proxy, which streams the upstream body verbatim (200), rather than our 502
	// "too large" short-circuit.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("fail-open should pass the oversize response through (200), got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "supply-chain: upstream response too large") {
		t.Errorf("fail-open should not emit the too-large error; got body %q", string(body))
	}
}

func TestProxyAddr(t *testing.T) {
	t.Run("empty before Start", func(t *testing.T) {
		p, err := NewProxy(ProxyConfig{Policy: Policy{MinReleaseAge: 72 * time.Hour}})
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		if got := p.Addr(); got != "" {
			t.Errorf("Addr() before Start = %q, want empty", got)
		}
	})

	t.Run("matches the bound address after Start", func(t *testing.T) {
		p, err := NewProxy(ProxyConfig{Policy: Policy{MinReleaseAge: 72 * time.Hour}})
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, err := p.Start(ctx)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer p.Close() //nolint:errcheck,gosec
		if p.Addr() != addr {
			t.Errorf("Addr() = %q, want %q (the address returned by Start)", p.Addr(), addr)
		}
		if !strings.HasPrefix(p.Addr(), "127.0.0.1:") {
			t.Errorf("Addr() = %q, want a 127.0.0.1 loopback address", p.Addr())
		}
	})
}

// --- PyPI Simple API (ModePyPI) tests ---

// pypiSimpleBody builds a PEP 691 Simple API JSON document for a project with
// the given files. Each file is {filename, url, hashes, upload-time}; an empty
// uploadTime omits the field entirely (to exercise the fail-closed path).
func pypiSimpleBody(name string, files []struct{ filename, uploadTime string }) string {
	var b strings.Builder
	b.WriteString(`{"meta":{"api-version":"1.1"},"name":"` + name + `","files":[`)
	for i, f := range files {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"filename":"` + f.filename + `","url":"https://files.pythonhosted.org/packages/` + f.filename + `","hashes":{"sha256":"deadbeef"}`)
		if f.uploadTime != "" {
			b.WriteString(`,"upload-time":"` + f.uploadTime + `"`)
		}
		b.WriteString("}")
	}
	b.WriteString(`]}`)
	return b.String()
}

func pypiFilenames(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal pypi body: %v\n%s", err, body)
	}
	names := make([]string, len(doc.Files))
	for i, f := range doc.Files {
		names[i] = f.Filename
	}
	return names
}

func TestProxyFilterPyPISimple(t *testing.T) {
	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	young := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	p := &Proxy{policy: Policy{MinReleaseAge: 72 * time.Hour}, mode: ModePyPI}

	t.Run("removes young files keeps old", func(t *testing.T) {
		body := pypiSimpleBody("requests", []struct{ filename, uploadTime string }{
			{"requests-2.31.0-py3-none-any.whl", old},
			{"requests-2.32.0-py3-none-any.whl", young},
		})
		filtered, blocked := p.filterPyPISimple([]byte(body), "requests")
		names := pypiFilenames(t, filtered)
		if len(names) != 1 || names[0] != "requests-2.31.0-py3-none-any.whl" {
			t.Errorf("kept files = %v, want only the old wheel", names)
		}
		if len(blocked) != 1 || blocked[0].Version != "requests-2.32.0-py3-none-any.whl" {
			t.Errorf("blocked = %+v, want the young wheel", blocked)
		}
	})

	t.Run("all old passes through unchanged", func(t *testing.T) {
		body := pypiSimpleBody("flask", []struct{ filename, uploadTime string }{
			{"flask-3.0.0-py3-none-any.whl", old},
			{"flask-3.0.0.tar.gz", old},
		})
		filtered, blocked := p.filterPyPISimple([]byte(body), "flask")
		if blocked != nil {
			t.Errorf("expected no blocked files, got %+v", blocked)
		}
		if string(filtered) != body {
			t.Errorf("body should be returned unchanged when nothing is filtered")
		}
	})

	t.Run("fail-closed on missing upload-time", func(t *testing.T) {
		// A file with no upload-time cannot be age-verified, so it must be
		// removed — the whole point of the control is age verification.
		body := pypiSimpleBody("mystery", []struct{ filename, uploadTime string }{
			{"mystery-1.0.0-py3-none-any.whl", ""},
			{"mystery-0.9.0-py3-none-any.whl", old},
		})
		filtered, blocked := p.filterPyPISimple([]byte(body), "mystery")
		names := pypiFilenames(t, filtered)
		if len(names) != 1 || names[0] != "mystery-0.9.0-py3-none-any.whl" {
			t.Errorf("kept files = %v, want only the datable old wheel", names)
		}
		if len(blocked) != 1 || blocked[0].Version != "mystery-1.0.0-py3-none-any.whl" {
			t.Errorf("blocked = %+v, want the undatable wheel", blocked)
		}
	})

	t.Run("preserves untouched file fields", func(t *testing.T) {
		body := pypiSimpleBody("requests", []struct{ filename, uploadTime string }{
			{"requests-2.31.0-py3-none-any.whl", old},
			{"requests-2.32.0-py3-none-any.whl", young},
		})
		filtered, _ := p.filterPyPISimple([]byte(body), "requests")
		// The surviving file must retain its url and hashes verbatim.
		if !strings.Contains(string(filtered), `"url":"https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl"`) {
			t.Errorf("surviving file lost its url field: %s", filtered)
		}
		if !strings.Contains(string(filtered), `"sha256":"deadbeef"`) {
			t.Errorf("surviving file lost its hashes: %s", filtered)
		}
		// meta and name must round-trip.
		if !strings.Contains(string(filtered), `"api-version":"1.1"`) {
			t.Errorf("meta field dropped: %s", filtered)
		}
	})

	t.Run("invalid JSON returned as-is", func(t *testing.T) {
		body := []byte(`not json`)
		filtered, blocked := p.filterPyPISimple(body, "x")
		if blocked != nil || string(filtered) != string(body) {
			t.Errorf("invalid JSON should pass through untouched")
		}
	})

	t.Run("no files key returned as-is", func(t *testing.T) {
		body := []byte(`{"meta":{"api-version":"1.1"},"name":"x"}`)
		filtered, blocked := p.filterPyPISimple(body, "x")
		if blocked != nil || string(filtered) != string(body) {
			t.Errorf("body without files should pass through untouched")
		}
	})

	t.Run("no-timezone upload-time accepted", func(t *testing.T) {
		// PEP 700 says RFC 3339, but some mirrors omit the zone; the parser
		// accepts the no-zone fallback rather than treating it as undatable.
		oldNoZone := now.Add(-30 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
		body := pypiSimpleBody("pkg", []struct{ filename, uploadTime string }{
			{"pkg-1.0.0.tar.gz", oldNoZone},
		})
		_, blocked := p.filterPyPISimple([]byte(body), "pkg")
		if blocked != nil {
			t.Errorf("no-timezone old file should pass, got blocked %+v", blocked)
		}
	})
}

func TestProxyFilterPyPISimple_AllowedPopulated(t *testing.T) {
	// Proxy.Allowed() must be populated with the newest stable safe version so
	// the wrap summary can report "→ 2.31.0 installed" rather than "no older
	// safe version" for pip/uv installs.
	now := time.Now()
	old1 := now.Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339) // 2.30.0
	old2 := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339) // 2.31.0 — newer of the two safe versions
	young := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)      // 2.32.0 — blocked

	p, err := NewProxy(ProxyConfig{Policy: Policy{MinReleaseAge: 72 * time.Hour}, Mode: ModePyPI})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	body := pypiSimpleBody("requests", []struct{ filename, uploadTime string }{
		{"requests-2.30.0-py3-none-any.whl", old1},
		{"requests-2.31.0-py3-none-any.whl", old2},
		{"requests-2.32.0-py3-none-any.whl", young},
	})
	_, blocked := p.filterPyPISimple([]byte(body), "requests")
	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked file, got %d: %+v", len(blocked), blocked)
	}

	allowed := p.Allowed()
	if len(allowed) != 1 || allowed[0].Name != "requests" || allowed[0].Version != "2.31.0" {
		t.Errorf("Allowed() = %+v, want [{requests 2.31.0}]", allowed)
	}
}

func TestPypiVersionFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"requests-2.31.0-py3-none-any.whl", "2.31.0"},
		{"requests-2.31.0.tar.gz", "2.31.0"},
		{"Flask-3.0.0-py3-none-any.whl", "3.0.0"},
		{"numpy-1.26.2-cp312-cp312-manylinux_2_17_x86_64.whl", "1.26.2"},
		{"setuptools-68.0.0.tar.gz", "68.0.0"},
		{"pkg-1.0.0a1-py3-none-any.whl", "1.0.0a1"},
		// sdists whose project name contains '-': the version is everything after
		// the FINAL '-', not the first (which would mis-return "interface"/"yaml").
		{"zope-interface-6.0.tar.gz", "6.0"},
		{"backports-zoneinfo-0.2.1.tar.gz", "0.2.1"},
		{"ruamel-yaml-clib-0.2.8.zip", "0.2.8"},
		// Hyphenated-name sdist with a build-tagged version (PEP 440 allows '+').
		{"my-pkg-1.2.3+local.tar.gz", "1.2.3+local"},
		// Wheels normalize the distribution name (PEP 427 collapses '-' to '_'),
		// so the version stays the second field even for multi-word projects.
		{"zope_interface-6.0-cp312-cp312-manylinux1_x86_64.whl", "6.0"},
		{"noversion.whl", ""},
		{"trailingdash-.tar.gz", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			if got := pypiVersionFromFilename(tt.filename); got != tt.want {
				t.Errorf("pypiVersionFromFilename(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestExtractPyPIPackageNameFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/simple/requests/", "requests"},
		{"/simple/requests", "requests"},
		{"/simple/Flask/", "Flask"},
		{"/simple/", ""},      // index root
		{"/simple", ""},       // index root, no trailing slash
		{"/", ""},             // not under /simple/
		{"/other/pkg/", ""},   // wrong prefix
		{"/simple/a/b/", ""},  // nested, not a project page
		{"/simple/%41/", "A"}, // percent-decoded
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := extractPyPIPackageNameFromPath(tt.path); got != tt.want {
				t.Errorf("extractPyPIPackageNameFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestProxyPyPIEndToEnd drives a full pip-style request through the proxy in
// PyPI mode against a mock Simple API upstream, asserting young files are
// filtered, the JSON Accept header is sent upstream, and the response carries
// the PEP 691 content type.
func TestProxyPyPIEndToEnd(t *testing.T) {
	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	young := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	var gotAccept, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", pypiSimpleJSONAccept)
		body := pypiSimpleBody("requests", []struct{ filename, uploadTime string }{
			{"requests-2.31.0-py3-none-any.whl", old},
			{"requests-2.32.0-py3-none-any.whl", young},
		})
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	proxy, err := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		Mode:        ModePyPI,
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

	resp, err := http.Get("http://" + addr + "/simple/requests/") //nolint:gosec // local test proxy
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	body, _ := io.ReadAll(resp.Body)

	if gotAccept != pypiSimpleJSONAccept {
		t.Errorf("upstream Accept = %q, want %q", gotAccept, pypiSimpleJSONAccept)
	}
	if gotPath != "/simple/requests/" {
		t.Errorf("upstream path = %q, want /simple/requests/", gotPath)
	}
	if ct := resp.Header.Get("Content-Type"); ct != pypiSimpleJSONAccept {
		t.Errorf("response Content-Type = %q, want %q", ct, pypiSimpleJSONAccept)
	}
	names := pypiFilenames(t, body)
	if len(names) != 1 || names[0] != "requests-2.31.0-py3-none-any.whl" {
		t.Errorf("served files = %v, want only the old wheel", names)
	}
	if blocked := proxy.Blocked(); len(blocked) != 1 {
		t.Errorf("expected 1 blocked file, got %+v", blocked)
	}
	if proxy.Checked() != 1 {
		t.Errorf("expected 1 checked, got %d", proxy.Checked())
	}
}

// TestProxyPyPIIndexRootPassesThrough ensures the /simple/ index root is not
// treated as a project page (it has no per-package files to filter) and is
// proxied through untouched.
func TestProxyPyPIIndexRootPassesThrough(t *testing.T) {
	var servedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servedPath = r.URL.Path
		_, _ = io.WriteString(w, `{"meta":{"api-version":"1.1"},"projects":[]}`)
	}))
	defer upstream.Close()

	proxy, _ := NewProxy(ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		Mode:        ModePyPI,
		UpstreamURL: upstream.URL,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := proxy.Start(ctx)
	defer proxy.Close() //nolint:errcheck,gosec

	resp, err := http.Get("http://" + addr + "/simple/") //nolint:gosec // local test proxy
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()        //nolint:errcheck,gosec
	io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec

	if servedPath != "/simple/" {
		t.Errorf("upstream path = %q, want /simple/", servedPath)
	}
	if proxy.Checked() != 0 {
		t.Errorf("index root should not count as a checked package, got %d", proxy.Checked())
	}
}

func TestNewProxyDefaultsPyPIUpstream(t *testing.T) {
	p, err := NewProxy(ProxyConfig{Policy: Policy{MinReleaseAge: 72 * time.Hour}, Mode: ModePyPI})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	if p.upstreamURL.String() != defaultPyPIIndex {
		t.Errorf("PyPI-mode upstream = %q, want %q", p.upstreamURL.String(), defaultPyPIIndex)
	}
}

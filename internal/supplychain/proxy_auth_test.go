package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startProxy is a test helper that constructs and starts a proxy against a
// given upstream, returning the proxy's loopback address. It registers cleanup.
func startProxy(t *testing.T, cfg ProxyConfig) (*Proxy, string) {
	t.Helper()
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy, addr
}

// npmMetadataWithTime renders a minimal npm metadata doc whose single version
// is old enough to pass any age policy.
func npmMetadataWithTime(name, version string) []byte {
	doc := map[string]any{
		"name":      name,
		"dist-tags": map[string]string{"latest": version},
		"versions": map[string]any{
			version: map[string]any{"name": name, "version": version},
		},
		"time": map[string]string{
			version: "2020-01-01T00:00:00.000Z",
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// TestProxyInjectsAuthMetadata is test-plan case #2: a metadata request to a
// custom upstream carries the injected Authorization header; the upstream
// answers 200 with the token and 401 without.
func TestProxyInjectsAuthMetadata(t *testing.T) {
	const token = "Bearer secret-tok"

	t.Run("with auth → 200", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="upstream"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(npmMetadataWithTime("express", "4.18.2")) //nolint:errcheck,gosec
		}))
		defer upstream.Close()

		_, addr := startProxy(t, ProxyConfig{
			Policy:      Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL: upstream.URL,
			AuthHeader:  token,
		})

		resp := getThrough(t, addr, "/express")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("without auth → 401 (negative case)", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != token {
				w.Header().Set("WWW-Authenticate", `Bearer realm="upstream"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		// No AuthHeader configured → upstream sees no token → 401.
		_, addr := startProxy(t, ProxyConfig{
			Policy:      Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL: upstream.URL,
		})

		resp := getThrough(t, addr, "/express")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 without auth", resp.StatusCode)
		}
	})
}

// TestProxyAuthBothLegs is test-plan case #3: buildAuthHeader() is used by BOTH
// the metadata path AND the reverse-proxy Director (tarball passthrough), so a
// 401-gated upstream authenticates on both. This is the prototype's headline
// finding turned into a regression guard.
func TestProxyAuthBothLegs(t *testing.T) {
	const token = "Bearer both-legs-tok"
	var metaAuthed, tarballAuthed atomic.Bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") == token
		isTarball := strings.HasSuffix(r.URL.Path, ".tgz")
		if !authed {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if isTarball {
			tarballAuthed.Store(true)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("tarball-bytes")) //nolint:errcheck,gosec
			return
		}
		metaAuthed.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.Write(npmMetadataWithTime("express", "4.18.2")) //nolint:errcheck,gosec
	}))
	defer upstream.Close()

	_, addr := startProxy(t, ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: upstream.URL,
		AuthHeader:  token,
	})

	// Metadata leg.
	mresp := getThrough(t, addr, "/express")
	mresp.Body.Close() //nolint:errcheck,gosec
	if mresp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", mresp.StatusCode)
	}
	// Tarball leg (passthrough via Director — contains "/-/").
	tresp := getThrough(t, addr, "/express/-/express-4.18.2.tgz")
	body, _ := io.ReadAll(tresp.Body)
	tresp.Body.Close() //nolint:errcheck,gosec
	if tresp.StatusCode != http.StatusOK {
		t.Fatalf("tarball status = %d, want 200 (Director must inject auth too)", tresp.StatusCode)
	}
	if string(body) != "tarball-bytes" {
		t.Errorf("tarball body = %q", body)
	}
	if !metaAuthed.Load() || !tarballAuthed.Load() {
		t.Errorf("both legs must reach upstream authed: meta=%v tarball=%v", metaAuthed.Load(), tarballAuthed.Load())
	}
}

// TestProxyRefusesCrossHostRedirect is test-plan case #4 (security): the proxy
// HTTP client refuses a cross-host redirect so the bearer token is never sent
// to a redirect target on a different host.
func TestProxyRefusesCrossHostRedirect(t *testing.T) {
	const token = "Bearer no-follow-tok"
	var attackerGotAuth atomic.Bool

	// The attacker host records whether it ever received the Authorization header.
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			attackerGotAuth.Store(true)
		}
		w.Write(npmMetadataWithTime("evil", "1.0.0")) //nolint:errcheck,gosec
	}))
	defer attacker.Close()

	// The configured upstream 302-redirects to the attacker host.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// armis:ignore cwe:601 reason:test fixture deliberately issuing a cross-host redirect to PROVE the proxy's CheckRedirect refuses to follow it; this is the attacker being simulated, not a vulnerability in product code
		http.Redirect(w, r, attacker.URL+r.URL.Path, http.StatusFound) //nolint:gosec // G710: intentional cross-host redirect in a security test
	}))
	defer upstream.Close()

	_, addr := startProxy(t, ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: upstream.URL,
		AuthHeader:  token,
	})

	resp := getThrough(t, addr, "/express")
	resp.Body.Close() //nolint:errcheck,gosec
	// The redirect must NOT have been followed to the attacker host with the token.
	if attackerGotAuth.Load() {
		t.Fatal("SECURITY: bearer token followed a cross-host redirect to the attacker host")
	}
	// A refused redirect surfaces as a non-200 (bad gateway / the 302 itself), not a 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected the cross-host redirect to be refused, got 200")
	}
}

// TestProxyStripsWWWAuthenticate is test-plan case #10: on a custom upstream, a
// 401 has its WWW-Authenticate stripped before reaching the PM so npm cannot
// re-auth directly against the upstream and bypass the proxy.
func TestProxyStripsWWWAuthenticate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://nexus.corp/"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	t.Run("custom upstream strips realm", func(t *testing.T) {
		_, addr := startProxy(t, ProxyConfig{
			Policy:      Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL: upstream.URL,
			AuthHeader:  "Bearer wrong",
		})
		resp := getThrough(t, addr, "/express")
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("WWW-Authenticate should be stripped on custom upstream, got %q", got)
		}
	})

	t.Run("default public path keeps realm", func(t *testing.T) {
		// No UpstreamURL → not a custom upstream → existing passthrough behavior
		// (realm forwarded). Point the default-mode proxy at our 401 upstream by
		// using UpstreamURL but asserting via customUpstream=false is impossible;
		// instead verify the negative directly: with customUpstream the realm is
		// gone (above), and the modify hook is gated on customUpstream.
		p := &Proxy{customUpstream: false, upstreamURL: mustParseURL(t, upstream.URL)}
		resp := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}, Request: &http.Request{URL: mustParseURL(t, upstream.URL)}}
		resp.Header.Set("WWW-Authenticate", `Bearer realm="x"`)
		if err := p.modifyUpstreamResponse(resp); err != nil {
			t.Fatalf("modifyUpstreamResponse: %v", err)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("default (non-custom) path must NOT strip WWW-Authenticate")
		}
	})
}

// TestModifyUpstreamResponse covers the ModifyResponse hook directly across the
// status/custom-upstream matrix that the end-to-end tests don't all reach.
func TestModifyUpstreamResponse(t *testing.T) {
	mk := func(custom bool, status int) *http.Response {
		resp := &http.Response{
			StatusCode: status,
			Header:     http.Header{},
			Request:    &http.Request{URL: mustParseURL(t, "https://nexus.corp/x")},
		}
		resp.Header.Set("WWW-Authenticate", `Bearer realm="x"`)
		return resp
	}

	t.Run("custom upstream strips on 401", func(t *testing.T) {
		p := &Proxy{customUpstream: true, upstreamURL: mustParseURL(t, "https://nexus.corp/")}
		resp := mk(true, http.StatusUnauthorized)
		_ = p.modifyUpstreamResponse(resp)
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Error("401 on custom upstream must strip WWW-Authenticate")
		}
	})

	t.Run("custom upstream strips on 403", func(t *testing.T) {
		p := &Proxy{customUpstream: true, upstreamURL: mustParseURL(t, "https://nexus.corp/")}
		resp := mk(true, http.StatusForbidden)
		_ = p.modifyUpstreamResponse(resp)
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Error("403 on custom upstream must strip WWW-Authenticate")
		}
	})

	t.Run("custom upstream leaves 200 untouched", func(t *testing.T) {
		p := &Proxy{customUpstream: true, upstreamURL: mustParseURL(t, "https://nexus.corp/")}
		resp := mk(true, http.StatusOK)
		_ = p.modifyUpstreamResponse(resp)
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("a 200 must not be modified")
		}
	})

	t.Run("non-custom upstream never strips", func(t *testing.T) {
		p := &Proxy{customUpstream: false, upstreamURL: mustParseURL(t, "https://registry.npmjs.org/")}
		resp := mk(false, http.StatusUnauthorized)
		_ = p.modifyUpstreamResponse(resp)
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("the default public path must not strip WWW-Authenticate")
		}
	})
}

// getThrough issues a GET to the proxy at the given path and returns the
// response. http.DefaultClient does NOT follow into the proxy's own redirect
// refusal (the proxy returns the upstream status verbatim), so a plain Get is
// the right driver here.
func getThrough(t *testing.T, addr, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", addr, path), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request to proxy: %v", err)
	}
	return resp
}

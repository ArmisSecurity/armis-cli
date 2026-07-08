package supplychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestJoinUpstreamURL verifies the boundary-slash collapse used by the metadata
// leg so a trailing slash on the configured upstream never produces a "//" path
// (the PPSC-994 double-slash bug: `registries.npm: https://host/` made every
// install 404 with GET //<pkg>).
func TestJoinUpstreamURL(t *testing.T) {
	cases := []struct {
		name       string
		base       string
		requestURI string
		want       string
	}{
		{"trailing slash + leading slash", "https://nexus.corp/", "/lodash", "https://nexus.corp/lodash"},
		{"no trailing slash + leading slash", "https://nexus.corp", "/lodash", "https://nexus.corp/lodash"},
		{"trailing slash + no leading slash", "https://nexus.corp/", "lodash", "https://nexus.corp/lodash"},
		{"no slash on either side", "https://nexus.corp", "lodash", "https://nexus.corp/lodash"},
		{"base path with trailing slash", "https://nexus.corp/repository/npm/", "/lodash", "https://nexus.corp/repository/npm/lodash"},
		{"base path no trailing slash", "https://nexus.corp/repository/npm", "/lodash", "https://nexus.corp/repository/npm/lodash"},
		{"query preserved", "https://nexus.corp/", "/lodash?write=true", "https://nexus.corp/lodash?write=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinUpstreamURL(tc.base, tc.requestURI); got != tc.want {
				t.Errorf("joinUpstreamURL(%q, %q) = %q, want %q", tc.base, tc.requestURI, got, tc.want)
			}
		})
	}
}

// TestProxyMetadataTrailingSlashUpstream is the end-to-end regression guard for
// the double-slash bug: with an upstream configured WITH a trailing slash (the
// exact shape of the committed example config), a metadata request must reach
// the upstream at "/express", not "//express", and resolve 200.
func TestProxyMetadataTrailingSlashUpstream(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write(npmMetadataWithTime("express", "4.18.2")) //nolint:errcheck,gosec
	}))
	defer upstream.Close()

	// httptest URLs have no trailing slash; append one to reproduce the config
	// shape that triggered the bug.
	_, addr := startProxy(t, ProxyConfig{
		Policy:      Policy{MinReleaseAge: 72 * time.Hour},
		UpstreamURL: upstream.URL + "/",
	})

	resp := getThrough(t, addr, "/express")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (trailing-slash upstream should resolve)", resp.StatusCode)
	}
	if gotPath != "/express" {
		t.Errorf("upstream saw path %q, want %q (double-slash regression)", gotPath, "/express")
	}
}

// TestProxyVerifyFailedCounter is the bug #2b regression guard: when the
// age-check request fails on the fail-closed path (unreachable/untrusted
// upstream), the package is counted in Checked() but ALSO in VerifyFailed(), so
// the wrap summary can distinguish "checked and passed" from "check could not
// run". Without this the summary printed a green "N packages checked, all pass"
// while every check had in fact errored out (e.g. a wrong registry-ca-bundle).
func TestProxyVerifyFailedCounter(t *testing.T) {
	t.Run("fail-closed increments VerifyFailed", func(t *testing.T) {
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
		resp.Body.Close() //nolint:errcheck,gosec

		if got := proxy.Checked(); got != 1 {
			t.Errorf("Checked() = %d, want 1 (the age check was attempted)", got)
		}
		if got := proxy.VerifyFailed(); got != 1 {
			t.Errorf("VerifyFailed() = %d, want 1 (the check could not be verified)", got)
		}
	})

	t.Run("fail-open does NOT increment VerifyFailed", func(t *testing.T) {
		// Under fail-open the package is deliberately passed through with an explicit
		// "allowing (fail-open)" notice, which is a separate, surfaced posture — not
		// a silently-missed check — so it must not count as a verify failure.
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
		resp.Body.Close() //nolint:errcheck,gosec

		if got := proxy.VerifyFailed(); got != 0 {
			t.Errorf("VerifyFailed() = %d, want 0 under fail-open", got)
		}
	})
}

// TestNewRegistryHTTPClient covers the bug #2a helper that gives `supply-chain
// check` the same private-CA trust the wrap proxy uses.
func TestNewRegistryHTTPClient(t *testing.T) {
	t.Run("no url and no bundle → nil client (use default)", func(t *testing.T) {
		c, err := NewRegistryHTTPClient("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c != nil {
			t.Errorf("expected nil client when no custom trust is needed, got %+v", c)
		}
	})

	t.Run("valid url, no bundle → non-nil client", func(t *testing.T) {
		c, err := NewRegistryHTTPClient("https://nexus.corp/", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c == nil {
			t.Error("expected a non-nil client (cross-host redirect guard applies even without a bundle)")
		}
	})

	t.Run("bad bundle path → hard error, not silent fallback", func(t *testing.T) {
		_, err := NewRegistryHTTPClient("https://nexus.corp/", "/no/such/ca-bundle.pem")
		if err == nil {
			t.Fatal("expected a hard error for an unreadable CA bundle (must never fail open)")
		}
	})
}

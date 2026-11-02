package supplychain

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyUnparseableIndex(t *testing.T) {
	const marker = "UPSTREAM-BODY-MARKER"

	type upstreamBody struct {
		name        string
		mode        ProxyMode
		path        string
		contentType string
		body        string
	}
	bodies := []upstreamBody{
		{"pypi html", ModePyPI, "/simple/requests/", "text/html", "<!DOCTYPE html><html><body>" + marker + "</body></html>"},
		{"pypi malformed json", ModePyPI, "/simple/requests/", pypiSimpleJSONAccept, `{"files": [` + marker},
		{"pypi no files key", ModePyPI, "/simple/requests/", pypiSimpleJSONAccept, `{"name":"requests","marker":"` + marker + `"}`},
		{"pypi files is object", ModePyPI, "/simple/requests/", pypiSimpleJSONAccept, `{"files":{"marker":"` + marker + `"}}`},
		{"npm malformed json", ModeNPM, "/express", "application/json", "not json " + marker},
	}

	type config struct {
		name     string
		degrade  bool
		failOpen bool
	}
	configs := []config{
		{"default", false, false},
		{"degrade does not apply", true, false},
		{"fail-open", false, true},
	}

	for _, ub := range bodies {
		for _, cfg := range configs {
			t.Run(ub.name+"/"+cfg.name, func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", ub.contentType)
					_, _ = io.WriteString(w, ub.body)
				}))
				defer upstream.Close()

				proxy, err := NewProxy(ProxyConfig{
					Policy:                     Policy{MinReleaseAge: 72 * time.Hour, FailOpen: cfg.failOpen},
					Mode:                       ub.mode,
					UpstreamURL:                upstream.URL,
					DegradeOnMissingTimestamps: cfg.degrade,
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

				resp, err := http.Get("http://" + addr + ub.path) //nolint:gosec // local test proxy
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				defer resp.Body.Close() //nolint:errcheck,gosec
				got, _ := io.ReadAll(resp.Body)

				if cfg.failOpen {
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status = %d, want 200", resp.StatusCode)
					}
					if string(got) != ub.body {
						t.Errorf("fail-open body = %q, want upstream body", got)
					}
					if ct := resp.Header.Get("Content-Type"); ct != ub.contentType {
						t.Errorf("Content-Type = %q, want upstream %q", ct, ub.contentType)
					}
					return
				}

				if resp.StatusCode != http.StatusBadGateway {
					t.Fatalf("status = %d, want 502", resp.StatusCode)
				}
				if strings.Contains(string(got), marker) {
					t.Errorf("response leaks upstream content: %q", got)
				}
				if n := proxy.VerifyFailed(); n != 1 {
					t.Errorf("VerifyFailed = %d, want 1", n)
				}
				if b := proxy.Blocked(); len(b) != 0 {
					t.Errorf("Blocked = %+v, want empty", b)
				}
			})
		}
	}
}

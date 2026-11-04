package netcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func serverTransport(srv *httptest.Server) *http.Transport {
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	return tr
}

// stallingProxy accepts a CONNECT, answers 200 and then forwards nothing, so
// the TLS handshake through it never finishes.
func stallingProxy(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}()
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}
}

func TestRunDirectSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var out bytes.Buffer
	ok := Run(context.Background(), Options{
		BaseURL:   srv.URL,
		Out:       &out,
		proxyFor:  func(*url.URL) (*url.URL, string, error) { return nil, "test", nil },
		transport: func(bool) *http.Transport { return serverTransport(srv) },
	})
	if !ok {
		t.Fatalf("expected success, report:\n%s", out.String())
	}
	report := out.String()
	for _, want := range []string{"direct connection (no proxy)", "TLS handshake finished", "OK: HTTP 401", "The API is reachable", "issued by"} {
		if !strings.Contains(report, want) {
			t.Errorf("report should contain %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "[2/2]") {
		t.Error("no direct comparison is needed when no proxy is used")
	}
}

func TestRunProxyStallsButDirectWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	proxy := stallingProxy(t)

	var out bytes.Buffer
	ok := Run(context.Background(), Options{
		BaseURL:  srv.URL,
		Out:      &out,
		proxyFor: func(*url.URL) (*url.URL, string, error) { return proxy, "the test", nil },
		transport: func(direct bool) *http.Transport {
			tr := serverTransport(srv)
			if !direct {
				tr.Proxy = http.ProxyURL(proxy)
				tr.TLSHandshakeTimeout = 300 * time.Millisecond
			}
			return tr
		},
	})
	if ok {
		t.Fatalf("the proxied path must be reported as failed:\n%s", out.String())
	}
	report := out.String()
	for _, want := range []string{
		"TLS handshake started",
		"TLS handshake timeout",
		"[2/2] Direct connection",
		"The direct connection works and the proxy path does not",
		"ARMIS_NO_SYSTEM_PROXY",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report should contain %q:\n%s", want, report)
		}
	}
}

func TestRunBothFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var out bytes.Buffer
	ok := Run(context.Background(), Options{
		BaseURL:   "https://" + addr,
		Out:       &out,
		proxyFor:  func(*url.URL) (*url.URL, string, error) { return nil, "test", nil },
		transport: func(bool) *http.Transport { return &http.Transport{} },
	})
	if ok {
		t.Fatal("expected failure for a closed port")
	}
	if !strings.Contains(out.String(), "The API is not reachable") {
		t.Errorf("unexpected report:\n%s", out.String())
	}
}

func TestRunRejectsBadURL(t *testing.T) {
	var out bytes.Buffer
	if Run(context.Background(), Options{BaseURL: "::", Out: &out}) {
		t.Fatal("expected failure")
	}
	if !strings.Contains(out.String(), "not a valid URL") {
		t.Errorf("unexpected output %q", out.String())
	}
}

func TestEnvValueHidesCredentials(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:secret@proxy.corp:8080")
	got := envValue("HTTPS_PROXY")
	if strings.Contains(got, "secret") {
		t.Errorf("credentials leaked: %q", got)
	}
}

func TestRunDeadProxyBlamesTheProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	_ = ln.Close()

	var out bytes.Buffer
	ok := Run(context.Background(), Options{
		BaseURL:  srv.URL,
		Out:      &out,
		proxyFor: func(*url.URL) (*url.URL, string, error) { return dead, "the test", nil },
		transport: func(direct bool) *http.Transport {
			tr := serverTransport(srv)
			if !direct {
				tr.Proxy = http.ProxyURL(dead)
			}
			return tr
		},
	})
	if ok {
		t.Fatal("expected the dead proxy to fail")
	}
	report := out.String()
	if !strings.Contains(report, "could not connect to the proxy itself") || strings.Contains(report, "TLS inspection") {
		t.Errorf("unexpected verdict:\n%s", report)
	}
}

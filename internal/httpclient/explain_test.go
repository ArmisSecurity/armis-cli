package httpclient

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTLSHandshakeTimeout(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset uses the default", "", 10 * time.Second},
		{"go duration", "30s", 30 * time.Second},
		{"plain seconds", "45", 45 * time.Second},
		{"garbage falls back", "soon", 10 * time.Second},
		{"zero falls back", "0", 10 * time.Second},
		{"negative falls back", "-5s", 10 * time.Second},
		{"over the cap falls back", "10m", 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvTLSHandshakeTimeout, tt.env)
			if got := TLSHandshakeTimeout(); got != tt.want {
				t.Errorf("TLSHandshakeTimeout() = %v, want %v", got, tt.want)
			}
			if got := ProxyAwareTransport().TLSHandshakeTimeout; got != tt.want {
				t.Errorf("transport TLSHandshakeTimeout = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoSystemProxyUsesEnvironmentOnly(t *testing.T) {
	want := &url.URL{Scheme: "http", Host: "proxy.example.com:8080"}
	old := envProxy
	envProxy = func(*http.Request) (*url.URL, error) { return want, nil }
	t.Cleanup(func() { envProxy = old })
	t.Setenv(EnvNoSystemProxy, "1")

	target, _ := url.Parse("https://api.example.com/")
	got, source, err := ProxyFor(target)
	if err != nil {
		t.Fatalf("ProxyFor: %v", err)
	}
	if got != want {
		t.Errorf("ProxyFor = %v, want %v", got, want)
	}
	if !strings.Contains(source, EnvNoSystemProxy) {
		t.Errorf("source %q should mention %s", source, EnvNoSystemProxy)
	}

	tr := ProxyAwareTransport()
	req := &http.Request{URL: target}
	if u, _ := tr.Proxy(req); u != want {
		t.Errorf("transport proxy = %v, want %v", u, want)
	}
	if desc := ProxyUsedFor(target.Host); desc != "http://proxy.example.com:8080" {
		t.Errorf("ProxyUsedFor = %q", desc)
	}
}

func TestDescribeProxy(t *testing.T) {
	tests := []struct {
		name string
		in   *url.URL
		want string
	}{
		{"nil is direct", nil, "direct connection (no proxy)"},
		{"bare host from a PAC result", &url.URL{Host: "10.0.0.1:8080"}, "http://10.0.0.1:8080"},
		{"credentials are hidden", &url.URL{Scheme: "http", User: url.UserPassword("u", "secret"), Host: "p:80"}, "http://u:xxxxx@p:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DescribeProxy(tt.in); got != tt.want {
				t.Errorf("DescribeProxy = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExplainTransportError(t *testing.T) {
	target, _ := url.Parse("https://api.example.com/path")
	handshake := errors.New(`Post "https://api.example.com/path": net/http: TLS handshake timeout`)
	proxyConnect := errors.New(`Post "https://api.example.com/path": proxyconnect tcp: dial tcp 10.0.0.1:8080: connectex: refused`)

	t.Run("unrelated errors are untouched", func(t *testing.T) {
		other := errors.New("boom")
		if got := ExplainTransportError(other, target); got != other {
			t.Errorf("got %v, want the original error", got)
		}
		if got := ExplainTransportError(nil, target); got != nil {
			t.Errorf("nil error became %v", got)
		}
	})

	t.Run("handshake timeout through a proxy names the proxy", func(t *testing.T) {
		proxyChoices.Store(target.Host, proxyChoice{url: &url.URL{Scheme: "http", User: url.UserPassword("u", "secret"), Host: "proxy.corp:8080"}})
		got := ExplainTransportError(handshake, target)
		msg := got.Error()
		for _, want := range []string{"proxy.corp:8080", EnvNoSystemProxy, "mcp doctor --network", "TLS inspection", "NO_PROXY=api.example.com"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message %q should contain %q", msg, want)
			}
		}
		if strings.Contains(msg, "secret") {
			t.Errorf("proxy password leaked into %q", msg)
		}
		if !errors.Is(got, handshake) {
			t.Error("the original error must stay in the chain")
		}
	})

	t.Run("proxy connect failure says the proxy was unreachable", func(t *testing.T) {
		proxyChoices.Store(target.Host, proxyChoice{url: &url.URL{Scheme: "http", Host: "10.0.0.1:8080"}})
		msg := ExplainTransportError(proxyConnect, target).Error()
		if !strings.Contains(msg, "could not connect to that proxy") || !strings.Contains(msg, "only the first one is used") {
			t.Errorf("unexpected message %q", msg)
		}
	})

	t.Run("handshake timeout without a proxy says direct", func(t *testing.T) {
		proxyChoices.Store(target.Host, proxyChoice{url: nil})
		msg := ExplainTransportError(handshake, target).Error()
		if !strings.Contains(msg, "directly") || strings.Contains(msg, EnvNoSystemProxy) {
			t.Errorf("unexpected message %q", msg)
		}
	})

	t.Run("untrusted certificate says how to trust the issuing authority", func(t *testing.T) {
		proxyChoices.Store(target.Host, proxyChoice{url: &url.URL{Scheme: "http", Host: "proxy.corp:8080"}})
		untrusted := errors.New(`Post "https://api.example.com/path": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
		got := ExplainTransportError(untrusted, target)
		msg := got.Error()
		for _, want := range []string{"does not trust the certificate", "proxy.corp:8080", "root CA", "mcp doctor --network"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message %q should contain %q", msg, want)
			}
		}
		if strings.Contains(msg, EnvNoSystemProxy) {
			t.Errorf("bypassing the proxy does not fix a trust problem, message %q", msg)
		}
		if !errors.Is(got, untrusted) {
			t.Error("the original error must stay in the chain")
		}
	})
}

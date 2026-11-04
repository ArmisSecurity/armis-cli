package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-ieproxy"
)

const (
	// EnvNoSystemProxy makes the CLI ignore the operating system's proxy
	// settings (WinINET and PAC on Windows) and use only the HTTP_PROXY,
	// HTTPS_PROXY and NO_PROXY environment variables.
	EnvNoSystemProxy = "ARMIS_NO_SYSTEM_PROXY"

	// EnvTLSHandshakeTimeout overrides how long the CLI waits for a TLS
	// handshake to finish. It accepts a Go duration ("30s") or a number of
	// seconds ("30").
	EnvTLSHandshakeTimeout = "ARMIS_TLS_HANDSHAKE_TIMEOUT"

	defaultTLSHandshakeTimeout = 10 * time.Second
	maxTLSHandshakeTimeout     = 5 * time.Minute
)

// proxyFuncOnce and proxyFunc cache the operating system's proxy resolver. On
// Windows, ieproxy.GetProxyFunc() reads the WinINET settings (including a PAC
// file referenced by AutoConfigURL) on first use, and we avoid repeating that
// work on every request.
var (
	proxyFuncOnce sync.Once
	proxyFunc     func(*http.Request) (*url.URL, error)
)

// envProxy is a variable so tests can bypass the process-wide environment
// snapshot that http.ProxyFromEnvironment takes on first use.
var envProxy = http.ProxyFromEnvironment

// proxyChoices remembers, per request host, the proxy chosen for the most
// recent request, so a failure can name the proxy it went through.
var proxyChoices sync.Map // host -> proxyChoice

type proxyChoice struct {
	url    *url.URL
	source string
}

// ProxyAwareTransport returns an *http.Transport that resolves proxies from the
// host operating system's configuration rather than from environment variables
// alone.
//
// Go's http.DefaultTransport uses http.ProxyFromEnvironment, which only honors
// the HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables. On Windows that
// ignores the system proxy entirely: corporate setups commonly distribute the
// proxy through WinINET — a static ProxyServer and/or a PAC script referenced by
// AutoConfigURL (e.g. Zscaler). A Go binary therefore attempts a direct
// connection that the network drops before any response, surfacing as a bare
// "EOF" on the very first request (the auth token exchange).
//
// ieproxy.GetProxyFunc() bridges that gap: on Windows it reads the WinINET
// registry settings and evaluates the PAC file, returning the same proxy a
// browser or Invoke-WebRequest would use. On macOS and Linux — and in our
// CGO_ENABLED=0 release builds, where the cgo system-preferences path is
// compiled out — it falls back to the standard environment-variable behavior,
// so existing setups are unaffected.
//
// Setting ARMIS_NO_SYSTEM_PROXY skips the operating system lookup, and
// ARMIS_TLS_HANDSHAKE_TIMEOUT changes the 10 second handshake limit.
func ProxyAwareTransport() *http.Transport {
	// http.DefaultTransport is documented as *http.Transport; guard the assertion
	// so a future stdlib change degrades to a fresh transport instead of panicking.
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	transport := base.Clone()
	transport.Proxy = proxyForRequest
	transport.TLSHandshakeTimeout = TLSHandshakeTimeout()
	return transport
}

// proxyForRequest is a package-level function (not a closure) so every
// transport shares the same resolver.
func proxyForRequest(req *http.Request) (*url.URL, error) {
	u, err := resolveProxy(req)
	if err == nil && req.URL != nil {
		proxyChoices.Store(req.URL.Host, proxyChoice{url: u, source: proxySource(u)})
	}
	return u, err
}

func resolveProxy(req *http.Request) (*url.URL, error) {
	if envTrue(EnvNoSystemProxy) {
		return envProxy(req)
	}
	return systemProxyFunc()(req)
}

// systemProxyFunc returns the cached OS proxy resolver, initializing it once.
func systemProxyFunc() func(*http.Request) (*url.URL, error) {
	proxyFuncOnce.Do(func() {
		proxyFunc = ieproxy.GetProxyFunc()
	})
	return proxyFunc
}

// ProxyFor reports the proxy the CLI would use for target (nil means a direct
// connection) and a description of where that setting comes from.
func ProxyFor(target *url.URL) (*url.URL, string, error) {
	u, err := resolveProxy(&http.Request{URL: target})
	return u, proxySource(u), err
}

// proxySource names the configuration that produced u. It is derived from the
// proxy that was actually chosen, so it stays correct on platforms where the
// operating system supplies the setting.
func proxySource(u *url.URL) string {
	switch {
	case u == nil:
		return "no proxy applies to this host (none is configured, or it is excluded)"
	case envTrue(EnvNoSystemProxy):
		return "environment variables only (" + EnvNoSystemProxy + " is set)"
	case proxyEnvSet():
		return "the HTTPS_PROXY/HTTP_PROXY environment variable"
	case runtime.GOOS == "windows":
		return "the Windows system proxy settings (PAC/WinINET)"
	case runtime.GOOS == "darwin":
		return "the macOS system proxy settings"
	default:
		return "the operating system's proxy settings"
	}
}

// BypassProxyAdvice says how to try a host without the proxy now in use. The
// advice depends on where the proxy comes from: ARMIS_NO_SYSTEM_PROXY has no
// effect on a proxy that HTTPS_PROXY or HTTP_PROXY supplies.
func BypassProxyAdvice(host string) string {
	if proxyEnvSet() {
		return fmt.Sprintf("To try without the proxy, unset HTTPS_PROXY and HTTP_PROXY, or set NO_PROXY=%s", host)
	}
	return fmt.Sprintf("To try without the system proxy, set %s=1 (or set HTTPS_PROXY to a working proxy and NO_PROXY=%s)", EnvNoSystemProxy, host)
}

// DescribeProxy formats a proxy for display, hiding any credentials in it.
func DescribeProxy(u *url.URL) string {
	if u == nil {
		return "direct connection (no proxy)"
	}
	if u.Scheme == "" {
		// PAC and WinINET results are bare host:port values.
		withScheme := *u
		withScheme.Scheme = "http"
		return withScheme.Redacted()
	}
	return u.Redacted()
}

// TLSHandshakeTimeout returns the handshake limit in effect. A value above the
// maximum is clamped to it; an unusable value falls back to the default and is
// reported once on stderr.
func TLSHandshakeTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(EnvTLSHandshakeTimeout))
	if raw == "" {
		return defaultTLSHandshakeTimeout
	}
	d, ok := parseHandshakeTimeout(raw)
	if !ok {
		warnOnce(raw, "ignoring %s=%q: use a duration such as 30s or a number of seconds between 1 and %d; using %s",
			EnvTLSHandshakeTimeout, raw, int(maxTLSHandshakeTimeout/time.Second), defaultTLSHandshakeTimeout)
		return defaultTLSHandshakeTimeout
	}
	if d > maxTLSHandshakeTimeout {
		warnOnce(raw, "%s=%q is above the maximum; using %s", EnvTLSHandshakeTimeout, raw, maxTLSHandshakeTimeout)
		return maxTLSHandshakeTimeout
	}
	return d
}

func parseHandshakeTimeout(raw string) (time.Duration, bool) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		secs, convErr := strconv.ParseInt(raw, 10, 64)
		if convErr != nil {
			return 0, false
		}
		if secs > int64(maxTLSHandshakeTimeout/time.Second) {
			return maxTLSHandshakeTimeout + time.Second, true
		}
		d = time.Duration(secs) * time.Second
	}
	return d, d > 0
}

// warnedValues remembers which settings were already reported, because
// TLSHandshakeTimeout is called from several places per run.
var (
	warnedValues sync.Map
	warnWriter   io.Writer = os.Stderr
)

func warnOnce(key, format string, args ...any) {
	if _, seen := warnedValues.LoadOrStore(key, struct{}{}); seen {
		return
	}
	_, _ = fmt.Fprintf(warnWriter, "Warning: "+format+"\n", args...)
}

func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func proxyEnvSet() bool {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

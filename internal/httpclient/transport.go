package httpclient

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/mattn/go-ieproxy"
)

// proxyFunc resolves the proxy for a request from the operating system's
// proxy configuration. It is computed once and reused: on Windows,
// ieproxy.GetProxyFunc() reads the WinINET settings (including a PAC file
// referenced by AutoConfigURL) on first use, and we avoid repeating that work
// on every request.
var (
	proxyFuncOnce sync.Once
	proxyFunc     func(*http.Request) (*url.URL, error)
)

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
func ProxyAwareTransport() *http.Transport {
	// http.DefaultTransport is documented as *http.Transport; guard the assertion
	// so a future stdlib change degrades to a fresh transport instead of panicking.
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	transport := base.Clone()
	transport.Proxy = systemProxyFunc()
	return transport
}

// systemProxyFunc returns the cached OS proxy resolver, initializing it once.
func systemProxyFunc() func(*http.Request) (*url.URL, error) {
	proxyFuncOnce.Do(func() {
		proxyFunc = ieproxy.GetProxyFunc()
	})
	return proxyFunc
}

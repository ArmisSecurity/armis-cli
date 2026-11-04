package httpclient

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
)

// ProxyUsedFor describes the proxy chosen for the most recent request to host
// (as it appears in the request URL), or "" when no request to it was made.
func ProxyUsedFor(host string) string {
	v, ok := proxyChoices.Load(host)
	if !ok {
		return ""
	}
	return DescribeProxy(v.(proxyChoice).url)
}

// TrustStoreAdvice says how to make the CLI trust a certificate authority on
// this operating system. A network that inspects TLS re-signs traffic with its
// own authority, and the CLI fails until that authority is trusted.
func TrustStoreAdvice() string {
	switch runtime.GOOS {
	case "windows":
		return "If your network inspects TLS, install your organization's root CA in the Windows certificate store " +
			"(Trusted Root Certification Authorities). The CLI uses that store and does not read SSL_CERT_FILE on Windows."
	case "darwin":
		return "If your network inspects TLS, add your organization's root CA to the macOS Keychain and trust it for SSL."
	default:
		return "If your network inspects TLS, add your organization's root CA to the system CA bundle, " +
			"or set SSL_CERT_FILE to a PEM file that contains it."
	}
}

// ExplainTransportError adds guidance to the two failures that proxies and
// firewalls cause most often: a TLS handshake that never finishes, and a proxy
// that cannot be reached. Other errors are returned unchanged.
func ExplainTransportError(err error, target *url.URL) error {
	if err == nil || target == nil {
		return err
	}
	msg := err.Error()
	handshake := strings.Contains(msg, "TLS handshake timeout")
	proxyConnect := strings.Contains(msg, "proxyconnect")
	untrusted := strings.Contains(msg, "x509:")
	if !handshake && !proxyConnect && !untrusted {
		return err
	}

	host := target.Hostname()
	var proxy *url.URL
	if v, ok := proxyChoices.Load(target.Host); ok {
		proxy = v.(proxyChoice).url
	}

	var hint string
	switch {
	case untrusted:
		hint = fmt.Sprintf("this machine does not trust the certificate presented for %s", host)
		if proxy != nil {
			hint += fmt.Sprintf(" (the connection went through the proxy %s)", DescribeProxy(proxy))
		}
		hint += ". " + TrustStoreAdvice()
	case proxy != nil && proxyConnect:
		hint = fmt.Sprintf("the CLI tried to reach %s through the proxy %s, taken from %s, and could not connect to that proxy. "+
			"Check the proxy address. If your PAC file lists several proxies, only the first one is used", host, DescribeProxy(proxy), ProxySource())
	case proxy != nil:
		hint = fmt.Sprintf("the connection to %s went through the proxy %s, taken from %s, and the TLS handshake did not finish within %s. "+
			"Ask your network team to allow %s through the proxy or exclude it from TLS inspection", host, DescribeProxy(proxy), ProxySource(), TLSHandshakeTimeout(), host)
	case handshake:
		hint = fmt.Sprintf("the CLI connected to %s directly (no proxy is configured for it) and the TLS handshake did not finish within %s. "+
			"A firewall, VPN or security agent may be blocking or delaying the connection. If your network requires a proxy, set HTTPS_PROXY", host, TLSHandshakeTimeout())
	default:
		return err
	}
	if proxy != nil && !untrusted {
		hint += fmt.Sprintf(". To try without the system proxy, set %s=1 (or set HTTPS_PROXY to a working proxy and NO_PROXY=%s)", EnvNoSystemProxy, host)
	}
	hint += ". Run 'armis-cli mcp doctor --network' for a step-by-step report"
	return fmt.Errorf("%w (%s)", err, hint)
}

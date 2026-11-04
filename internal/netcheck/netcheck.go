// Package netcheck reports, step by step, how the CLI reaches the Armis API:
// which proxy it uses, where a connection stops, and who signs the TLS
// certificate. It sends no credentials.
package netcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
)

const attemptTimeout = 30 * time.Second

// Options configures Run.
type Options struct {
	BaseURL string
	Out     io.Writer

	// Test hooks. Production code leaves them nil.
	proxyFor  func(*url.URL) (*url.URL, string, error)
	transport func(direct bool) *http.Transport
}

type attempt struct {
	events []string
	err    error
	status int
	took   time.Duration
	tls    *tls.ConnectionState
}

// Run checks the connection and writes a report to opts.Out. It returns true
// when the path the CLI normally uses reaches the API.
func Run(ctx context.Context, opts Options) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	out := opts.Out
	target, err := url.Parse(opts.BaseURL)
	if err != nil || target.Host == "" {
		_, _ = fmt.Fprintf(out, "Cannot check %q: not a valid URL\n", opts.BaseURL)
		return false
	}
	proxyFor := opts.proxyFor
	if proxyFor == nil {
		proxyFor = httpclient.ProxyFor
	}
	newTransport := opts.transport
	if newTransport == nil {
		newTransport = defaultTransport
	}

	proxy, source, proxyErr := proxyFor(target)

	_, _ = fmt.Fprintf(out, "Armis connectivity check\n")
	_, _ = fmt.Fprintf(out, "  Target:     %s\n", target.Redacted())
	_, _ = fmt.Fprintf(out, "  Platform:   %s/%s, %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	if proxyErr != nil {
		_, _ = fmt.Fprintf(out, "  Proxy:      could not be determined: %v\n", proxyErr)
	} else {
		_, _ = fmt.Fprintf(out, "  Proxy:      %s\n", httpclient.DescribeProxy(proxy))
		_, _ = fmt.Fprintf(out, "  Taken from: %s\n", source)
	}
	_, _ = fmt.Fprintf(out, "  TLS handshake limit: %s\n", httpclient.TLSHandshakeTimeout())
	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", httpclient.EnvNoSystemProxy, httpclient.EnvTLSHandshakeTimeout, "SSL_CERT_FILE", "GODEBUG"} {
		_, _ = fmt.Fprintf(out, "  %-28s %s\n", name, envValue(name))
	}

	total := 1
	if proxy != nil {
		total = 2
	}

	_, _ = fmt.Fprintf(out, "\n[1/%d] Connection the CLI uses\n", total)
	used := probe(ctx, newTransport(false), target)
	report(out, used)

	if proxy == nil {
		verdictDirectOnly(out, used)
		return used.err == nil
	}

	_, _ = fmt.Fprintf(out, "\n[2/2] Direct connection, without the proxy (diagnostic only: the CLI does not use it)\n")
	direct := probe(ctx, newTransport(true), target)
	report(out, direct)

	verdictProxied(out, used, direct, target.Hostname())
	return used.err == nil
}

func defaultTransport(direct bool) *http.Transport {
	tr := httpclient.ProxyAwareTransport()
	if direct {
		tr.Proxy = nil
	}
	return tr
}

func probe(ctx context.Context, tr *http.Transport, target *url.URL) attempt {
	var a attempt
	start := time.Now()
	mark := func(format string, args ...any) {
		a.events = append(a.events, fmt.Sprintf("%7s  %s", fmtDur(time.Since(start)), fmt.Sprintf(format, args...)))
	}

	trace := &httptrace.ClientTrace{
		DNSStart: func(i httptrace.DNSStartInfo) { mark("looking up %s", i.Host) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err != nil {
				mark("DNS failed: %v", i.Err)
				return
			}
			addrs := make([]string, 0, len(i.Addrs))
			for _, ad := range i.Addrs {
				addrs = append(addrs, ad.String())
			}
			mark("DNS answered: %s", strings.Join(addrs, ", "))
		},
		ConnectStart: func(network, addr string) { mark("connecting to %s", addr) },
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				mark("connect to %s failed: %v", addr, err)
				return
			}
			mark("connected to %s", addr)
		},
		TLSHandshakeStart: func() { mark("TLS handshake started (limit %s)", tr.TLSHandshakeTimeout) },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				mark("TLS handshake failed: %v", err)
				return
			}
			mark("TLS handshake finished (%s, protocol %q)", tlsVersion(cs.Version), cs.NegotiatedProtocol)
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { mark("request sent") },
		GotFirstResponseByte: func() { mark("first response byte received") },
	}

	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.String(), nil)
	if err != nil {
		a.err = err
		return a
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req) //nolint:gosec // G704: URL is the configured Armis API base URL
	a.took = time.Since(start)
	if err != nil {
		a.err = err
		return a
	}
	defer resp.Body.Close() //nolint:errcheck // body is not read
	a.status = resp.StatusCode
	a.tls = resp.TLS
	return a
}

func report(out io.Writer, a attempt) {
	for _, e := range a.events {
		_, _ = fmt.Fprintf(out, "  %s\n", e)
	}
	if a.err != nil {
		_, _ = fmt.Fprintf(out, "  FAILED after %s: %v\n", fmtDur(a.took), a.err)
		return
	}
	_, _ = fmt.Fprintf(out, "  OK: HTTP %d in %s\n", a.status, fmtDur(a.took))
	if a.tls != nil {
		for i, c := range a.tls.PeerCertificates {
			_, _ = fmt.Fprintf(out, "  certificate %d: subject %q, issued by %q\n", i, c.Subject.String(), c.Issuer.String())
		}
	}
}

func verdictDirectOnly(out io.Writer, a attempt) {
	_, _ = fmt.Fprintf(out, "\nResult\n")
	if a.err == nil {
		_, _ = fmt.Fprintf(out, "  The API is reachable. HTTP %d without credentials is the expected answer.\n", a.status)
		certNote(out, a)
		return
	}
	_, _ = fmt.Fprintf(out, "  The API is not reachable. Look at the last step above that did not finish.\n")
	_, _ = fmt.Fprintf(out, "  If your network requires a proxy, set HTTPS_PROXY. A firewall, VPN or security agent can also block the connection.\n")
}

func verdictProxied(out io.Writer, used, direct attempt, host string) {
	_, _ = fmt.Fprintf(out, "\nResult\n")
	switch {
	case used.err == nil:
		_, _ = fmt.Fprintf(out, "  The API is reachable through the proxy. HTTP %d without credentials is the expected answer.\n", used.status)
		certNote(out, used)
	case direct.err == nil:
		_, _ = fmt.Fprintf(out, "  The direct connection works and the proxy path does not.\n")
		if strings.Contains(used.err.Error(), "proxyconnect") {
			_, _ = fmt.Fprintf(out, "  The CLI could not connect to the proxy itself. Check that the proxy address is right and the proxy is running.\n")
			_, _ = fmt.Fprintf(out, "  If a PAC file lists several proxies, the CLI uses only the first one.\n")
		} else {
			_, _ = fmt.Fprintf(out, "  Ask your network team to allow %s through the proxy or exclude it from TLS inspection.\n", host)
		}
		_, _ = fmt.Fprintf(out, "  If policy allows a direct connection, set %s=1 to ignore the system proxy settings,\n", httpclient.EnvNoSystemProxy)
		_, _ = fmt.Fprintf(out, "  or set HTTPS_PROXY to a working proxy and NO_PROXY=%s.\n", host)
	default:
		_, _ = fmt.Fprintf(out, "  Neither the proxy path nor the direct connection reaches the API.\n")
		_, _ = fmt.Fprintf(out, "  Look at the last step in each section that did not finish. A VPN, firewall or security agent may be involved.\n")
	}
}

func certNote(out io.Writer, a attempt) {
	if a.tls == nil || len(a.tls.PeerCertificates) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "  The server certificate was issued by %q.\n", a.tls.PeerCertificates[0].Issuer.String())
	_, _ = fmt.Fprintf(out, "  If that is your organization's CA, your network is inspecting TLS traffic.\n")
}

func envValue(name string) string {
	v := os.Getenv(name)
	if v == "" {
		return "(not set)"
	}
	if u, err := url.Parse(v); err == nil && u.User != nil {
		return u.Redacted()
	}
	return v
}

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

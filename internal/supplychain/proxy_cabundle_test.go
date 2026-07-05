package supplychain

import (
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A throwaway self-signed PEM is enough to prove AppendCertsFromPEM accepts a
// valid bundle; the bytes are a real, syntactically valid certificate.
const testCAPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

// TestCABundleConfig is test-plan case #18: a CA bundle path is applied to the
// proxy's TLS config. A valid PEM is accepted; a missing or empty file is a
// hard error (a TLS misconfig must surface, never silently fail-open).
func TestCABundleConfig(t *testing.T) {
	t.Run("valid CA bundle accepted", func(t *testing.T) {
		dir := t.TempDir()
		caPath := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caPath, []byte(testCAPEM), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewProxy(ProxyConfig{
			Policy:       Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL:  "https://nexus.corp/repository/npm-group/",
			CABundlePath: caPath,
		})
		if err != nil {
			t.Fatalf("valid CA bundle should be accepted, got: %v", err)
		}
	})

	t.Run("missing CA bundle is a hard error", func(t *testing.T) {
		_, err := NewProxy(ProxyConfig{
			Policy:       Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL:  "https://nexus.corp/repository/npm-group/",
			CABundlePath: "/nonexistent/ca.pem",
		})
		if err == nil {
			t.Fatal("a missing CA bundle must be a hard error, not a silent fallback")
		}
	})

	t.Run("garbage CA bundle is a hard error", func(t *testing.T) {
		dir := t.TempDir()
		caPath := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewProxy(ProxyConfig{
			Policy:       Policy{MinReleaseAge: 72 * time.Hour},
			UpstreamURL:  "https://nexus.corp/repository/npm-group/",
			CABundlePath: caPath,
		})
		if err == nil {
			t.Fatal("a CA bundle with no valid certs must be a hard error")
		}
	})
}

// TestIsX509Error sanity-checks the typed-error detection used to print the
// CA-bundle fix message.
func TestIsX509Error(t *testing.T) {
	if isX509Error(os.ErrNotExist) {
		t.Error("a non-TLS error should not be detected as x509")
	}
}

// TestNewUpstreamHTTPClientAugmentsSystemTrust is the regression guard for the
// CA-bundle-replaces-system-trust bug: a configured bundle must ADD a corporate
// CA alongside the system roots, not swap them out — otherwise a registry
// fronted by a public CA (e.g. a CDN) would stop verifying once any CA bundle
// is configured. Proven indirectly: appending a syntactically valid PEM to a
// pool built via SystemCertPool() (this function's actual starting point)
// leaves that pool non-empty and still able to verify certs chaining to the
// system roots — an empty NewCertPool() base could not.
func TestNewUpstreamHTTPClientAugmentsSystemTrust(t *testing.T) {
	sysPool, err := x509.SystemCertPool()
	if err != nil || sysPool == nil {
		t.Skip("no system cert pool available on this platform")
	}
	sysSubjects := len(sysPool.Subjects()) //nolint:staticcheck // Subjects() is deprecated but adequate for this count-based assertion
	if sysSubjects == 0 {
		t.Skip("system cert pool is empty on this platform")
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte(testCAPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := newUpstreamHTTPClient(mustParseURL(t, "https://nexus.corp/repository/npm-group/"), caPath)
	if err != nil {
		t.Fatalf("valid CA bundle should be accepted, got: %v", err)
	}
	pool := client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if pool == nil {
		t.Fatal("expected a non-nil RootCAs pool")
	}
	if len(pool.Subjects()) <= sysSubjects { //nolint:staticcheck // Subjects() is deprecated but adequate for this count-based assertion
		t.Errorf("expected the configured bundle's RootCAs to contain the system roots plus the added cert (>%d subjects), got %d — CA bundle appears to have replaced system trust instead of augmenting it", sysSubjects, len(pool.Subjects())) //nolint:staticcheck
	}
}

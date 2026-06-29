package supplychain

import (
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

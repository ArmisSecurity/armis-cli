package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// ML-DSA signature schemes. Go 1.27.0-1.27.3 also offer them in
// signature_algorithms_cert, and Palo Alto's IPS rule for CVE-2020-1967
// (threat ID 58033) drops any ClientHello that does (go.dev/issue/79626).
// Go 1.27.4 keeps them out of that extension.
var mldsaSchemes = []uint16{0x0904, 0x0905, 0x0906}

// classicSignatureSchemes is what signature_algorithms_cert carried before Go
// 1.27. Middleboxes have shown they inspect this list, so a new entry needs
// checking against them before it ships.
var classicSignatureSchemes = []uint16{
	uint16(tls.PSSWithSHA256), uint16(tls.ECDSAWithP256AndSHA256), uint16(tls.Ed25519),
	uint16(tls.PSSWithSHA384), uint16(tls.PSSWithSHA512),
	uint16(tls.PKCS1WithSHA256), uint16(tls.PKCS1WithSHA384), uint16(tls.PKCS1WithSHA512),
	uint16(tls.ECDSAWithP384AndSHA384), uint16(tls.ECDSAWithP521AndSHA512),
	uint16(tls.PKCS1WithSHA1), uint16(tls.ECDSAWithSHA1),
}

const toolchainHint = "build with Go 1.27.4 or later (go.mod's toolchain line); earlier 1.27 releases send ML-DSA in signature_algorithms_cert, which Palo Alto threat ID 58033 drops"

func captureClientHello(t *testing.T) *testutil.ClientHello {
	t.Helper()
	proxy := testutil.NewHelloProxy(t, "", nil)
	tr := ProxyAwareTransport()
	tr.Proxy = http.ProxyURL(proxy.URL)
	tr.TLSHandshakeTimeout = 5 * time.Second
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get("https://api.armis.test/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the capturing proxy closes every tunnel; the request should fail")
	}
	hellos := proxy.Hellos()
	if len(hellos) == 0 {
		t.Fatalf("no ClientHello reached the proxy: %v", err)
	}
	return hellos[0]
}

func TestClientHelloSignatureSchemesCert(t *testing.T) {
	hello := captureClientHello(t)
	for _, s := range hello.SignatureSchemesCert {
		switch {
		case slices.Contains(mldsaSchemes, s):
			t.Errorf("signature_algorithms_cert offers ML-DSA 0x%04x; %s", s, toolchainHint)
		case !slices.Contains(classicSignatureSchemes, s):
			t.Errorf("signature_algorithms_cert offers 0x%04x, which earlier builds did not; check it against TLS-inspecting firewalls before shipping", s)
		}
	}
	if len(hello.SignatureSchemes) == 0 {
		t.Error("ClientHello has no signature_algorithms extension")
	}
}

func TestClientHelloStillOffersTLS13AndHTTP2(t *testing.T) {
	hello := captureClientHello(t)
	if !slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
		t.Errorf("ClientHello should still offer TLS 1.3, got versions %s", hex(hello.SupportedVersions))
	}
	if !slices.Equal(hello.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %q, want [h2 http/1.1]", hello.ALPN)
	}
}

// A firewall that accepts CONNECT and then never answers a ClientHello with
// ML-DSA in signature_algorithms_cert, as Palo Alto threat ID 58033 does. The
// CLI must get through it.
func TestHandshakeThroughFirewallDroppingMLDSACertHellos(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	proxy := testutil.NewHelloProxy(t, srv.Listener.Addr().String(), func(h *testutil.ClientHello) bool {
		return !slices.ContainsFunc(h.SignatureSchemesCert, func(s uint16) bool { return slices.Contains(mldsaSchemes, s) })
	})

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr := ProxyAwareTransport()
	tr.Proxy = http.ProxyURL(proxy.URL)
	tr.TLSHandshakeTimeout = time.Second
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	defer tr.CloseIdleConnections()

	// httptest's certificate is valid for example.com; the proxy sends every
	// tunnel to srv regardless of the CONNECT host.
	resp, err := (&http.Client{Transport: tr}).Get("https://example.com/")
	if err != nil {
		t.Fatalf("request through the filtering firewall failed: %v; %s", err, toolchainHint)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func hex(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("0x%04x", x)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

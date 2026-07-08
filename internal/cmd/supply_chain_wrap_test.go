package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

// execPMCapture records the arguments execPMFunc was invoked with so tests can
// assert on the resolved PM name, forwarded args, and injected environment
// without spawning a real process.
type execPMCapture struct {
	called   bool
	calls    int
	pm       string
	args     []string
	extraEnv []string
}

// stubExecPM replaces the package-level execPMFunc with a capturing stub that
// returns the given exit code, restoring the real implementation on cleanup. It
// returns the capture so the test can inspect what would have been executed.
func stubExecPM(t *testing.T, exitCode int) *execPMCapture {
	t.Helper()
	cap := &execPMCapture{}
	t.Cleanup(func() { execPMFunc = execPM })
	execPMFunc = func(pm string, args []string, extraEnv []string) (int, error) {
		cap.called = true
		cap.calls++
		cap.pm = pm
		cap.args = args
		cap.extraEnv = extraEnv
		return exitCode, nil
	}
	return cap
}

// envValue returns the value for key in a "KEY=value" environment slice, and
// whether it was present.
func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

// newWrapTestCmd returns a cobra command with a live context, as the wrap
// runners expect (runProxyWrap/runPreInstallBlock derive a timeout from
// cmd.Context(), which panics on a nil context).
func newWrapTestCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}

func TestRunSupplyChainWrap_SCActiveBypass(t *testing.T) {
	// With ARMIS_SUPPLY_CHAIN_ACTIVE=1 the wrapper must pass straight through to
	// the package manager (recursion guard) without starting a proxy.
	t.Setenv(envSCActive, "1")
	cap := stubExecPM(t, 0)

	err := runSupplyChainWrap(newWrapTestCmd(), []string{"npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called {
		t.Fatal("expected execPMFunc to be called")
	}
	if cap.pm != "npm" {
		t.Errorf("pm = %q, want npm", cap.pm)
	}
	if !reflect.DeepEqual(cap.args, []string{"install", "lodash"}) {
		t.Errorf("args = %#v, want [install lodash]", cap.args)
	}
	// The passthrough must not inject the registry override.
	if _, ok := envValue(cap.extraEnv, "npm_config_registry"); ok {
		t.Error("passthrough should not set npm_config_registry")
	}
}

func TestRunSupplyChainWrap_Off(t *testing.T) {
	// ARMIS_SUPPLY_CHAIN=off disables enforcement entirely.
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "off")
	cap := stubExecPM(t, 0)

	err := runSupplyChainWrap(newWrapTestCmd(), []string{"npm", "install"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called {
		t.Fatal("expected execPMFunc to be called for the off passthrough")
	}
}

func TestRunSupplyChainWrap_UnsupportedPM(t *testing.T) {
	cap := stubExecPM(t, 0)

	err := runSupplyChainWrap(newWrapTestCmd(), []string{"cargo", "build"})
	if err == nil {
		t.Fatal("expected an error for an unsupported package manager")
	}
	if cap.called {
		t.Error("execPMFunc must not run for an unsupported package manager")
	}
}

func TestRunProxyWrap_InjectsNpmRegistryEnv(t *testing.T) {
	// Run from an isolated dir so resolveWrapPolicy does not pick up a stray
	// .armis-supply-chain.yaml from an ancestor of the repo checkout.
	chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	cap := stubExecPM(t, 0)

	if err := runProxyWrap(newWrapTestCmd(), pmNPM, []string{"install"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called {
		t.Fatal("expected execPMFunc to be called")
	}
	reg, ok := envValue(cap.extraEnv, "npm_config_registry")
	if !ok {
		t.Fatalf("npm_config_registry not set; extraEnv=%v", cap.extraEnv)
	}
	if !strings.HasPrefix(reg, "http://127.0.0.1:") {
		t.Errorf("npm_config_registry = %q, want http://127.0.0.1:<port>/", reg)
	}
	// The recursion guard must be set for the child process.
	if v, ok := envValue(cap.extraEnv, envSCActive); !ok || v != "1" {
		t.Errorf("%s = %q (present=%v), want 1", envSCActive, v, ok)
	}
}

// TestRunProxyWrap_PipEnvPointsAtProxy asserts pip is routed through the proxy
// via PIP_INDEX_URL pointing at the local proxy's /simple/ endpoint. The actual
// PyPI Simple API age filtering the proxy performs in PyPI mode is covered by
// the proxy-layer tests (TestProxyFilterPyPISimple* in the supplychain package);
// this test pins the command-layer wiring that gets pip there.
func TestRunProxyWrap_PipEnvPointsAtProxy(t *testing.T) {
	chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	cap := stubExecPM(t, 0)

	if err := runProxyWrap(newWrapTestCmd(), pmPip, []string{"install", "requests"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idx, ok := envValue(cap.extraEnv, "PIP_INDEX_URL")
	if !ok {
		t.Fatalf("PIP_INDEX_URL not set; extraEnv=%v", cap.extraEnv)
	}
	if !strings.HasPrefix(idx, "http://127.0.0.1:") || !strings.HasSuffix(idx, "/simple/") {
		t.Errorf("PIP_INDEX_URL = %q, want http://127.0.0.1:<port>/simple/", idx)
	}
}

// TestRunSupplyChainWrap_UVSyncAuditsLockfileNotProxy pins the fix for uv.lock
// corruption: uv records the configured index URL as each package's
// source.registry in uv.lock, and an index that differs from the recorded one
// triggers a full re-lock. Routing a lockfile-writing uv command through the
// proxy therefore persisted the ephemeral http://127.0.0.1:<port> address into
// the lock, breaking every sync run outside the wrapper (Docker builds, CI).
// Such commands must take the pre-install audit path with no UV_INDEX_URL
// injected.
func TestRunSupplyChainWrap_UVSyncAuditsLockfileNotProxy(t *testing.T) {
	dir := chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")
	// An empty uv.lock parses to zero registry-backed packages, so the audit
	// has nothing to query (no network) and the build is allowed to run.
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cap := stubExecPM(t, 0)

	if err := runSupplyChainWrap(newWrapTestCmd(), []string{"uv", "sync"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called {
		t.Fatal("expected execPMFunc to be called")
	}
	if cap.pm != pmUV {
		t.Errorf("pm = %q, want %q", cap.pm, pmUV)
	}
	if v, ok := envValue(cap.extraEnv, "UV_INDEX_URL"); ok {
		t.Errorf("uv sync must not be proxied (UV_INDEX_URL=%q leaks into uv.lock)", v)
	}
}

// TestRunSupplyChainWrap_UVPipKeepsProxy asserts the lockfile-free `uv pip`
// interface still gets live proxy filtering: it never writes uv.lock, so the
// index override cannot leak anywhere persistent.
func TestRunSupplyChainWrap_UVPipKeepsProxy(t *testing.T) {
	chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")
	cap := stubExecPM(t, 0)

	if err := runSupplyChainWrap(newWrapTestCmd(), []string{"uv", "pip", "install", "requests"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idx, ok := envValue(cap.extraEnv, "UV_INDEX_URL")
	if !ok {
		t.Fatalf("UV_INDEX_URL not set for uv pip; extraEnv=%v", cap.extraEnv)
	}
	if !strings.HasPrefix(idx, "http://127.0.0.1:") || !strings.HasSuffix(idx, "/simple/") {
		t.Errorf("UV_INDEX_URL = %q, want http://127.0.0.1:<port>/simple/", idx)
	}
}

// TestRunProxyWrap_NormalizesBunLock pins the post-exec residue sweep: `bun
// update` records full tarball URLs in bun.lock, so a proxied run persists the
// ephemeral http://127.0.0.1:<port> origin into a committed artifact (verified
// empirically on bun 1.3). After the PM exits, the wrap must rewrite that
// origin back to the upstream registry.
func TestRunProxyWrap_NormalizesBunLock(t *testing.T) {
	dir := chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")

	// The stub plays the role of bun: it writes a bun.lock whose tarball URLs
	// use the registry origin it was invoked with, exactly like `bun update`.
	t.Cleanup(func() { execPMFunc = execPM })
	execPMFunc = func(pm string, args, extraEnv []string) (int, error) {
		reg, ok := envValue(extraEnv, "BUN_CONFIG_REGISTRY")
		if !ok {
			t.Fatal("BUN_CONFIG_REGISTRY not set; the proxy was not injected")
		}
		origin := strings.TrimSuffix(reg, "/")
		lock := `"axios": ["axios@0.30.3", "` + origin + `/axios/-/axios-0.30.3.tgz", {}, "sha512-x"]`
		return 0, os.WriteFile(filepath.Join(dir, "bun.lock"), []byte(lock), 0o600)
	}

	if err := runProxyWrap(newWrapTestCmd(), pmBun, []string{"update"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "bun.lock")) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "127.0.0.1") {
		t.Errorf("bun.lock still contains the proxy origin:\n%s", got)
	}
	if !strings.Contains(string(got), "https://registry.npmjs.org/axios/-/axios-0.30.3.tgz") {
		t.Errorf("bun.lock tarball URL not restored to the upstream registry:\n%s", got)
	}
}

// TestRunProxyWrap_NormalizesUVToolReceipt pins the receipt sweep: `uv tool
// install` records the index-url it was invoked with in uv-receipt.toml, which
// would point every later `uv tool upgrade` at the dead proxy address. After
// the PM exits, the wrap must rewrite the receipt to the real index.
func TestRunProxyWrap_NormalizesUVToolReceipt(t *testing.T) {
	chdirTemp(t)
	toolsDir := t.TempDir()
	t.Setenv("UV_TOOL_DIR", toolsDir)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")

	receipt := filepath.Join(toolsDir, "cowsay", "uv-receipt.toml")
	if err := os.MkdirAll(filepath.Dir(receipt), 0o700); err != nil {
		t.Fatal(err)
	}

	// The stub plays the role of uv: it writes a receipt recording the index
	// URL it was invoked with, exactly like `uv tool install`.
	t.Cleanup(func() { execPMFunc = execPM })
	execPMFunc = func(pm string, args, extraEnv []string) (int, error) {
		idx, ok := envValue(extraEnv, "UV_INDEX_URL")
		if !ok {
			t.Fatal("UV_INDEX_URL not set; the proxy was not injected")
		}
		return 0, os.WriteFile(receipt, []byte(`index-url = "`+idx+`"`), 0o600)
	}

	if err := runProxyWrap(newWrapTestCmd(), pmUV, []string{"tool", "install", "cowsay"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(receipt) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "127.0.0.1") {
		t.Errorf("receipt still contains the proxy origin:\n%s", got)
	}
	if want := `index-url = "https://pypi.org/simple/"`; string(got) != want {
		t.Errorf("receipt = %q, want %q", got, want)
	}
}

// TestRunProxyWrap_NormalizesUVCompileOutput pins the output-file sweep:
// `uv pip compile --emit-index-url -o FILE` writes the configured index — the
// proxy URL — into the generated requirements file (verified on uv 0.8).
func TestRunProxyWrap_NormalizesUVCompileOutput(t *testing.T) {
	dir := chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")
	out := filepath.Join(dir, "requirements.txt")

	// The stub plays the role of uv pip compile: it emits the index URL it was
	// invoked with into the -o output file.
	t.Cleanup(func() { execPMFunc = execPM })
	execPMFunc = func(pm string, args, extraEnv []string) (int, error) {
		idx, ok := envValue(extraEnv, "UV_INDEX_URL")
		if !ok {
			t.Fatal("UV_INDEX_URL not set; the proxy was not injected")
		}
		return 0, os.WriteFile(out, []byte("--index-url "+idx+"\nsix==1.17.0\n"), 0o600)
	}

	args := []string{"pip", "compile", "pyproject.toml", "-o", out, "--emit-index-url"}
	if err := runProxyWrap(newWrapTestCmd(), pmUV, args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(out) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "127.0.0.1") {
		t.Errorf("compiled requirements still contain the proxy origin:\n%s", got)
	}
	if !strings.Contains(string(got), "--index-url https://pypi.org/simple/") {
		t.Errorf("index URL not restored to PyPI:\n%s", got)
	}
	if !strings.Contains(string(got), "six==1.17.0") {
		t.Errorf("pinned requirement was not preserved:\n%s", got)
	}
}

func TestUVCompileOutputFile(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"short flag", []string{"pip", "compile", "in.toml", "-o", "req.txt"}, "req.txt"},
		{"long flag", []string{"pip", "compile", "in.toml", "--output-file", "req.txt"}, "req.txt"},
		{"long flag attached", []string{"pip", "compile", "--output-file=req.txt", "in.toml"}, "req.txt"},
		{"no output flag", []string{"pip", "compile", "in.toml"}, ""},
		{"dangling flag", []string{"pip", "compile", "-o"}, ""},
		{"no args", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uvCompileOutputFile(tt.args); got != tt.want {
				t.Errorf("uvCompileOutputFile(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestRunPreInstallBlock_AllPassRunsPM(t *testing.T) {
	// A poetry.lock whose only entry is a git-sourced package: the parser drops
	// it, so RunCheck has nothing to query (Checked == 0), no network is touched,
	// and the build is allowed to run.
	dir := chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")
	lock := `[[package]]
name = "my-git-dep"
version = "1.0.0"

[package.source]
type = "git"
url = "https://github.com/user/repo.git"
`
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	cap := stubExecPM(t, 0)

	if err := runPreInstallBlock(newWrapTestCmd(), pmPoetry, []string{"install"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.calls != 1 {
		t.Errorf("execPMFunc called %d times, want 1", cap.calls)
	}
	if cap.pm != pmPoetry {
		t.Errorf("pm = %q, want %q", cap.pm, pmPoetry)
	}
}

// TestRunPreInstallBlock_QueriesConfiguredRegistry is the regression guard for
// the bug where the pre-install audit path (poetry/pipenv/pdm/maven/gradle, and
// any lockfile-writing uv command) always called check.RunCheck — never
// RunCheckWithRegistry — so a configured registries.<eco> was silently
// ignored: every age check queried the PUBLIC registry regardless of policy,
// and `check` would report "all pass" having verified nothing against the
// approved artifactory. This pins that a configured registry is actually the
// host queried, using a fake Simple-API server as the "approved" registry and
// asserting it (not pypi.org) receives the hit.
func TestRunPreInstallBlock_QueriesConfiguredRegistry(t *testing.T) {
	// ValidateRegistryURL (S1) rejects a literal loopback IP, and (as of the
	// reserved-name fix below) "localhost"/"*.localhost" by name too, as a
	// registry host — so httptest.NewTLSServer's 127.0.0.1 URL cannot be used
	// directly here (a deliberate SSRF guard, not a test obstacle to route
	// around). "nexus.registry.example" is an IANA-reserved documentation domain
	// (RFC 2606) that passes validation like any real corporate hostname would,
	// while making clear it is a fixture, not a real host. It never actually
	// resolves via DNS; the dialer override below redirects it to 127.0.0.1
	// directly, so no real lookup happens and no OS-specific resolver behavior
	// (e.g. *.localhost special-casing, absent on Windows) is depended on. The
	// server's own default cert (issued for "example.com") would not validate
	// against this hostname, so this test mints its own self-signed cert for
	// "nexus.registry.example" and serves it directly over tls.Listen.
	// Override supplychain.BaseUpstreamTransport (a package-level test seam,
	// mirroring execPMFunc) instead of mutating the process-global
	// http.DefaultTransport — the latter would race against any parallel test
	// elsewhere in this module that makes its own HTTP request.
	origBaseTransport := supplychain.BaseUpstreamTransport
	supplychain.BaseUpstreamTransport = func() *http.Transport {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, splitErr := net.SplitHostPort(addr)
			// armis:ignore cwe:918 reason:test-only code (this file has no _test.go build exclusion but is never compiled into the shipped binary); the redirected host is a hardcoded string literal ("nexus.registry.example", this test's own fixture hostname), not derived from any request URL or other runtime input, so there is nothing here for an attacker to control
			if splitErr == nil && host == "nexus.registry.example" {
				addr = net.JoinHostPort("127.0.0.1", portStr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		return transport
	}
	t.Cleanup(func() { supplychain.BaseUpstreamTransport = origBaseTransport })

	var hit bool
	certPEM, server, port := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if r.URL.Path != "/simple/leftpad/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = w.Write([]byte(`{"files":[{"filename":"leftpad-1.0.0-py3-none-any.whl","upload-time":"2020-01-01T00:00:00Z"}]}`))
	})
	defer server.Close()

	dir := chdirTemp(t)
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	t.Setenv(envSCSkip, "")

	caBundlePath := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(caBundlePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	registryURL := fmt.Sprintf("https://nexus.registry.example:%s/simple/", port)
	writeConfig(t, dir, "version: 1\nmin-age: 72h\nregistries:\n  pypi: "+registryURL+"\nregistry-enforcement: warn\nregistry-ca-bundle: "+caBundlePath+"\n")

	lock := `version = 1

[[package]]
name = "leftpad"
version = "1.0.0"
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	cap := stubExecPM(t, 0)

	if err := runPreInstallBlock(newWrapTestCmd(), pmUV, []string{"sync"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Fatal("the configured registry was never queried — audit path silently used the public registry")
	}
	if cap.calls != 1 {
		t.Errorf("execPMFunc called %d times, want 1", cap.calls)
	}
}

// newTLSTestServer starts an HTTPS server on 127.0.0.1 with a self-signed cert
// issued for "nexus.registry.example" — a hostname string, not a literal IP,
// so it passes ValidateRegistryURL's loopback/reserved-name checks the way a
// real corporate hostname would. httptest.NewTLSServer's own cert, issued for
// "example.com", would not validate against that hostname. It returns the
// cert as a PEM block (for registry-ca-bundle) alongside the listening server
// and its port.
func newTLSTestServer(t *testing.T, handler http.HandlerFunc) ([]byte, *httptest.Server, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nexus.registry.example"},
		DNSNames:     []string{"nexus.registry.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, server, port
}

func TestRunSupplyChainWrap_EcosystemScopeExcludesPM(t *testing.T) {
	// Config scopes enforcement to npm only; a pip install must pass straight
	// through to the real pip with no proxy started and no PIP_INDEX_URL injected.
	dir := chdirTemp(t)
	writeConfig(t, dir, "version: 1\necosystems:\n  - npm\n")
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	cap := stubExecPM(t, 0)

	if err := runSupplyChainWrap(newWrapTestCmd(), []string{"pip", "install", "requests"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called {
		t.Fatal("expected execPMFunc to be called (passthrough)")
	}
	if _, ok := envValue(cap.extraEnv, "PIP_INDEX_URL"); ok {
		t.Error("out-of-scope pip must not be routed through the proxy (PIP_INDEX_URL set)")
	}
	if _, ok := envValue(cap.extraEnv, envSCActive); ok {
		t.Error("passthrough must not set the recursion guard env")
	}
}

func TestRunSupplyChainWrap_EcosystemScopeIncludesPM(t *testing.T) {
	// Config scopes to pip; a pip install is still enforced (routed through the
	// proxy). This guards against the gate over-blocking an in-scope ecosystem.
	dir := chdirTemp(t)
	writeConfig(t, dir, "version: 1\necosystems:\n  - pip\n")
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")
	cap := stubExecPM(t, 0)

	if err := runSupplyChainWrap(newWrapTestCmd(), []string{"pip", "install", "requests"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := envValue(cap.extraEnv, "PIP_INDEX_URL"); !ok {
		t.Errorf("in-scope pip should be routed through the proxy; extraEnv=%v", cap.extraEnv)
	}
}

func TestParseSkipPackages(t *testing.T) {
	// Hoist the repeated package names into constants so the want slices below
	// don't trip goconst (which flags an identical string literal repeated 3+
	// times across the package).
	const (
		lodash  = "lodash"
		express = "express"
		react   = "react"
	)

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		// FieldsFunc returns an empty (non-nil) slice when there are no fields;
		// an empty slice yields an empty skip set, which is the intended no-op.
		{"empty", "", []string{}},
		{"whitespace only", "   \t\n", []string{}},
		{"single", "lodash", []string{lodash}},
		{"comma separated", "lodash,express", []string{lodash, express}},
		{"comma with spaces", "lodash, express, react", []string{lodash, express, react}},
		{"whitespace separated", "lodash express react", []string{lodash, express, react}},
		{"mixed separators", "lodash,  express\treact", []string{lodash, express, react}},
		{"trailing comma drops empty field", "lodash,express,", []string{lodash, express}},
		{"leading and doubled separators", ",,lodash,,express", []string{lodash, express}},
		{"scoped package", "@myorg/utils,express", []string{"@myorg/utils", express}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSkipPackages(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSkipPackages(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCheckGradleStaleness(t *testing.T) {
	// checkGradleStaleness writes an advisory warning to stderr and returns
	// nothing; these cases exercise each path condition (missing lockfile,
	// missing build file, .kts fallback, stale vs fresh) to confirm it handles
	// them without panicking and stats the right sibling file.
	writeFile := func(t *testing.T, path string, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !mod.IsZero() {
			if err := os.Chtimes(path, mod, mod); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("missing lockfile is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		checkGradleStaleness(filepath.Join(dir, "gradle.lockfile"))
	})

	t.Run("lockfile without build file is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), time.Time{})
		checkGradleStaleness(filepath.Join(dir, "gradle.lockfile"))
	})

	t.Run("build.gradle newer than lockfile warns", func(t *testing.T) {
		dir := t.TempDir()
		old := time.Now().Add(-time.Hour)
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), old)
		writeFile(t, filepath.Join(dir, "build.gradle"), time.Now())
		checkGradleStaleness(filepath.Join(dir, "gradle.lockfile"))
	})

	t.Run("build.gradle.kts fallback is detected", func(t *testing.T) {
		dir := t.TempDir()
		old := time.Now().Add(-time.Hour)
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), old)
		writeFile(t, filepath.Join(dir, "build.gradle.kts"), time.Now())
		checkGradleStaleness(filepath.Join(dir, "gradle.lockfile"))
	})

	t.Run("fresh lockfile newer than build is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "build.gradle"), time.Now().Add(-time.Hour))
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), time.Now())
		checkGradleStaleness(filepath.Join(dir, "gradle.lockfile"))
	})
}

// TestFormatDurationShort locks in the human-readable rendering used by both the
// status text output and the JSON min_age field. It pins the singular forms (1
// minute / 1 hour / 1 day) so the grammatical guards can't silently regress, and
// covers each branch boundary (<1h, 1-23h, >=24h).
func TestFormatDurationShort(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0 minutes"},
		{"one minute", time.Minute, "1 minute"},
		{"several minutes", 30 * time.Minute, "30 minutes"},
		{"just under an hour", 59 * time.Minute, "59 minutes"},
		{"one hour", time.Hour, "1 hour"},
		{"several hours", 2 * time.Hour, "2 hours"},
		{"just under a day", 23 * time.Hour, "23 hours"},
		{"one day", 24 * time.Hour, "1 day"},
		{"several days", 72 * time.Hour, "3 days"},
		{"two weeks", 14 * 24 * time.Hour, "14 days"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDurationShort(tt.d); got != tt.want {
				t.Errorf("formatDurationShort(%s) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

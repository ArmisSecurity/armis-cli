package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// writeProject creates a temp dir with the given .armis-supply-chain.yaml and
// optional .npmrc, chdirs into it for the test, and returns the dir.
func writeProject(t *testing.T, configYAML, npmrc string) string {
	t.Helper()
	dir := t.TempDir()
	if configYAML != "" {
		if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName), []byte(configYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if npmrc != "" {
		if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return dir
}

func TestResolveRegistrySettings(t *testing.T) {
	t.Run("npm with token → bearer auth", func(t *testing.T) {
		writeProject(t,
			"version: 1\nregistries:\n  npm: https://nexus.corp/repository/npm-group/\n",
			"//nexus.corp/repository/npm-group/:_authToken=tok123\n")

		rs, err := resolveRegistrySettings("npm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rs.Configured {
			t.Fatal("expected Configured=true")
		}
		if rs.UpstreamURL != "https://nexus.corp/repository/npm-group/" {
			t.Errorf("UpstreamURL = %q", rs.UpstreamURL)
		}
		if rs.AuthHeader != "Bearer tok123" {
			t.Errorf("AuthHeader = %q", rs.AuthHeader)
		}
		if !rs.authFound {
			t.Error("authFound should be true")
		}
	})

	t.Run("npm without token → no auth, still configured", func(t *testing.T) {
		writeProject(t,
			"version: 1\nregistries:\n  npm: https://nexus.corp/repository/npm-group/\n", "")

		rs, err := resolveRegistrySettings("npm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rs.Configured || rs.AuthHeader != "" || rs.authFound {
			t.Errorf("expected configured-but-no-auth, got %+v", rs)
		}
	})

	t.Run("no registries → not configured", func(t *testing.T) {
		writeProject(t, "version: 1\nmin-age: 72h\n", "")
		rs, err := resolveRegistrySettings("npm")
		if err != nil || rs.Configured {
			t.Errorf("expected not configured, got %+v err=%v", rs, err)
		}
	})

	t.Run("unset ${VAR} token → hard error", func(t *testing.T) {
		writeProject(t,
			"version: 1\nregistries:\n  npm: https://nexus.corp/repository/npm-group/\n",
			"//nexus.corp/repository/npm-group/:_authToken=${ARMIS_UNSET_WRAP_VAR}\n")

		_, err := resolveRegistrySettings("npm")
		if err == nil {
			t.Fatal("expected a hard error for an unset token var")
		}
	})

	t.Run("pip index-url userinfo → basic auth", func(t *testing.T) {
		writeProject(t,
			"version: 1\nregistries:\n  pypi: https://nexus.corp/repository/pypi-group/simple/\n", "")
		t.Setenv("PIP_INDEX_URL", "https://user:pass@nexus.corp/repository/pypi-group/simple/")

		rs, err := resolveRegistrySettings("pip")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if rs.AuthHeader != want {
			t.Errorf("AuthHeader = %q, want %q", rs.AuthHeader, want)
		}
	})

	t.Run("maven is not routable", func(t *testing.T) {
		writeProject(t,
			"version: 1\nregistries:\n  npm: https://nexus.corp/npm/\n", "")
		rs, err := resolveRegistrySettings("mvn")
		if err != nil || rs.Configured {
			t.Errorf("maven should not be routable, got %+v", rs)
		}
	})
}

// TestEffectiveRegistryHost is test-plan case #13: explicit off-policy is
// detected; a silent/default public registry is NOT (returns not-ok).
func TestEffectiveRegistryHost(t *testing.T) {
	t.Run("explicit npm_config_registry env", func(t *testing.T) {
		writeProject(t, "version: 1\n", "")
		t.Setenv("npm_config_registry", "https://registry.npmjs.org/")
		host, ok := effectiveRegistryHost("npm")
		if !ok || host != "registry.npmjs.org" {
			t.Errorf("host=%q ok=%v", host, ok)
		}
	})

	t.Run("explicit registry= in .npmrc", func(t *testing.T) {
		writeProject(t, "version: 1\n", "registry=https://registry.npmjs.org/\n")
		t.Setenv("npm_config_registry", "")
		host, ok := effectiveRegistryHost("npm")
		if !ok || host != "registry.npmjs.org" {
			t.Errorf("host=%q ok=%v", host, ok)
		}
	})

	t.Run("no explicit source → not ok (silent default not a trigger)", func(t *testing.T) {
		writeProject(t, "version: 1\n", "")
		t.Setenv("npm_config_registry", "")
		_, ok := effectiveRegistryHost("npm")
		if ok {
			t.Error("a silent/default registry must NOT be an explicit off-policy trigger")
		}
	})

	t.Run("scoped registry key is ignored", func(t *testing.T) {
		// A @scope:registry= line must not be read as the default registry (v1
		// explicitly excludes scoped-registry divergence).
		writeProject(t, "version: 1\n", "@myorg:registry=https://npm.pkg.github.com/\n")
		t.Setenv("npm_config_registry", "")
		_, ok := effectiveRegistryHost("npm")
		if ok {
			t.Error("a scoped @x:registry= must not count as the default registry")
		}
	})

	t.Run("pip PIP_INDEX_URL env", func(t *testing.T) {
		writeProject(t, "version: 1\n", "")
		t.Setenv("PIP_INDEX_URL", "https://pypi.org/simple/")
		host, ok := effectiveRegistryHost("pip")
		if !ok || host != "pypi.org" {
			t.Errorf("host=%q ok=%v", host, ok)
		}
	})
}

// TestWrapDryRun verifies --dry-run reports the resolved registry and never
// executes the package manager.
func TestWrapDryRun(t *testing.T) {
	writeProject(t,
		"version: 1\nregistries:\n  npm: https://nexus.corp/repository/npm-group/\nregistry-enforcement: warn\n",
		"//nexus.corp/repository/npm-group/:_authToken=tok\n")
	t.Setenv(envSCActive, "")
	t.Setenv(envSCOff, "")

	cap := stubExecPM(t, 0)
	err := runSupplyChainWrap(newWrapTestCmd(), []string{"--dry-run", "npm", "install", "express"})
	if err != nil {
		t.Fatalf("dry-run returned error: %v", err)
	}
	if cap.called {
		t.Error("--dry-run must NOT execute the package manager")
	}
}

func TestWrapDryRunRequiresPM(t *testing.T) {
	err := runSupplyChainWrap(newWrapTestCmd(), []string{"--dry-run"})
	if err == nil {
		t.Fatal("--dry-run with no PM should error")
	}
}

// TestRegistryCoverageHonesty is test-plan case #16 (E4/DX3): with registries.npm
// set but registries.pypi absent, a pip check must say "not configured — public
// registry" rather than implying coverage; and an npm check shows the host.
func TestRegistryCoverageHonesty(t *testing.T) {
	forceNoColor(t)
	npmOnly := "version: 1\nregistries:\n  npm: https://nexus.corp/repository/npm-group/\n"

	t.Run("pip reports not configured when only npm is set", func(t *testing.T) {
		dir := writeProject(t, npmOnly, "")
		cfg, err := supplychain.LoadConfig(dir)
		if err != nil {
			t.Fatal(err)
		}
		s := output.GetStyles()
		out := captureStderr(t, func() {
			printRegistryCoverage(s, cfg, supplychain.EcosystemPip, cfg.RegistryURLFor(supplychain.EcosystemPip), 0)
		})
		if !strings.Contains(out, "not configured") || !strings.Contains(out, "pip") {
			t.Errorf("pip coverage should say 'not configured', got: %q", out)
		}
	})

	t.Run("npm reports the configured host", func(t *testing.T) {
		dir := writeProject(t, npmOnly, "")
		cfg, _ := supplychain.LoadConfig(dir)
		s := output.GetStyles()
		out := captureStderr(t, func() {
			printRegistryCoverage(s, cfg, supplychain.EcosystemNPM, cfg.RegistryURLFor(supplychain.EcosystemNPM), 5)
		})
		if !strings.Contains(out, "nexus.corp") || !strings.Contains(out, "npm") {
			t.Errorf("npm coverage should name the host, got: %q", out)
		}
	})

	t.Run("no header when no registry configured", func(t *testing.T) {
		dir := writeProject(t, "version: 1\nmin-age: 72h\n", "")
		cfg, _ := supplychain.LoadConfig(dir)
		s := output.GetStyles()
		out := captureStderr(t, func() {
			printRegistryCoverage(s, cfg, supplychain.EcosystemNPM, "", 0)
		})
		if strings.Contains(out, "Registry coverage") {
			t.Errorf("no coverage header expected when no registry configured, got: %q", out)
		}
	})
}

func TestBasicAuthFromIndexURL(t *testing.T) {
	t.Run("with userinfo", func(t *testing.T) {
		h, ok, err := basicAuthFromIndexURL("https://u:p@nexus.corp/simple/")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if !strings.HasPrefix(h, "Basic ") {
			t.Errorf("header = %q", h)
		}
	})
	t.Run("empty url", func(t *testing.T) {
		_, ok, _ := basicAuthFromIndexURL("")
		if ok {
			t.Error("empty url should yield no auth")
		}
	})
}

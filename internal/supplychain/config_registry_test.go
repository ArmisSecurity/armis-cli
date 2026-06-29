package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return dir
}

// TestLoadConfigRegistries covers parsing of the new registries map and the
// RegistryURLFor / HasAnyRegistry accessors.
func TestLoadConfigRegistries(t *testing.T) {
	t.Run("npm and pypi parsed and mapped", func(t *testing.T) {
		dir := writeConfig(t, `version: 1
registries:
  npm: https://nexus.corp/repository/npm-group/
  pypi: https://nexus.corp/repository/pypi-group/simple/
registry-enforcement: warn
`)
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := cfg.RegistryURLFor(EcosystemNPM); got != "https://nexus.corp/repository/npm-group/" {
			t.Errorf("npm URL = %q", got)
		}
		// The whole npm family shares the npm key.
		if got := cfg.RegistryURLFor(EcosystemPNPM); got == "" {
			t.Error("pnpm should resolve to the npm registry URL")
		}
		if got := cfg.RegistryURLFor(EcosystemPip); !strings.Contains(got, "pypi-group") {
			t.Errorf("pip URL = %q", got)
		}
		if got := cfg.RegistryURLFor(EcosystemUV); !strings.Contains(got, "pypi-group") {
			t.Errorf("uv URL = %q", got)
		}
		// Audit-path ecosystems are not routable in v1.
		if got := cfg.RegistryURLFor(EcosystemMaven); got != "" {
			t.Errorf("maven should not be routable, got %q", got)
		}
		if !cfg.HasAnyRegistry() {
			t.Error("HasAnyRegistry should be true")
		}
	})

	t.Run("absent registries", func(t *testing.T) {
		dir := writeConfig(t, "version: 1\nmin-age: 72h\n")
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.HasAnyRegistry() {
			t.Error("HasAnyRegistry should be false when no registries set")
		}
		if cfg.RegistryURLFor(EcosystemNPM) != "" {
			t.Error("npm URL should be empty when no registries set")
		}
	})

	t.Run("nil config accessors are safe", func(t *testing.T) {
		var cfg *Config
		if cfg.RegistryURLFor(EcosystemNPM) != "" {
			t.Error("nil config npm URL should be empty")
		}
		if cfg.HasAnyRegistry() {
			t.Error("nil config HasAnyRegistry should be false")
		}
	})
}

// TestLoadConfigRegistryEnforcement is test-plan case #15 (UC-1): block is
// rejected at parse with a hard error; warn and absent parse OK.
func TestLoadConfigRegistryEnforcement(t *testing.T) {
	t.Run("block rejected at parse", func(t *testing.T) {
		dir := writeConfig(t, "version: 1\nregistry-enforcement: block\n")
		_, err := LoadConfig(dir)
		if err == nil {
			t.Fatal("expected a hard error for registry-enforcement: block")
		}
		if !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "warn") {
			t.Errorf("error should explain block is unsupported and to use warn, got: %v", err)
		}
	})

	t.Run("warn accepted", func(t *testing.T) {
		dir := writeConfig(t, "version: 1\nregistry-enforcement: warn\n")
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("warn should parse OK, got: %v", err)
		}
		if cfg.RegistryEnforcement != "warn" {
			t.Errorf("RegistryEnforcement = %q", cfg.RegistryEnforcement)
		}
	})

	t.Run("absent accepted", func(t *testing.T) {
		dir := writeConfig(t, "version: 1\nmin-age: 72h\n")
		if _, err := LoadConfig(dir); err != nil {
			t.Fatalf("absent enforcement should parse OK, got: %v", err)
		}
	})

	t.Run("unknown posture rejected", func(t *testing.T) {
		dir := writeConfig(t, "version: 1\nregistry-enforcement: enforce\n")
		_, err := LoadConfig(dir)
		if err == nil {
			t.Fatal("expected an error for an unknown posture")
		}
	})
}

// TestLoadConfigRegistryURLValidation proves the SSRF guard runs at config-load
// (S1): a non-https or non-routable registry URL is a hard parse error.
func TestLoadConfigRegistryURLValidation(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		errHas string
	}{
		{
			name:   "http npm rejected",
			yaml:   "registries:\n  npm: http://nexus.corp/npm/\n",
			errHas: "https",
		},
		{
			name:   "IMDS npm rejected",
			yaml:   "registries:\n  npm: https://169.254.169.254/npm/\n",
			errHas: "link-local",
		},
		{ //nolint:gosec // G101: test fixture URL, not a real credential
			name:   "userinfo rejected",
			yaml:   "registries:\n  npm: https://user:tok@nexus.corp/npm/\n",
			errHas: "credentials",
		},
		{
			name:   "pypi without /simple/ rejected",
			yaml:   "registries:\n  pypi: https://nexus.corp/repository/pypi-group/\n",
			errHas: "/simple/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeConfig(t, "version: 1\n"+tt.yaml)
			_, err := LoadConfig(dir)
			if err == nil {
				t.Fatalf("expected a parse error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errHas) {
				t.Errorf("error %q does not mention %q", err.Error(), tt.errHas)
			}
		})
	}

	t.Run("valid https npm + pypi/simple/ accepted", func(t *testing.T) {
		dir := writeConfig(t, `version: 1
registries:
  npm: https://nexus.corp/repository/npm-group/
  pypi: https://nexus.corp/repository/pypi-group/simple/
`)
		if _, err := LoadConfig(dir); err != nil {
			t.Fatalf("valid registries should parse, got: %v", err)
		}
	})
}

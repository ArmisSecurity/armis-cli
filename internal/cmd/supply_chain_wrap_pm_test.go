package cmd

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestCanonicalPM(t *testing.T) {
	tests := []struct {
		pm   string
		want string
	}{
		{pmPip, pmPip},
		{"pip3", pmPip},
		{"pip3.11", pmPip},
		{"pip3.12", pmPip},
		{pmUV, pmUV},
		{pmNPM, pmNPM},
		{pmPoetry, pmPoetry},
		// pipx / pipenv are distinct tools, not pip variants — must not collapse.
		{pmPipenv, pmPipenv},
		{"pipx", "pipx"},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			if got := canonicalPM(tt.pm); got != tt.want {
				t.Errorf("canonicalPM(%q) = %q, want %q", tt.pm, got, tt.want)
			}
		})
	}
}

func TestCanonicalPMAllowed(t *testing.T) {
	// A versioned pip variant must pass the allowlist check after canonicalization,
	// otherwise a wrapped `pip3.12 install` would error with "unsupported".
	for _, variant := range []string{"pip3", "pip3.11", "pip3.12"} {
		if !allowedPMs[canonicalPM(variant)] {
			t.Errorf("canonicalPM(%q) is not in allowedPMs; wrapped invocation would be rejected", variant)
		}
	}
}

func TestRequiresPreInstallBlock(t *testing.T) {
	tests := []struct {
		pm   string
		want bool
	}{
		{pmPoetry, true},
		{pmPipenv, true},
		{pmPDM, true},
		{pmMaven, true},
		{pmGradle, true},
		{pmPip, false},
		{pmUV, false},
		{pmNPM, false},
		{pmPNPM, false},
		{pmBun, false},
		{pmYarn, false},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			if got := requiresPreInstallBlock(tt.pm); got != tt.want {
				t.Errorf("requiresPreInstallBlock(%q) = %v, want %v", tt.pm, got, tt.want)
			}
		})
	}
}

func TestPmToEcosystem(t *testing.T) {
	tests := []struct {
		pm   string
		want supplychain.Ecosystem
	}{
		{pmPoetry, supplychain.EcosystemPoetry},
		{pmPipenv, supplychain.EcosystemPipfile},
		{pmPDM, supplychain.EcosystemPDM},
		{pmMaven, supplychain.EcosystemMaven},
		{pmGradle, supplychain.EcosystemGradle},
		// pmToEcosystem maps every supported PM to its ecosystem — the proxied
		// ones (npm/pnpm/bun/yarn/pip/uv) as well as the pre-install ones — so the
		// config "ecosystems" scoping gate can classify any wrapped PM. Pass the
		// canonical name; a versioned pip variant resolves to pip via canonicalPM.
		{pmNPM, supplychain.EcosystemNPM},
		{pmPNPM, supplychain.EcosystemPNPM},
		{pmBun, supplychain.EcosystemBun},
		{pmYarn, supplychain.EcosystemYarn},
		{pmPip, supplychain.EcosystemPip},
		{pmUV, supplychain.EcosystemUV},
		{"unknown-pm", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			if got := pmToEcosystem(tt.pm); got != tt.want {
				t.Errorf("pmToEcosystem(%q) = %q, want %q", tt.pm, got, tt.want)
			}
		})
	}
}

func TestRegistryEnvForPM(t *testing.T) {
	// registryURL is built by the caller as fmt.Sprintf("http://%s/", addr), so it
	// always carries a trailing slash. registryEnvForPM trims that trailing slash
	// before appending "/simple/" for pip/uv, so the index URL has a single,
	// clean "/simple/" path (no "//simple/" double slash) — the shape a PEP 503
	// proxy handler should expect.
	const url = "http://127.0.0.1:9999/"

	tests := []struct {
		pm      string
		wantKey string
		wantVal string
	}{
		{pmNPM, "npm_config_registry", url},
		{pmPNPM, "npm_config_registry", url},
		{pmBun, "BUN_CONFIG_REGISTRY", url},
		{pmYarn, "YARN_NPM_REGISTRY_SERVER", url},
		{pmPip, "PIP_INDEX_URL", "http://127.0.0.1:9999/simple/"},
		{pmUV, "UV_INDEX_URL", "http://127.0.0.1:9999/simple/"},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			env := registryEnvForPM(tt.pm, url)
			found := false
			for _, e := range env {
				if strings.HasPrefix(e, tt.wantKey+"=") && strings.HasSuffix(e, tt.wantVal) {
					found = true
				}
			}
			if !found {
				t.Errorf("registryEnvForPM(%q, %q) = %v, want entry %s=...%s", tt.pm, url, env, tt.wantKey, tt.wantVal)
			}
		})
	}
}

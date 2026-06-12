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
		// uvx is a distinct binary, not a pip/uv variant — it must not collapse.
		{pmUVX, pmUVX},
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
		name string
		pm   string
		args []string
		want bool
	}{
		{"poetry", pmPoetry, []string{"install"}, true},
		{"pipenv", pmPipenv, []string{"install"}, true},
		{"pdm", pmPDM, []string{"install"}, true},
		{"maven", pmMaven, []string{"package"}, true},
		{"gradle", pmGradle, []string{"build"}, true},
		{"pip", pmPip, []string{"install", "requests"}, false},
		// uv persists the configured index URL into uv.lock on every
		// lockfile-writing command (and re-locks when the index differs from the
		// recorded one), so proxying those commands would corrupt the lockfile
		// with the ephemeral 127.0.0.1 proxy address. They take the audit path.
		{"uv no args", pmUV, nil, true},
		{"uv sync", pmUV, []string{"sync"}, true},
		{"uv lock", pmUV, []string{"lock"}, true},
		{"uv add", pmUV, []string{"add", "requests"}, true},
		{"uv run", pmUV, []string{"run", "script.py"}, true},
		// `uv pip` and `uv tool` never touch uv.lock — they keep the proxy.
		{"uv pip install", pmUV, []string{"pip", "install", "requests"}, false},
		{"uv tool run", pmUV, []string{"tool", "run", "ruff"}, false},
		// A global flag before the subcommand may carry a value, so the
		// subcommand is only recognized in first position; fail safe to audit.
		{"uv flag before pip subcommand", pmUV, []string{"--directory", "svc", "pip", "install"}, true},
		// uvx is uv's runner: it has no project lockfile, so it stays on the
		// transparent proxy, never the pre-install lockfile audit.
		{"uvx", pmUVX, []string{"ruff"}, false},
		{"npm", pmNPM, []string{"install"}, false},
		// npx is the npm runner: like npm it uses the transparent proxy, never the
		// pre-install lockfile audit (it has no lockfile of its own).
		{"npx", pmNPX, []string{"cowsay"}, false},
		{"pnpm", pmPNPM, []string{"install"}, false},
		{"bun", pmBun, []string{"install"}, false},
		{"yarn", pmYarn, []string{"install"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requiresPreInstallBlock(tt.pm, tt.args); got != tt.want {
				t.Errorf("requiresPreInstallBlock(%q, %v) = %v, want %v", tt.pm, tt.args, got, tt.want)
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
		// ones (npm/npx/pnpm/bun/yarn/pip/uv) as well as the pre-install ones — so the
		// config "ecosystems" scoping gate can classify any wrapped PM. Pass the
		// canonical name; a versioned pip variant resolves to pip via canonicalPM.
		{pmNPM, supplychain.EcosystemNPM},
		// npx maps to the npm ecosystem so the config "ecosystems" scoping gate
		// treats it exactly like npm (scoping npm in/out includes npx too).
		{pmNPX, supplychain.EcosystemNPM},
		{pmPNPM, supplychain.EcosystemPNPM},
		{pmBun, supplychain.EcosystemBun},
		{pmYarn, supplychain.EcosystemYarn},
		{pmPip, supplychain.EcosystemPip},
		{pmUV, supplychain.EcosystemUV},
		// uvx maps to the uv ecosystem so the config "ecosystems" scoping gate
		// treats it exactly like uv (scoping uv in/out includes uvx too).
		{pmUVX, supplychain.EcosystemUV},
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
		// npx resolves from the npm registry, so it gets the same env override as npm.
		{pmNPX, "npm_config_registry", url},
		{pmPNPM, "npm_config_registry", url},
		{pmBun, "BUN_CONFIG_REGISTRY", url},
		{pmYarn, "YARN_NPM_REGISTRY_SERVER", url},
		// Yarn Berry refuses plain-http registries unless the host is whitelisted
		// (YN0081); without this every wrapped Berry install fails outright.
		{pmYarn, "YARN_UNSAFE_HTTP_WHITELIST", "127.0.0.1"},
		{pmPip, "PIP_INDEX_URL", "http://127.0.0.1:9999/simple/"},
		{pmUV, "UV_INDEX_URL", "http://127.0.0.1:9999/simple/"},
		// uvx shares uv's config, so it gets the same PyPI index override as uv.
		{pmUVX, "UV_INDEX_URL", "http://127.0.0.1:9999/simple/"},
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

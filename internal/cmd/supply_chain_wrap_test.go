package cmd

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestRequiresPreInstallBlock(t *testing.T) {
	tests := []struct {
		pm       string
		expected bool
	}{
		{"mvn", true},
		{"gradle", true},
		{"poetry", true},
		{"pipenv", true},
		{"pdm", true},
		{"npm", false},
		{"pnpm", false},
		{"bun", false},
		{"yarn", false},
		{"pip", false},
		{"pip3", false},
		{"uv", false},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			got := requiresPreInstallBlock(tt.pm)
			if got != tt.expected {
				t.Errorf("requiresPreInstallBlock(%q) = %v, want %v", tt.pm, got, tt.expected)
			}
		})
	}
}

func TestPmToEcosystem(t *testing.T) {
	tests := []struct {
		pm       string
		expected supplychain.Ecosystem
	}{
		{"mvn", supplychain.EcosystemMaven},
		{"gradle", supplychain.EcosystemGradle},
		{"poetry", supplychain.EcosystemPoetry},
		{"pipenv", supplychain.EcosystemPipfile},
		{"pdm", supplychain.EcosystemPDM},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			got := pmToEcosystem(tt.pm)
			if got != tt.expected {
				t.Errorf("pmToEcosystem(%q) = %q, want %q", tt.pm, got, tt.expected)
			}
		})
	}
}

func TestRegistryEnvForPM(t *testing.T) {
	url := "http://127.0.0.1:9999/"

	tests := []struct {
		pm       string
		contains []string
	}{
		{"npm", []string{"npm_config_registry="}},
		{"bun", []string{"npm_config_registry=", "BUN_CONFIG_REGISTRY="}},
		{"yarn", []string{"npm_config_registry=", "YARN_NPM_REGISTRY_SERVER="}},
		{"pip", []string{"PIP_INDEX_URL="}},
		{"pip3", []string{"PIP_INDEX_URL="}},
		{"pip3.11", []string{"PIP_INDEX_URL="}},
		{"uv", []string{"UV_INDEX_URL="}},
	}

	for _, tt := range tests {
		t.Run(tt.pm, func(t *testing.T) {
			envs := registryEnvForPM(tt.pm, url)
			for _, expected := range tt.contains {
				found := false
				for _, env := range envs {
					if len(env) >= len(expected) && env[:len(expected)] == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("registryEnvForPM(%q, ...) missing env containing %q, got %v", tt.pm, expected, envs)
				}
			}
		})
	}
}

func TestCheckGradleStaleness(t *testing.T) {
	// checkGradleStaleness just prints a warning — it doesn't error.
	// This test verifies it doesn't panic on nonexistent paths.
	t.Run("no panic on nonexistent lockfile", func(t *testing.T) {
		checkGradleStaleness("/nonexistent/gradle.lockfile")
	})
}

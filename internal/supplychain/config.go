package supplychain

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ConfigFileName = ".armis-supply-chain.yaml"
	maxConfigSize  = 1 << 20 // 1 MB limit
)

type Config struct {
	Version    int      `yaml:"version,omitempty"`
	MinAge     string   `yaml:"min-age,omitempty"`
	Exclusions []string `yaml:"exclusions,omitempty"`
	FailOpen   bool     `yaml:"fail-open,omitempty"`
}

func LoadConfig(dir string) (*Config, error) {
	// Validate that the config file is within the specified directory
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("invalid config directory: %w", err)
	}
	path := filepath.Join(absDir, ConfigFileName)
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(absDir)) {
		return nil, fmt.Errorf("config file would be outside specified directory")
	}

	f, err := os.Open(path) //nolint:gosec // config file validated above
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", ConfigFileName, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigFileName, err)
	}

	var cfg Config
	// armis:ignore cwe:502 cwe:770 reason:yaml.v3 Unmarshal into a typed struct does not execute code or construct arbitrary types; input is the user's own config file, not untrusted data
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w\n\n  Valid format:\n    version: 1\n    min-age: 72h\n    exclusions:\n      - \"@myorg/*\"\n    fail-open: false", ConfigFileName, err)
	}

	return &cfg, nil
}

func (c *Config) ToPolicy() (Policy, error) {
	policy := DefaultPolicy()

	if c.MinAge != "" {
		d, err := ParseDuration(c.MinAge)
		if err != nil {
			return Policy{}, fmt.Errorf("invalid min-age in %s: %w", ConfigFileName, err)
		}
		policy.MinReleaseAge = d
	}

	if len(c.Exclusions) > 0 {
		policy.Exclusions = c.Exclusions
	}

	policy.FailOpen = c.FailOpen

	return policy, nil
}

// FindConfigDir walks up from startDir looking for a directory that contains
// ConfigFileName, returning that directory (or "" if none is found). startDir is
// resolved to an absolute path first so the upward walk works even when callers
// pass a relative path such as ".".
func FindConfigDir(startDir string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		dir = startDir
	}
	for {
		path := filepath.Join(dir, ConfigFileName)
		if _, err := os.Stat(path); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

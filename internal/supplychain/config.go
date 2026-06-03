package supplychain

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// LoadConfig reads the supply-chain config from dir, returning (nil, nil) when
// the file is absent. dir is the user's own project directory and ConfigFileName
// is a constant literal leaf with no separators or "..", so the joined path always
// resolves to dir/<ConfigFileName> and cannot be steered outside dir.
func LoadConfig(dir string) (*Config, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading its own project config file; ConfigFileName is a constant literal, so the path is not externally controllable across a trust boundary
	path := filepath.Join(dir, ConfigFileName)
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:ConfigFileName is a constant literal; the joined path cannot be steered outside the user's own project dir
	f, err := os.Open(path) //nolint:gosec // config file in project root
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

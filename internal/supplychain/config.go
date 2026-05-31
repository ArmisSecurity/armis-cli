package supplychain

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = ".armis-supply-chain.yaml"

type Config struct {
	Version    int      `yaml:"version,omitempty"`
	MinAge     string   `yaml:"min-age,omitempty"`
	Exclusions []string `yaml:"exclusions,omitempty"`
	Ecosystems []string `yaml:"ecosystems,omitempty"`
	FailOpen   bool     `yaml:"fail-open,omitempty"`
}

func LoadConfig(dir string) (*Config, error) {
	path := filepath.Join(dir, ConfigFileName)
	data, err := os.ReadFile(path) //nolint:gosec // config file in project root
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", ConfigFileName, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w\n\n  Valid format:\n    version: 1\n    min-age: 72h\n    exclusions:\n      - \"@myorg/*\"\n    ecosystems:\n      - npm\n    fail-open: false", ConfigFileName, err)
	}

	return &cfg, nil
}

var knownEcosystems = map[string]bool{
	"npm": true, "pnpm": true, "bun": true, "yarn": true,
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

	for _, eco := range c.Ecosystems {
		if !knownEcosystems[eco] {
			fmt.Fprintf(os.Stderr, "Warning: unknown ecosystem %q in %s — supported: npm, pnpm, bun, yarn\n", eco, ConfigFileName)
		}
	}

	policy.FailOpen = c.FailOpen

	return policy, nil
}

func FindConfigDir(startDir string) string {
	dir := startDir
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

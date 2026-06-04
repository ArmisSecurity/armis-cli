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
	Ecosystems []string `yaml:"ecosystems,omitempty"`
	FailOpen   bool     `yaml:"fail-open,omitempty"`
}

// ecosystemAliasPipenv is the user-facing name for the Pipfile/pipenv ecosystem.
// --help and the generated config call it "pipenv" (the tool name users know),
// while the internal constant is EcosystemPipfile (named after Pipfile.lock).
// Accepting both means copying "pipenv" from the docs never triggers a false
// "unknown ecosystem" warning.
const ecosystemAliasPipenv = "pipenv"

// knownEcosystems is the set of ecosystem names accepted in the config's
// "ecosystems" list, covering every package manager supply-chain supports
// (Node, Python, Java). It backs UnknownEcosystems so a typo in the config
// surfaces as a warning rather than being silently ignored. It is built from the
// typed Ecosystem constants (plus the "pipenv" alias) so the accepted set stays
// in lockstep with detection and there is a single source of truth.
var knownEcosystems = func() map[string]bool {
	m := make(map[string]bool)
	for _, e := range []Ecosystem{
		EcosystemNPM, EcosystemPNPM, EcosystemBun, EcosystemYarn,
		EcosystemPip, EcosystemPoetry, EcosystemPipfile, EcosystemPDM, EcosystemUV,
		EcosystemMaven, EcosystemGradle,
	} {
		m[string(e)] = true
	}
	m[ecosystemAliasPipenv] = true // accept the tool name as an alias for pipfile
	return m
}()

// knownEcosystemsHint is the human-facing "supported" list shown when an unknown
// ecosystem name is found in a config. It leads with "pipenv" (the tool name in
// --help) and omits the "pipfile" alias to keep the guidance aligned with the
// docs; both names are still accepted by knownEcosystems.
const knownEcosystemsHint = "npm, pnpm, bun, yarn, pip, poetry, pipenv, pdm, uv, maven, gradle"

// KnownEcosystemsHint returns the human-facing list of supported ecosystem names
// for use in CLI warnings, so the message stays in sync with knownEcosystems.
func KnownEcosystemsHint() string {
	return knownEcosystemsHint
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

	// Read one byte past the cap so an oversize config is reported clearly
	// instead of being silently truncated and failing as a confusing YAML
	// parse error.
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigFileName, err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("%s too large (max %d bytes)", ConfigFileName, maxConfigSize)
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

// UnknownEcosystems returns the names listed under "ecosystems" in the config
// that are not recognized supply-chain ecosystems, in the order they appear.
// It is pure (no I/O) so callers can decide how to surface the result; the CLI
// emits a warning, while tests assert on the returned slice directly. A typo
// like "pyhton" would otherwise be silently ignored, giving a false sense that
// a policy is scoped when it is not.
func (c *Config) UnknownEcosystems() []string {
	var unknown []string
	for _, eco := range c.Ecosystems {
		if !knownEcosystems[eco] {
			unknown = append(unknown, eco)
		}
	}
	return unknown
}

// EnforcesEcosystem reports whether eco should be enforced under this config.
//
// Semantics, chosen to fail safe for a security control:
//   - A nil config or an empty "ecosystems" list means "enforce every ecosystem"
//     (the default — the field is opt-in scoping, not opt-out).
//   - A list containing at least one recognized ecosystem restricts enforcement
//     to the listed ecosystems only.
//   - A list whose entries are ALL unrecognized (e.g. every name is a typo) is
//     treated as no restriction at all, so a misspelling cannot silently disable
//     the control. The typos are surfaced separately via UnknownEcosystems.
//
// The "pipenv" tool-name alias matches EcosystemPipfile, mirroring the alias
// accepted by knownEcosystems and the generated config.
func (c *Config) EnforcesEcosystem(eco Ecosystem) bool {
	if c == nil {
		return true
	}

	hasKnown := false
	for _, name := range c.Ecosystems {
		if knownEcosystems[name] {
			hasKnown = true
			break
		}
	}
	if !hasKnown {
		return true
	}

	for _, name := range c.Ecosystems {
		if name == string(eco) {
			return true
		}
		if eco == EcosystemPipfile && name == ecosystemAliasPipenv {
			return true
		}
	}
	return false
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

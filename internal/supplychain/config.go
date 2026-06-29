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
	Ecosystems []string `yaml:"ecosystems,omitempty"`
	FailOpen   bool     `yaml:"fail-open,omitempty"`
	// TransitivePolicy is the block/warn knob for young transitive dependencies
	// (WS5). Omitted or unrecognized → block (the secure default); only an
	// explicit "warn" opts a young transitive into pass-with-warning. Direct
	// deps are always blocked regardless. See Config.ToPolicy.
	TransitivePolicy string `yaml:"transitive-policy,omitempty"`

	// Registries maps an ecosystem name (npm, pypi) to the approved
	// artifactory/registry URL for that ecosystem (PPSC-994). When set for an
	// ecosystem, the proxy's upstream points at that URL and the CI check audits
	// against it. v1 recognizes the "npm" and "pypi" keys (see RegistryURLFor);
	// other keys are ignored. Each value is validated by ValidateRegistryURL at
	// config-load — the committed file is a trust boundary, so a non-https or
	// non-routable URL is a hard error, not a best-effort parse.
	Registries map[string]string `yaml:"registries,omitempty"`

	// RegistryEnforcement is the routing-enforcement posture, distinct from the
	// age-policy fail-open. v1 supports only "warn" (and absent, which means
	// warn-disabled). The value "block" is REJECTED at parse with a hard error
	// (UC-1): a CISO who writes "block" and deploys it must not be silently
	// downgraded to a one-line warning, manufacturing false compliance.
	RegistryEnforcement string `yaml:"registry-enforcement,omitempty"`

	// RegistryCABundle is an optional path to a PEM CA bundle used for the
	// proxy→upstream TLS leg (S6). It lets a minimal CI container reach a Nexus
	// fronted by a private/corporate CA without a system trust-store edit. The
	// env var ARMIS_REGISTRY_CA_BUNDLE overrides it. A TLS failure must surface a
	// visible, actionable error — never a silent fail-open enforcement bypass.
	RegistryCABundle string `yaml:"registry-ca-bundle,omitempty"`
}

// Ecosystem keys recognized inside the "registries" map. v1 wires only the npm
// family and PyPI; Maven/Gradle stay on the audit path and are intentionally
// not routable here.
const (
	registryKeyNPM  = "npm"
	registryKeyPyPI = "pypi"
)

// registryEnforcementWarn is the only routing-enforcement posture v1 accepts
// (alongside an absent value). See Config.RegistryEnforcement.
const registryEnforcementWarn = "warn"

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

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate enforces the structural and security invariants on the parsed
// config that must fail loudly at load time rather than degrade silently
// later. Three things are checked, all PPSC-994 launch requirements:
//
//   - registry-enforcement: only "warn" (or absent) is valid in v1. "block" is
//     REJECTED with a hard error (UC-1) — never accepted-and-downgraded to warn,
//     which would manufacture false compliance for a CISO.
//   - each registries.<ecosystem> URL passes ValidateRegistryURL (S1): https
//     only, no embedded credentials, no loopback/RFC1918/link-local host. The
//     committed config is a trust boundary; a bad URL is an SSRF, not a typo.
//   - a PyPI registry URL must expose the PEP 503 "/simple/" index path (DX4),
//     caught here rather than as a confusing 404 at install time.
func (c *Config) validate() error {
	switch c.RegistryEnforcement {
	case "", registryEnforcementWarn:
		// ok: absent or the one supported posture.
	case "block":
		return fmt.Errorf("registry-enforcement: 'block' is not supported in this version; use 'warn'")
	default:
		return fmt.Errorf("registry-enforcement: %q is not valid; use 'warn' (or omit it)", c.RegistryEnforcement)
	}

	for eco, raw := range c.Registries {
		if strings.TrimSpace(raw) == "" {
			continue // an empty value is treated as "not configured", not an error
		}
		u, err := ValidateRegistryURL(raw)
		if err != nil {
			return fmt.Errorf("registries.%s: %w", eco, err)
		}
		if eco == registryKeyPyPI && !strings.Contains(u.Path, "/simple") {
			return fmt.Errorf("registries.pypi: %q should point at the PEP 503 Simple API (a URL containing \"/simple/\", e.g. https://nexus.corp/repository/pypi-group/simple/)", raw)
		}
	}

	return nil
}

// RegistryURLFor returns the configured approved registry URL for an ecosystem,
// or "" when none is set. npm-family ecosystems (npm/pnpm/bun/yarn) all share
// the single "npm" key since they resolve from the same npm-registry protocol;
// the PyPI-family proxied ecosystems (pip/uv) share the "pypi" key. Audit-path
// ecosystems (poetry/pdm/maven/gradle) are not routable in v1 and always return
// "". A nil config returns "".
func (c *Config) RegistryURLFor(eco Ecosystem) string {
	if c == nil || c.Registries == nil {
		return ""
	}
	switch eco {
	case EcosystemNPM, EcosystemPNPM, EcosystemBun, EcosystemYarn:
		return strings.TrimSpace(c.Registries[registryKeyNPM])
	case EcosystemPip, EcosystemUV:
		return strings.TrimSpace(c.Registries[registryKeyPyPI])
	default:
		return ""
	}
}

// HasAnyRegistry reports whether the config sets at least one registries entry.
// It gates the "explicit coverage" honesty rules (E4/DX3): once ANY registry is
// configured, unconfigured ecosystems must be reported as "not configured
// (public)" rather than silently implying coverage.
func (c *Config) HasAnyRegistry() bool {
	if c == nil {
		return false
	}
	for _, raw := range c.Registries {
		if strings.TrimSpace(raw) != "" {
			return true
		}
	}
	return false
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

	// ParseTransitivePolicy fails safe: any value other than an explicit "warn"
	// (including "" and typos) resolves to block, so a misspelled key can never
	// silently open the warn-through path.
	policy.TransitivePolicy = ParseTransitivePolicy(c.TransitivePolicy)

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

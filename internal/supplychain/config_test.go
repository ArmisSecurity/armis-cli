package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Run("file exists", func(t *testing.T) {
		dir := t.TempDir()
		content := `min-age: 7d
exclusions:
  - "@myorg/*"
  - typescript
fail-open: true
`
		os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(content), 0o600) //nolint:errcheck,gosec

		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.MinAge != "7d" {
			t.Errorf("expected min-age=7d, got %s", cfg.MinAge)
		}
		if len(cfg.Exclusions) != 2 {
			t.Errorf("expected 2 exclusions, got %d", len(cfg.Exclusions))
		}
		if !cfg.FailOpen {
			t.Error("expected fail-open=true")
		}
	})

	t.Run("ecosystems field is parsed", func(t *testing.T) {
		dir := t.TempDir()
		content := `min-age: 5d
ecosystems:
  - npm
  - pnpm
`
		os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(content), 0o600) //nolint:errcheck,gosec

		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.MinAge != "5d" {
			t.Errorf("expected min-age=5d, got %s", cfg.MinAge)
		}
		if len(cfg.Ecosystems) != 2 || cfg.Ecosystems[0] != "npm" || cfg.Ecosystems[1] != "pnpm" {
			t.Errorf("expected ecosystems [npm pnpm], got %v", cfg.Ecosystems)
		}
	})

	t.Run("file not found returns nil", func(t *testing.T) {
		dir := t.TempDir()
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg != nil {
			t.Error("expected nil for missing config")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, ConfigFileName), []byte(": bad: yaml: ["), 0o600) //nolint:errcheck,gosec

		_, err := LoadConfig(dir)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})

	t.Run("file too large", func(t *testing.T) {
		// A config larger than maxConfigSize must fail with a clear "too large"
		// error rather than being silently truncated and surfacing as a confusing
		// YAML parse error.
		dir := t.TempDir()
		oversized := make([]byte, maxConfigSize+1)
		for i := range oversized {
			oversized[i] = 'a'
		}
		os.WriteFile(filepath.Join(dir, ConfigFileName), oversized, 0o600) //nolint:errcheck,gosec

		_, err := LoadConfig(dir)
		if err == nil {
			t.Fatal("expected error for oversized config file")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected 'too large' error, got: %v", err)
		}
	})
}

func TestConfigToPolicy(t *testing.T) {
	t.Run("full config", func(t *testing.T) {
		cfg := &Config{
			MinAge:     "5d",
			Exclusions: []string{"@myorg/*", "typescript"},
		}

		policy, err := cfg.ToPolicy()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := 5 * 24 * time.Hour
		if policy.MinReleaseAge != expected {
			t.Errorf("expected %v, got %v", expected, policy.MinReleaseAge)
		}
		if len(policy.Exclusions) != 2 {
			t.Errorf("expected 2 exclusions, got %d", len(policy.Exclusions))
		}
	})

	t.Run("empty config uses defaults", func(t *testing.T) {
		cfg := &Config{}
		policy, err := cfg.ToPolicy()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if policy.MinReleaseAge != 72*time.Hour {
			t.Errorf("expected default 72h, got %v", policy.MinReleaseAge)
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		cfg := &Config{MinAge: "invalid"}
		_, err := cfg.ToPolicy()
		if err == nil {
			t.Error("expected error for invalid duration")
		}
	})
}

func TestFindConfigDir(t *testing.T) {
	t.Run("config in current dir", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, ConfigFileName), []byte("min-age: 3d\n"), 0o600) //nolint:errcheck,gosec

		found := FindConfigDir(dir)
		if found != dir {
			t.Errorf("expected %s, got %s", dir, found)
		}
	})

	t.Run("config in parent dir", func(t *testing.T) {
		parent := t.TempDir()
		child := filepath.Join(parent, "subdir")
		os.MkdirAll(child, 0o750)                                                           //nolint:errcheck,gosec
		os.WriteFile(filepath.Join(parent, ConfigFileName), []byte("min-age: 3d\n"), 0o600) //nolint:errcheck,gosec

		found := FindConfigDir(child)
		if found != parent {
			t.Errorf("expected %s, got %s", parent, found)
		}
	})

	t.Run("no config found", func(t *testing.T) {
		dir := t.TempDir()
		found := FindConfigDir(dir)
		if found != "" {
			t.Errorf("expected empty string, got %s", found)
		}
	})

	t.Run("relative dot resolves and finds parent config", func(t *testing.T) {
		parent := t.TempDir()
		child := filepath.Join(parent, "subdir")
		if err := os.MkdirAll(child, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		os.WriteFile(filepath.Join(parent, ConfigFileName), []byte("min-age: 3d\n"), 0o600) //nolint:errcheck,gosec

		// Run from the child dir using a relative ".": FindConfigDir must resolve
		// to an absolute path so the upward walk actually reaches the parent.
		origWd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		t.Cleanup(func() {
			if cerr := os.Chdir(origWd); cerr != nil {
				t.Errorf("restoring working dir: %v", cerr)
			}
		})
		if err := os.Chdir(child); err != nil {
			t.Fatalf("chdir: %v", err)
		}

		found := FindConfigDir(".")
		// Resolve symlinks (macOS /var -> /private/var) before comparing.
		wantResolved, _ := filepath.EvalSymlinks(parent)
		gotResolved, _ := filepath.EvalSymlinks(found)
		if gotResolved != wantResolved {
			t.Errorf("expected config dir %s, got %s", wantResolved, gotResolved)
		}
	})
}

func TestUnknownEcosystems(t *testing.T) {
	t.Run("all known returns nil", func(t *testing.T) {
		cfg := &Config{Ecosystems: []string{"npm", "pip", "maven", "gradle", "uv"}}
		if got := cfg.UnknownEcosystems(); got != nil {
			t.Errorf("expected nil for all-known ecosystems, got %v", got)
		}
	})

	t.Run("flags unknown names in order", func(t *testing.T) {
		cfg := &Config{Ecosystems: []string{"npm", "pyhton", "cargo", "pip"}}
		got := cfg.UnknownEcosystems()
		want := []string{"pyhton", "cargo"}
		if len(got) != len(want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("at %d: expected %q, got %q", i, want[i], got[i])
			}
		}
	})

	t.Run("empty config returns nil", func(t *testing.T) {
		cfg := &Config{}
		if got := cfg.UnknownEcosystems(); got != nil {
			t.Errorf("expected nil for empty ecosystems, got %v", got)
		}
	})

	t.Run("every supported ecosystem is recognized", func(t *testing.T) {
		all := []string{
			string(EcosystemNPM), string(EcosystemPNPM), string(EcosystemBun), string(EcosystemYarn),
			string(EcosystemPip), string(EcosystemPoetry), string(EcosystemPipfile), string(EcosystemPDM),
			string(EcosystemUV), string(EcosystemMaven), string(EcosystemGradle),
		}
		cfg := &Config{Ecosystems: all}
		if got := cfg.UnknownEcosystems(); got != nil {
			t.Errorf("expected all %d ecosystems recognized, got unknown %v", len(all), got)
		}
	})

	t.Run("pipenv alias is accepted alongside pipfile", func(t *testing.T) {
		// --help and the generated config call this ecosystem "pipenv" (the tool
		// name), while the internal constant is "pipfile". Both must be accepted
		// so copying "pipenv" from the docs never triggers a false typo warning.
		cfg := &Config{Ecosystems: []string{ecosystemAliasPipenv, string(EcosystemPipfile)}}
		if got := cfg.UnknownEcosystems(); got != nil {
			t.Errorf("expected both pipenv and pipfile recognized, got unknown %v", got)
		}
	})
}

func TestEnforcesEcosystem(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		eco  Ecosystem
		want bool
	}{
		// Fail-safe defaults: no scoping means enforce everything.
		{"nil config enforces all", nil, EcosystemNPM, true},
		{"empty list enforces all", &Config{}, EcosystemPip, true},
		{"nil ecosystems slice enforces all", &Config{Ecosystems: nil}, EcosystemMaven, true},

		// Explicit scoping restricts to the listed ecosystems.
		{"listed ecosystem enforced", &Config{Ecosystems: []string{"npm", "pip"}}, EcosystemNPM, true},
		{"unlisted ecosystem not enforced", &Config{Ecosystems: []string{"npm", "pip"}}, EcosystemMaven, false},
		{"single-entry scope excludes others", &Config{Ecosystems: []string{"npm"}}, EcosystemPNPM, false},

		// The pipenv tool-name alias matches the internal pipfile ecosystem.
		{"pipenv alias matches pipfile", &Config{Ecosystems: []string{"pipenv"}}, EcosystemPipfile, true},
		{"pipfile name matches pipfile", &Config{Ecosystems: []string{"pipfile"}}, EcosystemPipfile, true},

		// A list of only-unknown names must NOT silently disable enforcement: a
		// pure typo should fail safe (enforce everything) rather than turn the
		// control off. The typo is surfaced separately via UnknownEcosystems.
		{"all-typo list enforces all (fail safe)", &Config{Ecosystems: []string{"pyhton", "nmp"}}, EcosystemNPM, true},
		// A mix of one valid + one typo restricts to the valid one (the typo is
		// ignored for scoping, still warned about elsewhere).
		{"valid plus typo restricts to valid", &Config{Ecosystems: []string{"npm", "pyhton"}}, EcosystemNPM, true},
		{"valid plus typo excludes unlisted", &Config{Ecosystems: []string{"npm", "pyhton"}}, EcosystemPip, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EnforcesEcosystem(tt.eco); got != tt.want {
				t.Errorf("EnforcesEcosystem(%q) = %v, want %v", tt.eco, got, tt.want)
			}
		})
	}
}

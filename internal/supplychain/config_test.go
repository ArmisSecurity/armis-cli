package supplychain

import (
	"os"
	"path/filepath"
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

	t.Run("unknown fields like ecosystems are ignored", func(t *testing.T) {
		// `ecosystems:` was removed from the schema; an existing config that still
		// carries it must load without error (yaml.v3 ignores unknown keys) so we
		// stay backward-compatible with files written by older versions.
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

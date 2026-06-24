package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func TestConfirm(t *testing.T) {
	// Discard the prompt so its unterminated "Continue? [y/N] " line does not
	// bleed into gotestsum's go-test-json parser and cause false failures.
	originalConfirmOut := confirmOut
	confirmOut = io.Discard
	t.Cleanup(func() { confirmOut = originalConfirmOut })

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"y returns true", "y\n", true},
		{"yes returns true", "yes\n", true},
		{"Y returns true", "Y\n", true},
		{"YES returns true", "YES\n", true},
		{"n returns false", "n\n", false},
		{"no returns false", "no\n", false},
		{"empty returns false", "\n", false},
		{"arbitrary text returns false", "maybe\n", false},
		{"whitespace y returns true", "  y  \n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.WriteString(tt.input)
			_ = w.Close()

			oldStdin := os.Stdin
			os.Stdin = r
			t.Cleanup(func() {
				os.Stdin = oldStdin
				_ = r.Close()
			})

			got := confirm("Continue?")
			if got != tt.want {
				t.Errorf("confirm() with input %q = %v, want %v", tt.input, got, tt.want)
			}
		})
	}

	t.Run("EOF returns false", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		oldStdin := os.Stdin
		os.Stdin = r
		t.Cleanup(func() {
			os.Stdin = oldStdin
			_ = r.Close()
		})

		if confirm("Continue?") {
			t.Error("confirm() should return false on EOF")
		}
	})
}

func TestUninstallTargets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}

	u := install.NewUninstaller()

	t.Run("advisory editors do not error", func(t *testing.T) {
		advisoryEditors := []string{"jetbrains", "devin", "openhands", "aider"}
		for _, name := range advisoryEditors {
			if err := uninstallTargets(u, []string{name}); err != nil {
				t.Errorf("uninstallTargets(%q) unexpected error: %v", name, err)
			}
		}
	})

	t.Run("unknown editor prints warning without error", func(t *testing.T) {
		err := uninstallTargets(u, []string{"nonexistent-editor"})
		if err != nil {
			t.Errorf("uninstallTargets(unknown) unexpected error: %v", err)
		}
	})

	t.Run("copilot maps to copilot cli", func(t *testing.T) {
		err := uninstallTargets(u, []string{"copilot"})
		if err != nil {
			t.Errorf("uninstallTargets(copilot) unexpected error: %v", err)
		}
	})
}

func TestUninstallAllForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("CLIENT_ID=test"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("force skips confirmation and removes files", func(t *testing.T) {
		u := install.NewUninstaller()
		err := uninstallAll(u, false, true)
		if err != nil {
			t.Errorf("uninstallAll(force=true) unexpected error: %v", err)
		}
	})

	t.Run("keep-credentials preserves env file", func(t *testing.T) {
		if err := os.MkdirAll(pluginDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("CLIENT_ID=test"), 0o600); err != nil {
			t.Fatal(err)
		}

		u := install.NewUninstaller()
		err := uninstallAll(u, true, true)
		if err != nil {
			t.Errorf("uninstallAll(keepCreds=true, force=true) unexpected error: %v", err)
		}
	})
}

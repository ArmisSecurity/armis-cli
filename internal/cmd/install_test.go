package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func TestInstallTargetsUnknownEditor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	err := installTargets([]string{"nonexistent-editor"}, false)
	if err == nil {
		t.Fatal("expected error for unknown editor")
	}
	if got := err.Error(); got == "" {
		t.Error("error message should not be empty")
	}
}

func TestInstallTargetsAdvisoryEditors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	advisoryEditors := []string{"jetbrains", "devin", "openhands", "aider"}
	for _, name := range advisoryEditors {
		t.Run(name, func(t *testing.T) {
			err := installTargets([]string{name}, false)
			if err != nil {
				t.Errorf("installTargets(%q) unexpected error: %v", name, err)
			}
		})
	}
}

// TestInstallTargetsJetBrainsNoGhostFlag verifies fix #2: the JetBrains advisory
// must not reference the nonexistent --jetbrains-project flag (which errors with
// "unknown flag"), and should give accurate manual setup guidance instead.
func TestInstallTargetsJetBrainsNoGhostFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	installErr := installTargets([]string{"jetbrains"}, false)
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()

	if installErr != nil {
		t.Errorf("installTargets(jetbrains) unexpected error: %v", installErr)
	}
	output := string(out)
	if strings.Contains(output, "--jetbrains-project") {
		t.Errorf("JetBrains guidance must not mention the ghost flag --jetbrains-project, got:\n%s", output)
	}
	if !strings.Contains(output, ".jb-mcp.json") {
		t.Errorf("JetBrains guidance should mention the .jb-mcp.json config file, got:\n%s", output)
	}
}

func TestShowInstalledVersionsNoVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// Create .claude dir so NewClaudeInstaller doesn't error on its own
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(filepath.Join(claudeDir, "plugins"), 0o750); err != nil {
		t.Fatal(err)
	}

	err := showInstalledVersions()
	if err == nil {
		t.Fatal("expected error when no version installed")
	}
}

func TestShowInstalledVersionsWithMCPVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// Stage an .installed-version file in the expected plugin dir
	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".installed-version"), []byte("1.5.0"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create .claude dir so NewClaudeInstaller doesn't error
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(filepath.Join(claudeDir, "plugins"), 0o750); err != nil {
		t.Fatal(err)
	}

	err := showInstalledVersions()
	if err != nil {
		t.Errorf("showInstalledVersions() unexpected error: %v", err)
	}
}

func TestPrintCredentialStatusWithEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("CLIENT_ID=test"), 0o600); err != nil {
		t.Fatal(err)
	}

	ei := install.NewEditorInstaller()
	printCredentialStatus(ei)
}

func TestPrintCredentialStatusWithoutEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}

	ei := install.NewEditorInstaller()
	printCredentialStatus(ei)
}

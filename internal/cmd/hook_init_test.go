package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

// newHookInitTestCmd builds a bare command exposing the two flags runHookInit
// reads (--remove, --fail-open), mirroring hookInitCmd's flag set without
// touching shared command state.
func newHookInitTestCmd() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().Bool("fail-open", false, "")
	c.Flags().Bool("remove", false, "")
	return c
}

// TestRunHookInit_NoPluginInstallsFallback is the regression test for the
// PPSC-1009 P0: hook init used to hard-error when the MCP plugin was absent,
// even though the install layer falls back to a direct-scan hook. With the gate
// removed, hook init must succeed with no plugin present and write the fallback.
func TestRunHookInit_NoPluginInstallsFallback(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Point HOME at an empty dir so NewEditorInstaller().PluginDir() resolves to
	// a non-existent path — the exact condition that used to trigger the gate.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// runHookInit detects the repo from the process cwd, so work inside a real
	// git repo. chdirTemp restores the original cwd on cleanup.
	dir := chdirTemp(t)
	if err := runTestGitCmd(dir, "init"); err != nil {
		t.Fatalf("git init: %v", err)
	}

	if err := runHookInit(newHookInitTestCmd(), nil); err != nil {
		t.Fatalf("runHookInit() with no plugin should succeed, got: %v", err)
	}

	// Resolve the hook path through the same logic the installer uses
	// (git rev-parse --git-path hooks), rather than hard-coding
	// <repo>/.git/hooks/pre-commit — that would break under a custom
	// core.hooksPath, worktrees, or submodules.
	hookPath, err := install.PreCommitHookPath(dir)
	if err != nil {
		t.Fatalf("resolving hook path: %v", err)
	}
	data, err := os.ReadFile(hookPath) //nolint:gosec // G304: path resolved via git under t.TempDir()
	if err != nil {
		t.Fatalf("reading installed hook: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "armis-cli scan repo") {
		t.Errorf("expected direct-scan fallback hook, got:\n%s", content)
	}
	if !strings.Contains(content, "--changed=staged") {
		t.Errorf("expected fallback to scan staged changes, got:\n%s", content)
	}
}

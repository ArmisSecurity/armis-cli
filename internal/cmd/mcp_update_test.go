package cmd

import (
	"strings"
	"testing"
)

// TestRunMCPUpdateNoManifest pins the guard that stops runMCPUpdate before it
// ever calls FetchPlugin (a real network call) when nothing is installed yet.
func TestRunMCPUpdateNoManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	err := runMCPUpdate(mcpUpdateCmd, nil)
	if err == nil {
		t.Fatal("expected error when no manifest is present")
	}
	if !strings.Contains(err.Error(), "armis-cli install") {
		t.Errorf("error should point at 'armis-cli install', got: %v", err)
	}
}

func TestMCPUpdateHasForceFlag(t *testing.T) {
	f := mcpUpdateCmd.Flags().Lookup("force")
	if f == nil {
		t.Fatal("mcp update command is missing the --force flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--force default = %q, want false", f.DefValue)
	}
}

func TestMCPUpdateHasWithKnowledgeFlag(t *testing.T) {
	f := mcpUpdateCmd.Flags().Lookup("with-knowledge")
	if f == nil {
		t.Fatal("mcp update command is missing the --with-knowledge flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--with-knowledge default = %q, want false (only auto-enabled via the manifest)", f.DefValue)
	}
}

func TestMCPUpdateRegisteredUnderMCPCommand(t *testing.T) {
	for _, c := range mcpCmd.Commands() {
		if c.Name() == "update" {
			return
		}
	}
	t.Fatal("'update' is not registered under the 'mcp' command")
}

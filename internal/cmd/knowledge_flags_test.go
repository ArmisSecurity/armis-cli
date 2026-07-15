package cmd

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("setting --%s=%s: %v", name, value, err)
	}
}

func TestParseKnowledgeVariant(t *testing.T) {
	cases := []struct {
		in      string
		want    install.KnowledgeVariant
		wantErr bool
	}{
		{"skills", install.KnowledgeVariantSkills, false},
		{"mcp", install.KnowledgeVariantMCP, false},
		{"", "", true},
		{"MCP", "", true}, // case-sensitive by design
		{"bogus", "", true},
	}
	for _, tc := range cases {
		got, err := parseKnowledgeVariant(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseKnowledgeVariant(%q) err = nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKnowledgeVariant(%q) unexpected err: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseKnowledgeVariant(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKnowledgeEnvForDev(t *testing.T) {
	if got := knowledgeEnvForDev(false); got != install.KnowledgeEnvProd {
		t.Errorf("knowledgeEnvForDev(false) = %q, want prod", got)
	}
	if got := knowledgeEnvForDev(true); got != install.KnowledgeEnvDev {
		t.Errorf("knowledgeEnvForDev(true) = %q, want dev", got)
	}
}

// The install/uninstall knowledge commands must reject an unknown --variant
// before doing any work (the flag contract), for both subcommands.
func TestKnowledgeCmd_RejectsUnknownVariant(t *testing.T) {
	for _, run := range []struct {
		name string
		fn   func() error
	}{
		{"install", func() error {
			mustSetFlag(t, installKnowledgeCmd, "variant", "bogus")
			defer mustSetFlag(t, installKnowledgeCmd, "variant", "skills")
			return runInstallKnowledge(installKnowledgeCmd, nil)
		}},
		{"uninstall", func() error {
			mustSetFlag(t, uninstallKnowledgeCmd, "variant", "bogus")
			defer mustSetFlag(t, uninstallKnowledgeCmd, "variant", "skills")
			return runUninstallKnowledge(uninstallKnowledgeCmd, nil)
		}},
	} {
		t.Run(run.name, func(t *testing.T) {
			err := run.fn()
			if err == nil {
				t.Fatalf("%s knowledge with --variant=bogus: err = nil, want error", run.name)
			}
			if got := err.Error(); got == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

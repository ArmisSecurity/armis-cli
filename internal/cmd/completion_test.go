package cmd

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/spf13/cobra"
)

// stripDesc returns the candidate value with any "\tdescription" hint removed.
// Cobra encodes a completion as "value\tDescription"; only the value before the
// tab is what the shell inserts.
func stripDesc(completion string) string {
	if i := strings.IndexByte(completion, '\t'); i >= 0 {
		return completion[:i]
	}
	return completion
}

// runFlagCompletion looks up the completion func registered on cmd for flagName,
// invokes it, and returns the bare candidate values and the directive.
func runFlagCompletion(t *testing.T, cmd *cobra.Command, flagName string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	fn, ok := cmd.GetFlagCompletionFunc(flagName)
	if !ok || fn == nil {
		t.Fatalf("no completion func registered for --%s", flagName)
	}
	raw, directive := fn(cmd, nil, "")
	values := make([]string, 0, len(raw))
	for _, c := range raw {
		values = append(values, stripDesc(c))
	}
	return values, directive
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFlagCompletionsMatchValidators is the core guarantee: every registered
// completion offers exactly the values its validator accepts, in order, and
// suppresses file completion. If a validator's value list changes, this test
// fails unless the completion is updated to match.
func TestFlagCompletionsMatchValidators(t *testing.T) {
	tests := []struct {
		name     string
		cmd      *cobra.Command
		flag     string
		expected []string
	}{
		// --format/--fail-on were relocated from rootCmd to scanCmd (PPSC-1009),
		// and supply-chain check re-registers its own instances (distinct flag
		// pointers), so both registration sites are asserted here.
		{"format", scanCmd, "format", validFormats},
		{"fail-on", scanCmd, "fail-on", cmdutil.ValidSeverities},
		{"sc-check format", scCheckCmd, "format", validFormats},
		{"sc-check fail-on", scCheckCmd, "fail-on", cmdutil.ValidSeverities},
		{"color", rootCmd, "color", []string{string(cli.ColorModeAuto), string(cli.ColorModeAlways), string(cli.ColorModeNever)}},
		{"theme", rootCmd, "theme", []string{themeAuto, themeDark, themeLight}},
		{"group-by", scanCmd, "group-by", validGroupBy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, directive := runFlagCompletion(t, tt.cmd, tt.flag)
			if !equalSlices(values, tt.expected) {
				t.Errorf("--%s completions = %v, want %v", tt.flag, values, tt.expected)
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Errorf("--%s directive = %d, want ShellCompDirectiveNoFileComp (%d)",
					tt.flag, directive, cobra.ShellCompDirectiveNoFileComp)
			}
		})
	}
}

// TestFlagCompletionsHaveDescriptions verifies the candidates carry the "\thint"
// suffix that zsh/fish render, matching the established supply-chain pattern.
func TestFlagCompletionsHaveDescriptions(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
		flag string
	}{
		{"format", scanCmd, "format"},
		{"fail-on", scanCmd, "fail-on"},
		{"sc-check format", scCheckCmd, "format"},
		{"sc-check fail-on", scCheckCmd, "fail-on"},
		{"color", rootCmd, "color"},
		{"theme", rootCmd, "theme"},
		{"group-by", scanCmd, "group-by"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, ok := tt.cmd.GetFlagCompletionFunc(tt.flag)
			if !ok || fn == nil {
				t.Fatalf("no completion func registered for --%s", tt.flag)
			}
			raw, _ := fn(tt.cmd, nil, "")
			if len(raw) == 0 {
				t.Fatalf("--%s produced no completions", tt.flag)
			}
			for _, c := range raw {
				if !strings.Contains(c, "\t") {
					t.Errorf("--%s completion %q is missing a \\tdescription hint", tt.flag, c)
				}
			}
		})
	}
}

// TestFixedCompletions exercises the helper directly, including the fallback for
// values that have no description entry.
func TestFixedCompletions(t *testing.T) {
	t.Run("attaches descriptions in order", func(t *testing.T) {
		fn := fixedCompletions([]string{"a", "b"}, map[string]string{
			"a": "first",
			"b": "second",
		})
		got, directive := fn(nil, nil, "")
		want := []cobra.Completion{"a\tfirst", "b\tsecond"}
		if !equalSlices(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("directive = %d, want %d", directive, cobra.ShellCompDirectiveNoFileComp)
		}
	})

	t.Run("falls back to bare value when no description", func(t *testing.T) {
		fn := fixedCompletions([]string{"a", "b"}, map[string]string{"a": "first"})
		got, _ := fn(nil, nil, "")
		if got[1] != "b" {
			t.Errorf("undescribed value = %q, want bare %q", got[1], "b")
		}
		if strings.Contains(got[1], "\t") {
			t.Errorf("undescribed value %q should not carry a tab", got[1])
		}
	})
}

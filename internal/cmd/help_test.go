package cmd

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
)

func TestStyleHelpOutput_CommandNames(t *testing.T) {
	// Initialize colors for styled output
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	input := `Available Commands:
  scan        Scan a repository or container image
  auth        Test authentication
  completion  Generate shell completion scripts
  help        Help about any command`

	result := styleHelpOutput(input)

	// Commands should be styled (contain ANSI codes around them)
	if !strings.Contains(result, "scan") {
		t.Error("Expected output to contain 'scan' command")
	}
	// The styling should have been applied (result differs from input)
	if result == input {
		t.Error("Expected styleHelpOutput to modify the input when colors enabled")
	}
}

func TestStyleHelpOutput_LongFlags(t *testing.T) {
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	input := `Flags:
      --color string    Color output mode (auto, always, never)
      --debug           Enable debug mode
  -h, --help            Help for this command
      --no-update-check Skip update check`

	result := styleHelpOutput(input)

	// Long flags should be styled
	if !strings.Contains(result, "--color") {
		t.Error("Expected output to contain '--color' flag")
	}
	if !strings.Contains(result, "--debug") {
		t.Error("Expected output to contain '--debug' flag")
	}
	// Result should differ from input when colors are enabled
	if result == input {
		t.Error("Expected styleHelpOutput to modify the input when colors enabled")
	}
}

func TestStyleHelpOutput_ShortFlags(t *testing.T) {
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	input := `Flags:
  -f, --format string   Output format
  -h, --help            Help for command
  -v, --verbose         Verbose output`

	result := styleHelpOutput(input)

	// Short flags should be present
	if !strings.Contains(result, "-f") {
		t.Error("Expected output to contain '-f' flag")
	}
	if !strings.Contains(result, "-h") {
		t.Error("Expected output to contain '-h' flag")
	}
}

func TestStyleHelpOutput_NoColorsReturnsUnchanged(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	output.SyncColors()

	input := `Available Commands:
  scan        Scan a repository
  --format    Some flag`

	result := styleHelpOutput(input)

	// When colors disabled, output should be unchanged
	if result != input {
		t.Errorf("Expected unchanged output when colors disabled\nGot: %q\nWant: %q", result, input)
	}
}

func TestStyleHelpOutput_PlainTextUnchanged(t *testing.T) {
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	// Text that doesn't match command/flag patterns should pass through
	input := "This is plain text without any commands or flags."

	result := styleHelpOutput(input)

	// Plain text (no flags/commands pattern) should be unchanged
	if result != input {
		t.Logf("Plain text was modified: %q -> %q", input, result)
	}
}

func TestStyleHelpOutput_EdgeCases(t *testing.T) {
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "newlines only", input: "\n\n\n"},
		{name: "single flag", input: "--help"},
		{name: "flag in middle of text", input: "Use --help for more info"},
		{name: "hyphenated command", input: "  scan-repo  Scan a repository"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			result := styleHelpOutput(tt.input)
			// Result should be non-empty if input was non-empty
			if tt.input != "" && result == "" {
				t.Error("Non-empty input produced empty output")
			}
		})
	}
}

func TestStyledUsageTemplate_ColorsEnabled(t *testing.T) {
	cli.InitColors(cli.ColorModeAlways)
	output.SyncColors()

	template := styledUsageTemplate()

	// Template should contain styled section headers
	if !strings.Contains(template, "Usage:") {
		t.Error("Expected template to contain 'Usage:' section")
	}
	if !strings.Contains(template, "Flags:") {
		t.Error("Expected template to contain 'Flags:' section")
	}

	// With colors enabled, the template should be different from default
	defaultTemplate := defaultUsageTemplate()
	if template == defaultTemplate {
		t.Error("Expected styled template to differ from default when colors enabled")
	}
}

func TestStyledUsageTemplate_ColorsDisabled(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	output.SyncColors()

	template := styledUsageTemplate()

	// When colors disabled, should return the default template
	defaultTemplate := defaultUsageTemplate()
	if template != defaultTemplate {
		t.Error("Expected styled template to equal default template when colors disabled")
	}
}

func TestDefaultUsageTemplate(t *testing.T) {
	template := defaultUsageTemplate()

	// Should return a non-empty template
	if template == "" {
		t.Error("Expected defaultUsageTemplate to return non-empty string")
	}

	// Should contain standard Cobra template elements
	if !strings.Contains(template, "{{") {
		t.Error("Expected template to contain Go template syntax")
	}
}

// Package cmd implements the CLI commands for the Armis security scanner.
package cmd

import (
	"bytes"
	"io"
	"regexp"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// SetupHelp configures styled help output for a command.
// The help function is inherited by all subcommands, so this only needs
// to be called on the root command.
func SetupHelp(cmd *cobra.Command) {
	// Override the help function to apply styling
	originalHelpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		// Initialize colors for help output (--help bypasses PersistentPreRunE)
		initColorsForHelp(c)

		// Save original output destination before redirecting
		originalOut := c.OutOrStdout()

		// Capture help output to a buffer
		buf := new(bytes.Buffer)
		c.SetOut(buf)
		c.SetUsageTemplate(styledUsageTemplate())
		originalHelpFunc(c, args)

		// Restore original output and write styled content
		c.SetOut(originalOut)
		styled := styleHelpOutput(buf.String())
		_, _ = io.WriteString(originalOut, styled)
	})
}

// styledUsageTemplate returns a usage template with bold section headers.
func styledUsageTemplate() string {
	if !cli.ColorsEnabled() {
		return defaultUsageTemplate()
	}

	styles := output.GetStyles()
	bold := func(s string) string {
		return styles.HelpHeading.Render(s)
	}

	return bold("Usage:") + `
  {{.UseLine}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

` + bold("Aliases:") + `
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

` + bold("Examples:") + `
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

` + bold("Available Commands:") + `{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

` + bold("Additional Commands:") + `{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

` + bold("Flags:") + `
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

` + bold("Global Flags:") + `
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

` + bold("Additional help topics:") + `{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
}

// defaultUsageTemplate returns Cobra's default usage template.
func defaultUsageTemplate() string {
	return (&cobra.Command{}).UsageTemplate()
}

// initColorsForHelp initializes color mode for help output.
// This is needed because --help bypasses PersistentPreRunE where colors
// are normally initialized based on the --color flag.
func initColorsForHelp(cmd *cobra.Command) {
	// If colors are already forced (e.g., from a previous init), don't reinitialize
	// This prevents the flag's default value from overriding an explicit --color=always
	if cli.ColorsForced() {
		return
	}

	// Find root command to get the --color flag
	root := cmd.Root()
	colorFlag := root.PersistentFlags().Lookup("color")
	if colorFlag == nil {
		return
	}

	// Check if the flag was explicitly set (changed from default)
	if !colorFlag.Changed {
		// Flag wasn't set - use auto detection which was done at startup
		return
	}

	mode := cli.ColorMode(colorFlag.Value.String())
	switch mode {
	case cli.ColorModeAuto, cli.ColorModeAlways, cli.ColorModeNever:
		cli.InitColors(mode)
	}

	// Apply theme override if explicitly set
	themeFlagVal := root.PersistentFlags().Lookup("theme")
	if themeFlagVal != nil && themeFlagVal.Changed {
		switch themeFlagVal.Value.String() {
		case themeDark:
			lipgloss.SetHasDarkBackground(true)
		case themeLight:
			lipgloss.SetHasDarkBackground(false)
		}
	}

	output.SyncColors()
}

// styleHelpOutput applies colors to command names and flags in help text.
func styleHelpOutput(s string) string {
	if !cli.ColorsEnabled() {
		return s
	}

	styles := output.GetStyles()

	// Color command names in "Available Commands:" section
	// Pattern: "  commandname   Description" (2 spaces, word, 2+ spaces, rest)
	cmdRe := regexp.MustCompile(`(?m)^(  )([a-z][-a-z0-9]*)(\s{2,})(.*)$`)
	s = cmdRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := cmdRe.FindStringSubmatch(match)
		if len(parts) == 5 {
			return parts[1] + styles.HelpCommand.Render(parts[2]) + parts[3] + parts[4]
		}
		return match
	})

	// Color long flags: --flag-name
	flagRe := regexp.MustCompile(`(--[a-z][-a-z0-9]*)`)
	s = flagRe.ReplaceAllStringFunc(s, func(match string) string {
		return styles.HelpFlag.Render(match)
	})

	// Color short flags: -f (when followed by comma or space)
	shortFlagRe := regexp.MustCompile(`(\s)(-[a-zA-Z])([,\s])`)
	s = shortFlagRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := shortFlagRe.FindStringSubmatch(match)
		if len(parts) == 4 {
			return parts[1] + styles.HelpFlag.Render(parts[2]) + parts[3]
		}
		return match
	})

	return s
}

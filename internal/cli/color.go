// Package cli provides CLI utilities including colored output with TTY detection.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// ColorMode represents the color output strategy.
type ColorMode string

const (
	ColorModeAuto   ColorMode = "auto"
	ColorModeAlways ColorMode = "always"
	ColorModeNever  ColorMode = "never"
)

// Tailwind color palette (matching output/styles.go for consistency)
// AdaptiveColor automatically selects Light/Dark variant based on terminal background
var (
	colorErrorFg   = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#EF4444"} // red-600 / red-500
	colorWarningFg = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#F59E0B"} // amber-600 / amber-500
	colorMuted     = lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#6B7280"} // gray-600 / gray-500
)

// Lipgloss styles for error/warning labels
var (
	errorLabelStyle   lipgloss.Style
	warningLabelStyle lipgloss.Style
	mutedStyle        lipgloss.Style
)

// colorsEnabled tracks whether colors are currently active.
var colorsEnabled = true

// colorsForced tracks whether colors are forced via --color=always.
var colorsForced = false

// InitColors resolves the final color state based on the --color flag value,
// the NO_COLOR env var, and TTY detection. This should be called after flag parsing.
//
// Precedence:
//  1. --color=always -> colors ON (overrides everything, including NO_COLOR)
//  2. --color=never  -> colors OFF
//  3. NO_COLOR env   -> colors OFF (takes precedence over auto)
//  4. TERM=dumb      -> colors OFF
//  5. --color=auto   -> detect TTY on stderr
func InitColors(mode ColorMode) {
	// Reset colorsForced - only ColorModeAlways sets it to true
	colorsForced = false

	switch mode {
	case ColorModeAlways:
		colorsForced = true
		enableColors()
	case ColorModeNever:
		disableColors()
	case ColorModeAuto:
		if os.Getenv("NO_COLOR") != "" {
			disableColors()
			return
		}
		if strings.Contains(strings.ToLower(os.Getenv("TERM")), "dumb") {
			disableColors()
			return
		}
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			disableColors()
			return
		}
		enableColors()
	}
}

// ColorsEnabled returns whether colors are currently enabled.
func ColorsEnabled() bool {
	return colorsEnabled
}

// ColorsForced returns whether colors are forced via --color=always.
// When true, the color profile should be set to TrueColor regardless of TTY detection.
func ColorsForced() bool {
	return colorsForced
}

func enableColors() {
	colorsEnabled = true
	errorLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(colorErrorFg)
	warningLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(colorWarningFg)
	mutedStyle = lipgloss.NewStyle().Foreground(colorMuted)
}

func disableColors() {
	colorsEnabled = false
	errorLabelStyle = lipgloss.NewStyle()
	warningLabelStyle = lipgloss.NewStyle()
	mutedStyle = lipgloss.NewStyle()
}

// parseErrorMessage extracts a human-readable reason from an error string.
// It looks for JSON {"detail":"..."} payloads common in API error responses.
// Returns (reason, context) where reason is the primary message and context
// is the supplementary error chain (shown muted).
func parseErrorMessage(msg string) (reason, context string) {
	// Try to find and extract JSON detail from the end of the message
	if idx := strings.LastIndex(msg, "{"); idx >= 0 {
		jsonPart := msg[idx:]
		var parsed struct {
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal([]byte(jsonPart), &parsed); err == nil && parsed.Detail != "" {
			reason = parsed.Detail
			// Build context from the chain before the JSON
			chain := strings.TrimSpace(msg[:idx])
			chain = strings.TrimSuffix(chain, ":")
			chain = strings.TrimSpace(chain)
			if chain != "" {
				context = chain
			}
			return reason, context
		}
	}

	// No JSON found - return as-is
	return msg, ""
}

// PrintError writes a colored error message to stderr.
// For API errors with JSON {"detail":"..."}, shows the detail prominently
// with the error chain context displayed below in muted style.
func PrintError(msg string) {
	reason, context := parseErrorMessage(msg)
	fmt.Fprintf(os.Stderr, "%s %s\n", errorLabelStyle.Render("Error:"), reason)
	if context != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", mutedStyle.Render(context))
	}
}

// PrintErrorf is like PrintError but with fmt.Sprintf formatting.
func PrintErrorf(format string, args ...interface{}) {
	PrintError(fmt.Sprintf(format, args...))
}

// PrintWarning writes a colored warning message to stderr.
// Format: "Warning: <message>\n"
func PrintWarning(msg string) {
	fmt.Fprintf(os.Stderr, "%s %s\n", warningLabelStyle.Render("Warning:"), msg)
}

// PrintWarningf is like PrintWarning but with fmt.Sprintf formatting.
func PrintWarningf(format string, args ...interface{}) {
	PrintWarning(fmt.Sprintf(format, args...))
}

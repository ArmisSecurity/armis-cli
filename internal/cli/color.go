// Package cli provides CLI utilities including colored output with TTY detection.
package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ColorMode represents the color output strategy.
type ColorMode string

const (
	ColorModeAuto   ColorMode = "auto"
	ColorModeAlways ColorMode = "always"
	ColorModeNever  ColorMode = "never"
)

// ANSI color codes
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[93m"
	colorBold   = "\033[1m"
)

// colorsEnabled tracks whether colors are currently active.
var colorsEnabled = true

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
	switch mode {
	case ColorModeAlways:
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

func enableColors() {
	colorsEnabled = true
	colorReset = "\033[0m"
	colorRed = "\033[31m"
	colorYellow = "\033[93m"
	colorBold = "\033[1m"
}

func disableColors() {
	colorsEnabled = false
	colorReset = ""
	colorRed = ""
	colorYellow = ""
	colorBold = ""
}

// PrintError writes a colored error message to stderr.
// Format: "Error: <message>\n"
func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "%s%sError:%s %s\n", colorBold, colorRed, colorReset, msg)
}

// PrintErrorf is like PrintError but with fmt.Sprintf formatting.
func PrintErrorf(format string, args ...interface{}) {
	PrintError(fmt.Sprintf(format, args...))
}

// PrintWarning writes a colored warning message to stderr.
// Format: "Warning: <message>\n"
func PrintWarning(msg string) {
	fmt.Fprintf(os.Stderr, "%s%sWarning:%s %s\n", colorBold, colorYellow, colorReset, msg)
}

// PrintWarningf is like PrintWarning but with fmt.Sprintf formatting.
func PrintWarningf(format string, args ...interface{}) {
	PrintWarning(fmt.Sprintf(format, args...))
}

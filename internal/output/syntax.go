// Package output provides formatters for scan results.
package output

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// GetLexer returns the appropriate chroma lexer for a filename.
// Falls back to plaintext if the language cannot be detected.
func GetLexer(filename string) chroma.Lexer {
	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Fallback
	}
	// Coalesce merges adjacent tokens of the same type for cleaner output
	return chroma.Coalesce(lexer)
}

// GetChromaStyle returns the chroma style based on terminal theme settings.
// Returns nil when colors are disabled.
func GetChromaStyle() *chroma.Style {
	if !cli.ColorsEnabled() {
		return nil
	}
	if lipgloss.HasDarkBackground() {
		return styles.Get("monokai")
	}
	return styles.Get("github")
}

// HighlightCode tokenizes and highlights code, returning lines with ANSI formatting.
// Each line is separately formatted for line-level control.
// Returns plain lines if colors are disabled or highlighting fails.
func HighlightCode(code, filename string) []string {
	style := GetChromaStyle()
	if style == nil {
		// No colors - return plain lines
		return strings.Split(code, "\n")
	}

	lexer := GetLexer(filename)
	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return strings.Split(code, "\n")
	}

	// Get formatter based on terminal color support
	formatter := getTerminalFormatter()

	// Format all tokens
	var buf bytes.Buffer
	err = formatter.Format(&buf, style, iterator)
	if err != nil {
		return strings.Split(code, "\n")
	}

	return strings.Split(buf.String(), "\n")
}

// HighlightLine highlights a single line of code.
// This is useful for re-highlighting truncated lines.
func HighlightLine(line, filename string) string {
	lines := HighlightCode(line, filename)
	if len(lines) > 0 {
		return lines[0]
	}
	return line
}

// getTerminalFormatter returns the appropriate chroma formatter for terminal color depth.
func getTerminalFormatter() chroma.Formatter {
	profile := lipgloss.ColorProfile()
	switch profile {
	case termenv.TrueColor:
		return formatters.Get("terminal16m")
	case termenv.ANSI256:
		return formatters.Get("terminal256")
	default:
		return formatters.Get("terminal")
	}
}

// HighlightLineWithBackground applies syntax highlighting with a persistent background color.
// This handles Chroma's ANSI resets that would otherwise clear the background.
// The bgColor should be a lipgloss.AdaptiveColor for automatic light/dark theme support.
func HighlightLineWithBackground(line, filename string, bgColor lipgloss.AdaptiveColor) string {
	highlighted := HighlightLine(line, filename)
	if !cli.ColorsEnabled() {
		return highlighted
	}

	// Get the ANSI escape code for background color
	bgANSI := getBackgroundANSI(bgColor)
	if bgANSI == "" {
		return highlighted
	}

	// Replace all full resets with reset+background to maintain background through tokens
	// \x1b[0m -> \x1b[0m{bgANSI}
	result := strings.ReplaceAll(highlighted, "\x1b[0m", "\x1b[0m"+bgANSI)

	// Wrap: start with bg, end with full reset
	return bgANSI + result + "\x1b[0m"
}

// getBackgroundANSI returns the ANSI escape code for a background color.
// Adapts to terminal color capability (TrueColor, ANSI256, or basic).
// Returns empty string if color cannot be parsed or terminal doesn't support colors.
func getBackgroundANSI(color lipgloss.AdaptiveColor) string {
	// Resolve color based on theme
	c := color.Dark
	if !lipgloss.HasDarkBackground() {
		c = color.Light
	}

	// Parse hex color
	r, g, b, ok := parseHexColor(c)
	if !ok {
		return ""
	}

	// Adapt to terminal color capability (consistent with getTerminalFormatter)
	profile := lipgloss.ColorProfile()
	switch profile {
	case termenv.TrueColor:
		// 24-bit color: 48;2;R;G;B
		return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)
	case termenv.ANSI256:
		// Convert to nearest 256-color palette index
		idx := rgbToANSI256(r, g, b)
		return fmt.Sprintf("\x1b[48;5;%dm", idx)
	default:
		// Basic 16-color terminals: use nearest standard color
		// For vulnerability highlighting background, use red (41) as fallback
		return "\x1b[41m"
	}
}

// rgbToANSI256 converts RGB values to the nearest ANSI 256-color palette index.
// Uses the 6x6x6 color cube (indices 16-231) for best color matching.
func rgbToANSI256(r, g, b uint8) uint8 {
	// Convert to 6-level values (0-5) for the 6x6x6 color cube.
	// Math: (0-255) * 5 / 255 = 0-5, always fits in uint8.
	r6 := (int(r) * 5) / 255 //nolint:gosec // Result is always 0-5
	g6 := (int(g) * 5) / 255 //nolint:gosec // Result is always 0-5
	b6 := (int(b) * 5) / 255 //nolint:gosec // Result is always 0-5

	// Color cube index: 16 + 36*r + 6*g + b (max: 16 + 180 + 30 + 5 = 231)
	return uint8(16 + 36*r6 + 6*g6 + b6) //nolint:gosec // Result is always 16-231
}

// parseHexColor parses a hex color string like "#RRGGBB" or "RRGGBB".
// Returns r, g, b values and true if successful, or 0,0,0,false if parsing fails.
func parseHexColor(hex string) (r, g, b uint8, ok bool) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, 0, 0, false
	}

	rr, err := strconv.ParseUint(hex[0:2], 16, 8)
	if err != nil {
		return 0, 0, 0, false
	}
	gg, err := strconv.ParseUint(hex[2:4], 16, 8)
	if err != nil {
		return 0, 0, 0, false
	}
	bb, err := strconv.ParseUint(hex[4:6], 16, 8)
	if err != nil {
		return 0, 0, 0, false
	}

	return uint8(rr), uint8(gg), uint8(bb), true
}

// Package output provides formatters for scan results.
package output

import (
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Color palette - using Tailwind CSS color system for consistency
// AdaptiveColor automatically selects Light/Dark variant based on terminal background
var (
	// Severity colors (background) - high saturation works on both themes
	colorCriticalBg = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#DC2626"} // red-600
	colorHighBg     = lipgloss.AdaptiveColor{Light: "#EA580C", Dark: "#EA580C"} // orange-600
	colorMediumBg   = lipgloss.AdaptiveColor{Light: "#CA8A04", Dark: "#CA8A04"} // yellow-600
	colorLowBg      = lipgloss.AdaptiveColor{Light: "#2563EB", Dark: "#2563EB"} // blue-600
	colorInfoBg     = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#6B7280"} // gray-500

	// Severity colors (foreground for text) - darker on light bg for contrast
	colorCriticalFg = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#EF4444"} // red-600 / red-500
	colorHighFg     = lipgloss.AdaptiveColor{Light: "#EA580C", Dark: "#F97316"} // orange-600 / orange-500
	colorMediumFg   = lipgloss.AdaptiveColor{Light: "#A16207", Dark: "#EAB308"} // yellow-700 / yellow-500
	colorLowFg      = lipgloss.AdaptiveColor{Light: "#2563EB", Dark: "#3B82F6"} // blue-600 / blue-500
	colorInfoFg     = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"} // gray-500 / gray-400

	// Semantic colors - darker on light bg for contrast
	colorSuccess = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#22C55E"} // green-600 / green-500
	colorWarning = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#F59E0B"} // amber-600 / amber-500
	colorMuted   = lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#6B7280"} // gray-600 / gray-500
	colorAccent  = lipgloss.AdaptiveColor{Light: "#7c3aed", Dark: "#7c3aed"} // purple-600 (Armis brand)

	// Diff colors - darker on light bg for contrast
	colorDiffAdd    = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#22C55E"} // green-600 / green-500
	colorDiffRemove = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#EF4444"} // red-600 / red-500
	colorDiffHunk   = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#6B7280"} // gray-500

	// Diff background colors - light tints on light bg, dark tints on dark bg
	colorDiffAddBg    = lipgloss.AdaptiveColor{Light: "#dcfce7", Dark: "#0f2918"} // green-50 / dark green
	colorDiffRemoveBg = lipgloss.AdaptiveColor{Light: "#fee2e2", Dark: "#2a1215"} // red-100 / dark red

	// UI colors - inverted for light/dark themes
	colorBorder = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#374151"} // gray-300 / gray-700
	colorDim    = lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#6B7280"} // gray-600 / gray-500

	// Bright text color - dark on light bg, white on dark bg
	colorBright = lipgloss.AdaptiveColor{Light: "#1F2937", Dark: "#FFFFFF"} // gray-800 / white
)

// Styles holds all lipgloss styles for consistent formatting
type Styles struct {
	// Severity badge styles (colored backgrounds)
	CriticalBadge lipgloss.Style
	HighBadge     lipgloss.Style
	MediumBadge   lipgloss.Style
	LowBadge      lipgloss.Style
	InfoBadge     lipgloss.Style

	// Severity text styles (colored text, no background)
	CriticalText lipgloss.Style
	HighText     lipgloss.Style
	MediumText   lipgloss.Style
	LowText      lipgloss.Style
	InfoText     lipgloss.Style

	// Section headers
	HeaderBanner    lipgloss.Style // Main banner (bold white text)
	HeaderBox       lipgloss.Style
	SectionTitle    lipgloss.Style
	FindingHeader   lipgloss.Style
	SubsectionTitle lipgloss.Style

	// Code block styles
	CodeBlock      lipgloss.Style
	CodeLineNumber lipgloss.Style
	CodeHighlight  lipgloss.Style

	// Vulnerability highlighting styles
	VulnHighlight       lipgloss.Style // Full-line highlight for vulnerable code
	VulnColumnHighlight lipgloss.Style // Column-specific highlight within a line
	ProposedLineNumber  lipgloss.Style // Line numbers in proposed fix snippets

	// Status indicators
	SuccessText lipgloss.Style
	WarningText lipgloss.Style
	ErrorText   lipgloss.Style
	MutedText   lipgloss.Style

	// Diff styles
	DiffAdd             lipgloss.Style // Text-only green for + marker
	DiffRemove          lipgloss.Style // Text-only red for - marker
	DiffHunk            lipgloss.Style // Gray for @@ hunk headers
	DiffAddLine         lipgloss.Style // Full line: green fg + dark green bg
	DiffRemoveLine      lipgloss.Style // Full line: red fg + dark red bg
	DiffAddHighlight    lipgloss.Style // Inline change highlight (added text)
	DiffRemoveHighlight lipgloss.Style // Inline change highlight (removed text)
	DiffLineNumber      lipgloss.Style // Dim gray for line numbers in diff
	DiffGutter          lipgloss.Style // Style for the │ gutter character

	// Summary dashboard
	SummaryBox    lipgloss.Style
	ProgressFull  lipgloss.Style
	ProgressEmpty lipgloss.Style

	// Miscellaneous
	Bold       lipgloss.Style
	Italic     lipgloss.Style
	Underline  lipgloss.Style
	LocationFg lipgloss.Style

	// Spinner styles
	SpinnerChar  lipgloss.Style // The animated spinner character
	SpinnerText  lipgloss.Style // The message text
	SpinnerTimer lipgloss.Style // The elapsed time [00:00]

	// Info styles
	ScanID          lipgloss.Style // For highlighting scan IDs
	StatusComplete  lipgloss.Style // Green for "completed" status
	Duration        lipgloss.Style // Bold for duration values
	FooterSeparator lipgloss.Style // Double border footer line

	// Help output styles
	HelpHeading lipgloss.Style // Bold for section headers (Usage:, Flags:, etc.)
	HelpCommand lipgloss.Style // Accent color for command names
	HelpFlag    lipgloss.Style // Accent color for --flag-name
}

// DefaultStyles returns the default style configuration
func DefaultStyles() *Styles {
	return &Styles{
		// Severity badges - white text on colored background with padding
		CriticalBadge: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorCriticalBg).
			Padding(0, 1),
		HighBadge: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorHighBg).
			Padding(0, 1),
		MediumBadge: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorMediumBg).
			Padding(0, 1),
		LowBadge: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorLowBg).
			Padding(0, 1),
		InfoBadge: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorInfoBg).
			Padding(0, 1),

		// Severity text - colored foreground, no background
		CriticalText: lipgloss.NewStyle().Bold(true).Foreground(colorCriticalFg),
		HighText:     lipgloss.NewStyle().Bold(true).Foreground(colorHighFg),
		MediumText:   lipgloss.NewStyle().Bold(true).Foreground(colorMediumFg),
		LowText:      lipgloss.NewStyle().Bold(true).Foreground(colorLowFg),
		InfoText:     lipgloss.NewStyle().Foreground(colorInfoFg),

		// Section headers - use colorBright for theme-adaptive text
		HeaderBanner: lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright),
		HeaderBox: lipgloss.NewStyle().
			Bold(true).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1),
		SectionTitle: lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright),
		FindingHeader: lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright),
		SubsectionTitle: lipgloss.NewStyle().
			Bold(true).
			Foreground(colorMuted),

		// Code block styles
		CodeBlock: lipgloss.NewStyle().
			Padding(0, 1), // No border, just padding
		CodeLineNumber: lipgloss.NewStyle().
			Foreground(colorDim).
			Width(4).
			Align(lipgloss.Right),
		CodeHighlight: lipgloss.NewStyle().
			Bold(true), // Simple bold - no loud background

		// Vulnerability highlighting styles
		VulnHighlight: lipgloss.NewStyle().
			Bold(true), // Simple bold for full-line highlight
		VulnColumnHighlight: lipgloss.NewStyle().
			Bold(true), // Bold for column-specific highlight
		ProposedLineNumber: lipgloss.NewStyle().
			Foreground(colorDim),

		// Status indicators
		SuccessText: lipgloss.NewStyle().Foreground(colorSuccess),
		WarningText: lipgloss.NewStyle().Foreground(colorWarning),
		ErrorText:   lipgloss.NewStyle().Foreground(colorCriticalFg),
		MutedText:   lipgloss.NewStyle().Foreground(colorMuted),

		// Diff styles
		DiffAdd:    lipgloss.NewStyle().Foreground(colorDiffAdd),
		DiffRemove: lipgloss.NewStyle().Foreground(colorDiffRemove),
		DiffHunk:   lipgloss.NewStyle().Foreground(colorDiffHunk),
		DiffAddLine: lipgloss.NewStyle().
			Foreground(colorDiffAdd).
			Background(colorDiffAddBg),
		DiffRemoveLine: lipgloss.NewStyle().
			Foreground(colorDiffRemove).
			Background(colorDiffRemoveBg),
		DiffAddHighlight: lipgloss.NewStyle().
			Foreground(colorDiffAdd).
			Bold(true),
		DiffRemoveHighlight: lipgloss.NewStyle().
			Foreground(colorDiffRemove).
			Bold(true),
		DiffLineNumber: lipgloss.NewStyle().
			Foreground(colorDim),
		DiffGutter: lipgloss.NewStyle().
			Foreground(colorBorder),

		// Summary dashboard
		SummaryBox: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1),
		ProgressFull:  lipgloss.NewStyle().Foreground(colorBright),
		ProgressEmpty: lipgloss.NewStyle().Foreground(colorDim),

		// Miscellaneous
		Bold:       lipgloss.NewStyle().Bold(true),
		Italic:     lipgloss.NewStyle().Italic(true),
		Underline:  lipgloss.NewStyle().Underline(true),
		LocationFg: lipgloss.NewStyle().Bold(true).Foreground(colorBright),

		// Spinner styles
		SpinnerChar:  lipgloss.NewStyle().Bold(true).Foreground(colorAccent),
		SpinnerText:  lipgloss.NewStyle(),
		SpinnerTimer: lipgloss.NewStyle().Foreground(colorMuted),

		// Info styles
		ScanID:         lipgloss.NewStyle().Bold(true).Foreground(colorAccent),
		StatusComplete: lipgloss.NewStyle().Foreground(colorSuccess),
		Duration:       lipgloss.NewStyle().Bold(true),
		FooterSeparator: lipgloss.NewStyle().
			Foreground(colorDim),

		// Help output styles
		HelpHeading: lipgloss.NewStyle().Bold(true),
		HelpCommand: lipgloss.NewStyle().Foreground(colorAccent),
		HelpFlag:    lipgloss.NewStyle().Foreground(colorAccent),
	}
}

// NoColorStyles returns styles with all formatting disabled (for --color=never)
func NoColorStyles() *Styles {
	plain := lipgloss.NewStyle()
	return &Styles{
		CriticalBadge: plain,
		HighBadge:     plain,
		MediumBadge:   plain,
		LowBadge:      plain,
		InfoBadge:     plain,

		CriticalText: plain,
		HighText:     plain,
		MediumText:   plain,
		LowText:      plain,
		InfoText:     plain,

		HeaderBanner:    plain,
		HeaderBox:       plain,
		SectionTitle:    plain,
		FindingHeader:   plain,
		SubsectionTitle: plain,

		CodeBlock:      plain,
		CodeLineNumber: plain,
		CodeHighlight:  plain,

		VulnHighlight:       plain,
		VulnColumnHighlight: plain,
		ProposedLineNumber:  plain,

		SuccessText: plain,
		WarningText: plain,
		ErrorText:   plain,
		MutedText:   plain,

		DiffAdd:             plain,
		DiffRemove:          plain,
		DiffHunk:            plain,
		DiffAddLine:         plain,
		DiffRemoveLine:      plain,
		DiffAddHighlight:    plain,
		DiffRemoveHighlight: plain,
		DiffLineNumber:      plain,
		DiffGutter:          plain,

		SummaryBox:    plain,
		ProgressFull:  plain,
		ProgressEmpty: plain,

		Bold:       plain,
		Italic:     plain,
		Underline:  plain,
		LocationFg: plain,

		SpinnerChar:  plain,
		SpinnerText:  plain,
		SpinnerTimer: plain,

		ScanID:          plain,
		StatusComplete:  plain,
		Duration:        plain,
		FooterSeparator: plain,

		HelpHeading: plain,
		HelpCommand: plain,
		HelpFlag:    plain,
	}
}

// currentStyles holds the active style set
var currentStyles *Styles

// lipglossInitialized tracks whether lipgloss renderer has been configured
var lipglossInitialized bool

// GetStyles returns the current style set based on color mode
func GetStyles() *Styles {
	if currentStyles == nil {
		SyncStylesWithColorMode()
	}
	return currentStyles
}

// SyncStylesWithColorMode updates the styles based on the current color mode
func SyncStylesWithColorMode() {
	// Initialize lipgloss renderer once (configure to output to stderr)
	if !lipglossInitialized {
		lipgloss.SetDefaultRenderer(lipgloss.NewRenderer(os.Stderr))
		lipglossInitialized = true
	}

	if cli.ColorsEnabled() {
		currentStyles = DefaultStyles()
		// Configure lipgloss color profile
		if cli.ColorsForced() {
			// --color=always: force TrueColor regardless of TTY detection
			lipgloss.SetColorProfile(termenv.TrueColor)
		} else {
			// Auto mode: detect terminal capabilities
			lipgloss.SetColorProfile(lipgloss.ColorProfile())
		}
	} else {
		currentStyles = NoColorStyles()
		// Force no colors using termenv's Ascii profile
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// GetSeverityText returns the appropriate text style for a severity level
func (s *Styles) GetSeverityText(severity model.Severity) lipgloss.Style {
	switch severity {
	case model.SeverityCritical:
		return s.CriticalText
	case model.SeverityHigh:
		return s.HighText
	case model.SeverityMedium:
		return s.MediumText
	case model.SeverityLow:
		return s.LowText
	case model.SeverityInfo:
		return s.InfoText
	default:
		return s.InfoText
	}
}

// Box drawing constants for consistency
const (
	BoxWidth         = 68  // Default box width for findings/summary (fallback)
	MinBoxWidth      = 60  // Minimum usable width
	MaxBoxWidth      = 120 // Cap to prevent overly wide output
	BoxPadding       = 4   // Margin from terminal edge
	DefaultWrapWidth = 76  // Default text wrapping width
)

// TerminalWidth detects the current terminal width with fallbacks.
// Returns BoxWidth if detection fails (non-TTY, pipe, etc.)
func TerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return BoxWidth
	}
	// Subtract padding for visual margin
	usable := w - BoxPadding
	if usable < MinBoxWidth {
		return MinBoxWidth
	}
	if usable > MaxBoxWidth {
		return MaxBoxWidth
	}
	return usable
}

// Package output provides formatters for scan results.
package output

// Severity indicator - Unicode dot with color applied via lipgloss styling
// This provides consistent rendering across terminals and respects --color=never
const (
	// SeverityDot is the universal severity indicator
	// Color is applied via GetSeverityText() styling
	SeverityDot = "●"
)

// Category icons - represent different types of security findings
const (
	IconDependency = "📦" // SBOM/dependency issues, also used for update notifications
)

// Status icons
const (
	IconSuccess = "✓"
	IconPointer = "►"
)

// GetConfidenceIcon returns an icon based on confidence level
func GetConfidenceIcon(confidence int) string {
	switch {
	case confidence >= 80:
		return IconSuccess
	case confidence >= 50:
		return "~"
	default:
		return "?"
	}
}

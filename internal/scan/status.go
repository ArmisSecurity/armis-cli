// Package scan provides shared utilities for scanning operations.
package scan

import (
	"fmt"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// FormatScanStatus returns a human-readable message for the current scan phase.
// The inProgressMsg parameter customizes the message for the IN_PROGRESS state,
// allowing different scan types (repo, image) to show context-specific messages.
// Status values are from the ArtifactScanStatus enum in the Project-Moose API.
func FormatScanStatus(scanStatus, inProgressMsg string) string {
	switch strings.ToUpper(scanStatus) {
	case "INITIATED":
		return "Scan initiated, preparing analysis..."
	case "IN_PROGRESS":
		return inProgressMsg
	case "COMPLETED":
		return "Scan completed, preparing results..."
	case "FAILED":
		return "Scan encountered an error"
	case "STOPPED":
		return "Scan was stopped"
	default:
		return fmt.Sprintf("Scanning... [%s]", strings.ToUpper(scanStatus))
	}
}

// FormatElapsed formats a duration as a human-readable time string.
// Examples: "45s", "2m 30s"
func FormatElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// MapSeverity converts a string severity level to the model.Severity type.
// Recognized values (case-insensitive): CRITICAL, HIGH, MEDIUM, LOW.
// Unrecognized values default to Info severity.
func MapSeverity(toolSeverity string) model.Severity {
	switch strings.ToUpper(toolSeverity) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

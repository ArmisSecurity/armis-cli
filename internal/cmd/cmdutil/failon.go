package cmdutil

import (
	"fmt"
	"strings"
)

// ValidSeverities contains the valid severity level strings for the --fail-on flag.
var ValidSeverities = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// ValidateFailOn checks that every entry of severities is a recognized severity
// level and normalizes it to uppercase in place. ShouldFail matches severities
// exactly, so normalization here is what lets a lowercase "medium" trip the gate
// on a "MEDIUM" finding.
func ValidateFailOn(severities []string) error {
	validSet := make(map[string]bool)
	for _, s := range ValidSeverities {
		validSet[s] = true
	}

	for i, sev := range severities {
		// Normalize to uppercase for case-insensitive matching
		upper := strings.ToUpper(sev)
		if !validSet[upper] {
			return fmt.Errorf("invalid severity level %q: must be one of %v", sev, ValidSeverities)
		}
		// Update the slice with normalized value
		severities[i] = upper
	}
	return nil
}

// GetFailOn validates and normalizes the given --fail-on severities, returning
// the normalized slice. It is pure: callers pass the flag value (read from the
// cobra command or a package global) rather than relying on a shared global, so
// both the scan commands and the supplychain subpackage can use it.
func GetFailOn(failOn []string) ([]string, error) {
	if err := ValidateFailOn(failOn); err != nil {
		return nil, err
	}
	return failOn, nil
}

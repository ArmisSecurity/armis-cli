package cmdutil

import (
	"fmt"
	"slices"
	"strings"
)

// ValidSeverities contains the valid severity level strings for the --fail-on and
// --min-severity flags, least severe first: FailOnThreshold relies on the order.
var ValidSeverities = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// ValidateFailOn checks that every entry of severities is a recognized severity
// level and normalizes it to uppercase in place. ShouldFail matches the levels
// GetFailOn returns exactly, so normalization here is what lets a lowercase
// "medium" trip the gate on a "MEDIUM" finding.
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

// GetFailOn validates the given --fail-on severities and returns the levels
// that fail the run: the lowest level given and every level above it, so
// `--fail-on HIGH` fails on HIGH and CRITICAL findings, as a gate is meant to.
// A list means its lowest level (`HIGH,CRITICAL` is HIGH and up), and no level
// (`--fail-on ""`) fails on nothing. It is pure: callers pass the flag value
// (read from the cobra command or a package global) rather than relying on a
// shared global, so both the scan commands and the supplychain subpackage can
// use it.
func GetFailOn(failOn []string) ([]string, error) {
	if err := ValidateFailOn(failOn); err != nil {
		return nil, err
	}
	return FailOnThreshold(failOn), nil
}

// FailOnThreshold is the lowest of severities (valid, upper-case levels) and
// every level above it, in ValidSeverities' order; nil for no severities.
func FailOnThreshold(severities []string) []string {
	lowest := len(ValidSeverities)
	for _, s := range severities {
		if i := slices.Index(ValidSeverities, s); i >= 0 && i < lowest {
			lowest = i
		}
	}
	if lowest == len(ValidSeverities) {
		return nil
	}
	return slices.Clone(ValidSeverities[lowest:])
}

// ValidateMinSeverity checks a --min-severity value and returns it normalized
// to uppercase. An empty value is valid and means "show every severity".
// Like --fail-on it is a threshold, but it takes a single level.
func ValidateMinSeverity(severity string) (string, error) {
	if severity == "" {
		return "", nil
	}
	upper := strings.ToUpper(severity)
	for _, s := range ValidSeverities {
		if s == upper {
			return upper, nil
		}
	}
	return "", fmt.Errorf("invalid --min-severity value %q: must be one of %v", severity, ValidSeverities)
}

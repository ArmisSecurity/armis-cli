package output

import (
	"fmt"
	"io"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// FormatOptions contains options for formatting scan results.
type FormatOptions struct {
	GroupBy  string
	RepoPath string
}

// Formatter is the interface for formatting scan results in different output formats.
type Formatter interface {
	Format(result *model.ScanResult, w io.Writer) error
	FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error
}

// GetFormatter returns a formatter for the specified format type.
func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "human":
		return &HumanFormatter{}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "sarif":
		return &SARIFFormatter{}, nil
	case "junit":
		return &JUnitFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// ShouldFail determines if the scan should fail based on the severity of findings.
func ShouldFail(result *model.ScanResult, failOnSeverities []string) bool {
	severityMap := make(map[string]bool)
	for _, sev := range failOnSeverities {
		severityMap[sev] = true
	}

	for _, finding := range result.Findings {
		if severityMap[string(finding.Severity)] {
			return true
		}
	}

	return false
}

// ExitIfNeeded exits the program with the specified exit code if the scan should fail.
func ExitIfNeeded(result *model.ScanResult, failOnSeverities []string, exitCode int) {
	if ShouldFail(result, failOnSeverities) {
		os.Exit(exitCode)
	}
}

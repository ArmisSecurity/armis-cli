package output

import (
	"fmt"
	"io"
	"os"

	"github.com/silk-security/Moose-CLI/internal/model"
)

type Formatter interface {
	Format(result *model.ScanResult, w io.Writer) error
}

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

func ExitIfNeeded(result *model.ScanResult, failOnSeverities []string, exitCode int) {
	if ShouldFail(result, failOnSeverities) {
		os.Exit(exitCode)
	}
}

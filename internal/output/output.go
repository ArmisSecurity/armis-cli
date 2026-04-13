package output

import (
	"fmt"
	"io"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// Package-level variables for testability
var (
	stdoutSyncer           = func() error { return os.Stdout.Sync() }
	stderrWriter io.Writer = os.Stderr
)

// ErrFindingsExceeded indicates scan found findings matching --fail-on severities.
// This is not an error condition - it's expected behavior signaling CI systems.
// The ExitCode field contains the configured exit code (default 1, or --exit-code value).
type ErrFindingsExceeded struct {
	ExitCode int
}

func (e *ErrFindingsExceeded) Error() string {
	return "findings exceeded threshold"
}

// ErrResultsIncomplete indicates the scan completed on the server but the CLI
// failed to retrieve results. This should result in a non-zero exit code so
// CI pipelines do not silently pass when results are unavailable.
type ErrResultsIncomplete struct {
	ScanID string
}

func (e *ErrResultsIncomplete) Error() string {
	return fmt.Sprintf("scan completed but results could not be retrieved (scan ID: %s)", e.ScanID)
}

// FormatOptions contains options for formatting scan results.
type FormatOptions struct {
	GroupBy          string
	RepoPath         string
	Debug            bool
	SummaryTop       bool
	FailOnSeverities []string // Severities that count as failures (for JUnit output)
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

// CheckExit returns an error if the scan should fail based on severity of findings.
// The returned error should be propagated to main.go which handles the exit.
// Returns nil if no findings match the fail-on severities.
func CheckExit(result *model.ScanResult, failOnSeverities []string, exitCode int) error {
	if ShouldFail(result, failOnSeverities) {
		// Normalize exit code to valid POSIX range (0-255)
		if exitCode < 0 || exitCode > 255 {
			exitCode = 1
		}
		// Flush stdout to ensure all output is written before returning
		if err := stdoutSyncer(); err != nil {
			// Silently ignore "sync not supported" errors - these occur when stdout
			// is a pipe, socket, or /dev/stdout which don't support fsync.
			// The output is still delivered correctly.
			if !isSyncNotSupported(err) {
				// Log actual flush failures to stderr (stdout may be broken)
				// Using stderrWriter (instead of cli.PrintWarning) for testability
				_, _ = fmt.Fprintf(stderrWriter, "Warning: failed to flush stdout before exit: %v\n", err)
			}
		}
		return &ErrFindingsExceeded{ExitCode: exitCode}
	}
	return nil
}

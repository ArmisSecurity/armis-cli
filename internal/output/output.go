package output

import (
	"fmt"
	"io"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

const suppressionSourceInline = "inline"

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
	ShowSuppressed   bool     // Show findings suppressed by .armisignore directives
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

// ExitPolicy describes what makes a scan fail.
type ExitPolicy struct {
	// FailOnSeverities are the severity levels that fail the scan.
	FailOnSeverities []string
	// FailOnSecret fails the scan when a secret is exposed in the scanned source,
	// whatever severity the backend assigned it. An exposed secret arrives as
	// severity INFO with no CWE unless --include-non-exploitable is passed, so
	// under the usual --fail-on HIGH,CRITICAL a credential committed to source is
	// a passing scan. Reachability grading has no bearing on a literal secret:
	// it is already disclosed to everyone who can read the repository.
	FailOnSecret bool
}

// ShouldFail determines if the scan should fail based on the severity of findings.
// Suppressed findings are excluded from the evaluation.
func ShouldFail(result *model.ScanResult, failOnSeverities []string) bool {
	return ShouldFailPolicy(result, ExitPolicy{FailOnSeverities: failOnSeverities})
}

// ShouldFailPolicy determines if the scan should fail under the given policy.
// Suppressed findings are excluded from the evaluation, so .armisignore remains the
// escape hatch for a finding the policy would otherwise fail on.
func ShouldFailPolicy(result *model.ScanResult, policy ExitPolicy) bool {
	return failureReason(result, policy) != failureNone
}

type failureKind int

const (
	failureNone failureKind = iota
	failureSeverity
	failureSecret
)

func failureReason(result *model.ScanResult, policy ExitPolicy) failureKind {
	severityMap := make(map[string]bool)
	for _, sev := range policy.FailOnSeverities {
		severityMap[sev] = true
	}

	reason := failureNone
	for _, finding := range result.Findings {
		if finding.Suppressed {
			continue
		}
		if severityMap[string(finding.Severity)] {
			// A severity match is the reason the user configured, so report it in
			// preference to the secret rule even if both apply.
			return failureSeverity
		}
		if policy.FailOnSecret && finding.Type == model.FindingTypeSecret {
			reason = failureSecret
		}
	}

	return reason
}

// FilterActiveFindings returns only non-suppressed findings.
func FilterActiveFindings(findings []model.Finding) []model.Finding {
	active := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	return active
}

// CheckExit returns an error if the scan should fail based on severity of findings.
// The returned error should be propagated to main.go which handles the exit.
// Returns nil if no findings match the fail-on severities.
func CheckExit(result *model.ScanResult, failOnSeverities []string, exitCode int) error {
	return CheckExitPolicy(result, ExitPolicy{FailOnSeverities: failOnSeverities}, exitCode)
}

// CheckExitPolicy returns an error if the scan should fail under the given policy.
// The returned error should be propagated to main.go which handles the exit.
func CheckExitPolicy(result *model.ScanResult, policy ExitPolicy, exitCode int) error {
	reason := failureReason(result, policy)
	if reason != failureNone {
		if reason == failureSecret {
			// Without this the exit is unexplainable: every finding sits below the
			// configured --fail-on threshold, yet the scan failed.
			// armis:ignore cwe:253 reason:fmt.Fprintf to stderr for warning; return value not actionable
			_, _ = fmt.Fprintf(stderrWriter,
				"Failing because a secret is exposed in the scanned source; "+
					"severity thresholds do not apply to secrets (--fail-on-secret=false to disable)\n")
		}
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
				// armis:ignore cwe:253 reason:fmt.Fprintf to stderr for warning; return value not actionable
				_, _ = fmt.Fprintf(stderrWriter, "Warning: failed to flush stdout before exit: %v\n", err)
			}
		}
		return &ErrFindingsExceeded{ExitCode: exitCode}
	}
	return nil
}

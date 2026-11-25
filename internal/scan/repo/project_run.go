package repo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// maxFetchRetries bounds the reads of a scan's results that fail transiently.
const maxFetchRetries = 5

// unsupportedReadError means the server can't serve a recorded run's findings
// from AppSec: it predates the route, or ignores expand=detail. The run's
// findings are then read the legacy way. Reason is the answer that said so.
type unsupportedReadError struct {
	reason string
}

func (e *unsupportedReadError) Error() string {
	return "the server does not serve this run's findings from AppSec: " + e.reason
}

// errRunNotRecordedInTime means the run's findings history was still being
// written when the scan timeout ran out.
var errRunNotRecordedInTime = errors.New("the run's findings were not recorded within the scan timeout")

// recordedProjectRun is the project run /ingest/scan recorded the scan as,
// nil for a scan it recorded as none: an unpublished scan, an unrecorded
// run, or a server that predates project runs. A run whose ids aren't of
// their shape is none either, since no path can be built from them.
func recordedProjectRun(run *model.ProjectRun) *model.ProjectRun {
	if run == nil || !run.Recorded || !api.IsValidProjectID(run.ProjectID) || !api.IsValidRunID(run.RunID) {
		return nil
	}
	return run
}

// recordedRunResult reads a recorded run's findings from AppSec: every
// finding the history kept, the ones the project's filters suppressed
// included, so they are shown suppressed and left out of --fail-on. It never
// returns a result for findings it couldn't read:
//
//   - not_finished is read again every poll interval until deadline;
//   - run_failed, and a read that fails after its retries or doesn't add up
//     to the run's list, are ErrResultsIncomplete;
//   - not_recorded (a server that keeps no history for the run, or a run
//     recorded before it did), a route that can't serve the run, and a run
//     still not recorded at deadline read the legacy way, once, where the 409
//     of a run whose findings Armis keeps in AppSec is ErrResultsIncomplete;
//   - a cancelled scan returns ctx's error, so it exits as cancelled.
//
// The second result reports a legacy read that found no result entry.
func (s *Scanner) recordedRunResult(ctx context.Context, scanID string, run model.ProjectRun, deadline time.Time, spinner *progress.Spinner) (*model.ScanResult, bool, error) {
	read, err := s.readRunFindings(ctx, run, deadline, spinner)
	var unsupported *unsupportedReadError
	switch {
	case errors.Is(err, context.Canceled):
		spinner.Stop()
		return nil, false, err
	case errors.As(err, &unsupported), errors.Is(err, errRunNotRecordedInTime):
		return s.fallBackToNormalizedResult(ctx, scanID, run, err, spinner)
	case err != nil:
		spinner.Stop()
		cli.PrintWarningf("Failed to read the findings of run %s of project %s: %v", run.RunID, run.ProjectID, err)
		cli.PrintWarningf("Scan completed. Its findings are in AppSec, run %s of project %s", run.RunID, run.ProjectID)
		return nil, false, &output.ErrResultsIncomplete{ScanID: scanID}
	}

	switch read.EmptyReason {
	case model.RunFindingsRunFailed:
		spinner.Stop()
		cli.PrintWarningf("Armis recorded run %s of project %s as failed: it has no findings to read", run.RunID, run.ProjectID)
		return nil, false, &output.ErrResultsIncomplete{ScanID: scanID}
	case model.RunFindingsNotRecorded:
		return s.fallBackToNormalizedResult(ctx, scanID, run, nil, spinner)
	}

	debug := s.client.IsDebug()
	findings, filtered := convertProjectRunFindings(read.Findings, debug, s.includeNonExploitable)
	result := &model.ScanResult{
		ScanID:   scanID,
		Status:   "completed",
		Findings: findings,
		Summary:  model.SummarizeFindings(findings),
	}
	result.Summary.FilteredNonExploitable = filtered
	if read.Truncated {
		result.Truncated = runTruncation(read)
		spinner.Stop()
		cli.PrintWarningf("Armis kept the %d most severe findings of %d", result.Truncated.Kept, result.Truncated.Total)
	}
	if debug {
		s.printScanFilters(ctx, run.ProjectID)
	}
	return result, false, nil
}

// readRunFindings reads a recorded run's findings, again every poll interval
// while its history is still being written, which can trail the scan's
// status, until deadline.
func (s *Scanner) readRunFindings(ctx context.Context, run model.ProjectRun, deadline time.Time, spinner *progress.Spinner) (*api.ProjectRunFindings, error) {
	for {
		read, err := s.fetchRunFindings(ctx, run, spinner)
		if err != nil {
			return nil, err
		}
		if read.EmptyReason != model.RunFindingsNotFinished {
			return read, nil
		}
		if !time.Now().Add(s.pollInterval).Before(deadline) {
			return nil, errRunNotRecordedInTime
		}
		spinner.Update("Waiting for Armis to record the run's findings...")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.pollInterval):
		}
	}
}

// fetchRunFindings reads a run's findings once, retrying a read that fails
// transiently. A server that doesn't know the route or its parameters (404,
// 405, 422), or that returns rows without the detail asked for, is an
// unsupportedReadError.
func (s *Scanner) fetchRunFindings(ctx context.Context, run model.ProjectRun, spinner *progress.Spinner) (*api.ProjectRunFindings, error) {
	var read *api.ProjectRunFindings
	var err error
	for attempt := 1; attempt <= maxFetchRetries; attempt++ {
		read, err = s.client.FetchAllProjectRunFindings(ctx, s.tenantID, run.ProjectID, run.RunID)
		if err == nil || !isRetryableError(err) {
			break
		}
		if attempt < maxFetchRetries {
			spinner.Update(fmt.Sprintf("Retrieving results (retry %d/%d)...", attempt, maxFetchRetries-1))
			time.Sleep(s.fetchRetryInterval)
		}
	}
	if err != nil {
		var appSecErr *api.AppSecError
		if errors.As(err, &appSecErr) {
			switch appSecErr.StatusCode {
			case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnprocessableEntity:
				s.debugf("AppSec findings read unsupported: %v", err)
				return nil, &unsupportedReadError{reason: err.Error()}
			}
		}
		return nil, err
	}
	for i := range read.Findings {
		if read.Findings[i].Detail == nil {
			s.debugf("AppSec findings read returned rows without their detail")
			return nil, &unsupportedReadError{reason: "it served rows without their detail"}
		}
	}
	return read, nil
}

// fallBackToNormalizedResult reads a recorded run's findings the legacy way.
// That serves a server whose AppSec findings route predates CLI runs, and a
// run recorded before Armis kept CLI runs' findings in AppSec. cause is why
// AppSec didn't serve them, nil for a run it has no record of. A 409 there
// means Armis keeps them in AppSec: the results are incomplete, and the
// warning says why AppSec didn't serve them.
func (s *Scanner) fallBackToNormalizedResult(ctx context.Context, scanID string, run model.ProjectRun, cause error, spinner *progress.Spinner) (*model.ScanResult, bool, error) {
	findings, err := s.fetchNormalizedFindings(ctx, scanID, spinner)
	if errors.Is(err, context.Canceled) {
		spinner.Stop()
		return nil, false, err
	}
	if refusal, ok := api.ProjectRunFindingsRefusal(err); ok {
		spinner.Stop()
		projectID, runID := refusal.ContextString("project_id"), refusal.ContextString("run_id")
		if projectID == "" {
			projectID = run.ProjectID
		}
		if runID == "" {
			runID = run.RunID
		}
		cli.PrintWarningf("Armis keeps the findings of run %s of project %s in AppSec, %s",
			util.StripControl(runID), util.StripControl(projectID), notServedBecause(cause))
		return nil, false, &output.ErrResultsIncomplete{ScanID: scanID}
	}
	return s.normalizedResultOf(scanID, findings, err, spinner)
}

// notServedBecause says why AppSec didn't serve a run's findings, for the
// warning of a legacy read that refused them.
func notServedBecause(cause error) string {
	var unsupported *unsupportedReadError
	switch {
	case cause == nil:
		return "which has none recorded for it"
	case errors.Is(cause, errRunNotRecordedInTime):
		return "which had not recorded them when the scan timeout ran out"
	case errors.As(cause, &unsupported):
		return "which could not serve them: " + util.StripControl(unsupported.reason)
	default:
		return "which could not serve them: " + util.StripControl(cause.Error())
	}
}

// runTruncation is what the history kept of a run with more findings than it
// keeps: the most severe, the least severe of which bounds what it dropped.
func runTruncation(read *api.ProjectRunFindings) *model.ResultsTruncation {
	truncation := &model.ResultsTruncation{Kept: len(read.Findings), LeastSevereKept: model.SeverityCritical}
	if read.Counts != nil {
		truncation.Total = read.Counts.Total + read.Counts.Suppressed
	}
	if truncation.Total < truncation.Kept {
		truncation.Total = truncation.Kept
	}
	for i := range read.Findings {
		severity := scan.MapSeverity(read.Findings[i].Severity)
		if model.SeverityRank(severity) < model.SeverityRank(truncation.LeastSevereKept) {
			truncation.LeastSevereKept = severity
		}
	}
	return truncation
}

// printScanFilters prints, under --debug, the filters the project's next scan
// applies, as an .armisignore. Display only: an older server lacks the route,
// so any error skips it silently.
func (s *Scanner) printScanFilters(ctx context.Context, projectID string) {
	filters, err := s.client.GetProjectScanFilters(ctx, s.tenantID, projectID)
	if err != nil {
		s.debugf("no scan filters to show: %v", err)
		return
	}
	lines := strings.Split(filters.Armisignore, "\n")
	for i, line := range lines {
		lines[i] = util.StripControl(line)
	}
	fmt.Fprintf(os.Stderr, "\n=== DEBUG: Armis scan filters of project %s ===\n%s\n=== END DEBUG ===\n\n",
		projectID, strings.Join(lines, "\n"))
}

func (s *Scanner) debugf(format string, args ...any) {
	if s.client.IsDebug() {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

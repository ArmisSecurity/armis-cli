package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// AppSecCodeProjectRunFindings is the code of the 409 that
// /ingest/normalized-results answers for a recorded project run's scan: its
// findings are read from the AppSec findings route its context names.
const AppSecCodeProjectRunFindings = "project_run_findings"

// ProjectRunFindingsPageSize is the page a run's findings are read in:
// expand=detail caps it at 100.
const ProjectRunFindingsPageSize = 100

// MaxProjectRunFindings is the most findings the history keeps of a run: a
// read past it is refused rather than kept in memory.
const MaxProjectRunFindings = 50_000

// MaxProjectRunFindingsPages bounds a run's read: MaxProjectRunFindings in
// pages of ProjectRunFindingsPageSize.
const MaxProjectRunFindingsPages = MaxProjectRunFindings / ProjectRunFindingsPageSize

// runIDPattern matches a project run's id: "s_" and the run's 24 hex digits.
var runIDPattern = regexp.MustCompile(`^s_[0-9a-f]{24}$`)

// IsValidRunID reports whether id has the shape of a project run's id.
func IsValidRunID(id string) bool {
	return runIDPattern.MatchString(id)
}

// ListProjectRunFindings reads one page of a recorded run's findings, every
// finding the history kept, suppressed ones included, each with its detail.
func (c *Client) ListProjectRunFindings(ctx context.Context, tenantID, projectID, runID string, page int) (*model.RunFindingsPage, error) {
	if !IsValidProjectID(projectID) {
		return nil, fmt.Errorf("invalid project id %q", projectID)
	}
	if !IsValidRunID(runID) {
		return nil, fmt.Errorf("invalid run id %q", runID)
	}
	if page < 1 || page > MaxProjectRunFindingsPages {
		return nil, fmt.Errorf("page %d is outside 1..%d", page, MaxProjectRunFindingsPages)
	}
	params := url.Values{}
	params.Set("tenant_id", tenantID)
	params.Set("page", strconv.Itoa(page))
	params.Set("page_size", strconv.Itoa(ProjectRunFindingsPageSize))
	params.Set("expand", "detail")
	params.Set("suppressed", "include")

	var out model.RunFindingsPage
	path := projectsPath + "/" + projectID + "/scans/" + runID + "/findings"
	if err := c.doAppSec(ctx, http.MethodGet, path, params, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	if len(out.Data) > ProjectRunFindingsPageSize {
		return nil, fmt.Errorf("%w: a page of %d findings", ErrRunFindingsTooLarge, len(out.Data))
	}
	return &out, nil
}

// ProjectRunFindings is a recorded run's findings, read whole, with the first
// page's counts, truncation and empty state.
type ProjectRunFindings struct {
	Findings []model.RunFinding
	Counts   *model.RunFindingCounts
	// Truncated: the history kept only the most severe of the run's
	// findings (at most 50,000).
	Truncated bool
	// EmptyReason is the list's empty state (model.RunFindings*), "" for a
	// run with findings.
	EmptyReason string
}

// ErrRunFindingsTooLarge means a run's findings list holds more than the
// history keeps of a run, so it isn't read whole.
var ErrRunFindingsTooLarge = errors.New("the run's findings list is larger than the findings history keeps")

// ErrRunFindingsIncomplete means a run's findings, as read, don't add up to
// what its list says it holds, so a finding the CLI never read could be
// missing from them.
var ErrRunFindingsIncomplete = errors.New("the run's findings list is incomplete")

// FetchAllProjectRunFindings reads every page of a recorded run's findings.
// It returns ErrRunFindingsIncomplete unless the rows read are exactly the
// ones the list holds: as many as page 1's total_items, each read once, on
// pages that all count the same total and none of which has an empty state;
// and, for a run the history didn't truncate, as many as its counts, which
// include any finding the history counted but kept no row for.
func (c *Client) FetchAllProjectRunFindings(ctx context.Context, tenantID, projectID, runID string) (*ProjectRunFindings, error) {
	first, err := c.ListProjectRunFindings(ctx, tenantID, projectID, runID, 1)
	if err != nil {
		return nil, err
	}
	result := &ProjectRunFindings{
		Findings:    first.Data,
		Counts:      first.Counts,
		Truncated:   first.Truncated,
		EmptyReason: first.EmptyReason(),
	}
	if result.EmptyReason != "" {
		return result, nil
	}
	pages := first.Pagination.TotalPages
	if pages > MaxProjectRunFindingsPages {
		return nil, fmt.Errorf("%w: %d pages of %d", ErrRunFindingsTooLarge, pages, ProjectRunFindingsPageSize)
	}
	listed := first.Pagination.TotalItems
	for page := 2; page <= pages; page++ {
		next, err := c.ListProjectRunFindings(ctx, tenantID, projectID, runID, page)
		if err != nil {
			return nil, err
		}
		if next.EmptyState != nil {
			return nil, fmt.Errorf("%w: page %d of %d is empty (%s)", ErrRunFindingsIncomplete, page, pages, next.EmptyReason())
		}
		if next.Pagination.TotalItems != listed {
			return nil, fmt.Errorf("%w: page %d lists %d findings, page 1 %d", ErrRunFindingsIncomplete, page, next.Pagination.TotalItems, listed)
		}
		result.Findings = append(result.Findings, next.Data...)
	}
	// Pages hold at most ProjectRunFindingsPageSize each, and there are at
	// most MaxProjectRunFindingsPages, so this is the history's own bound.
	if len(result.Findings) > MaxProjectRunFindings {
		return nil, fmt.Errorf("%w: %d findings", ErrRunFindingsTooLarge, len(result.Findings))
	}
	if err := checkRunFindingsRead(result, listed); err != nil {
		return nil, err
	}
	return result, nil
}

// checkRunFindingsRead returns ErrRunFindingsIncomplete unless read holds
// listed findings, none of them twice, and a run the history didn't truncate
// holds every finding its counts count.
func checkRunFindingsRead(read *ProjectRunFindings, listed int) error {
	seen := make(map[string]struct{}, len(read.Findings))
	for i := range read.Findings {
		id := read.Findings[i].FindingID
		if _, repeated := seen[id]; repeated {
			return fmt.Errorf("%w: finding %q was read twice", ErrRunFindingsIncomplete, id)
		}
		seen[id] = struct{}{}
	}
	if len(read.Findings) != listed {
		return fmt.Errorf("%w: read %d of the %d findings it lists", ErrRunFindingsIncomplete, len(read.Findings), listed)
	}
	if read.Truncated {
		return nil
	}
	if read.Counts == nil {
		return fmt.Errorf("%w: it has no counts", ErrRunFindingsIncomplete)
	}
	if counted := read.Counts.Total + read.Counts.Suppressed; counted != len(read.Findings) {
		return fmt.Errorf("%w: read %d of the %d findings the run counts", ErrRunFindingsIncomplete, len(read.Findings), counted)
	}
	return nil
}

// GetProjectScanFilters reads the filters a project's next scan applies,
// for --debug: display only.
func (c *Client) GetProjectScanFilters(ctx context.Context, tenantID, projectID string) (*model.ProjectScanFilters, error) {
	if !IsValidProjectID(projectID) {
		return nil, fmt.Errorf("invalid project id %q", projectID)
	}
	// The route refuses any query parameter it doesn't declare.
	params := url.Values{}
	params.Set("tenant_id", tenantID)

	var out model.ProjectScanFilters
	if err := c.doAppSec(ctx, http.MethodGet, projectsPath+"/"+projectID+"/scan-filters", params, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProjectRunFindingsRefusal reports whether err is the 409 that
// /ingest/normalized-results answers for a recorded project run's scan, and
// returns it as an *AppSecError whose context names the project and the run.
func ProjectRunFindingsRefusal(err error) (*AppSecError, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		return nil, false
	}
	parsed := parseAppSecError(apiErr.StatusCode, []byte(apiErr.Body))
	if parsed.Code != AppSecCodeProjectRunFindings {
		return nil, false
	}
	return parsed, true
}

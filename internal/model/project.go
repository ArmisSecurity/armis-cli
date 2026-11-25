package model

// AppSec project types and statuses the CLI relies on (from the AppSec API's
// AppSecProjectType and AppSecProjectStatus enums).
const (
	// ProjectTypeCICD is the type of a project created by the CLI: it has no
	// repository binding, and the API reports its source as "cli".
	ProjectTypeCICD = "ci_cd"

	// ProjectStatusActive is a project that records runs.
	ProjectStatusActive = "active"
	// ProjectStatusPaused is a project whose schedules and repository sweeps
	// stop; a CLI scan that names it is still recorded as one of its runs.
	ProjectStatusPaused = "paused"
	// ProjectStatusArchived is a hidden project that does not record runs; its
	// name stays reserved until it is deleted.
	ProjectStatusArchived = "archived"
)

// Why /ingest/scan recorded no run of the project a scan names
// (ProjectRun.Reason).
const (
	// ProjectRunDisabled: the tenant does not record CLI scans as runs yet.
	ProjectRunDisabled = "disabled"
	// ProjectRunProjectNotFound: the tenant has no project with the id.
	ProjectRunProjectNotFound = "project_not_found"
	// ProjectRunProjectArchived: an archived project records no runs.
	ProjectRunProjectArchived = "project_archived"
	// ProjectRunProjectNotCLI: only a CLI (ci_cd) project takes CLI runs.
	ProjectRunProjectNotCLI = "project_not_cli"
	// ProjectRunNotRecorded: recording failed; the scan was dispatched anyway.
	ProjectRunNotRecorded = "not_recorded"
)

// ProjectRun is what /ingest/scan answers for a scan that names its project:
// whether the scan was recorded as a run of it, as which run, or why not.
type ProjectRun struct {
	Recorded  bool   `json:"recorded"`
	ProjectID string `json:"project_id"`
	// RunID is the run's id ("s_" and 24 hex characters) when Recorded.
	RunID string `json:"run_id,omitempty"`
	// Reason is one of the ProjectRun* reasons when not Recorded.
	Reason string `json:"reason,omitempty"`
}

// Project is an AppSec project as the /api/v1/appsec/projects endpoints return
// it, trimmed to the fields the CLI reads.
type Project struct {
	ProjectID   string `json:"project_id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	ProjectType string `json:"project_type"`
	Status      string `json:"status"`
	// Source is how the project came to exist ("scm", "cli" or "sbom"); null
	// for projects that predate the field.
	Source    *string `json:"source"`
	CreatedAt *string `json:"created_at"`
}

// ProjectCreateRequest is the body of POST /api/v1/appsec/projects. The API
// rejects unknown fields, so only fields it declares belong here.
type ProjectCreateRequest struct {
	Name        string `json:"name"`
	ProjectType string `json:"project_type"`
}

// ProjectListPagination is the pagination block of GET /api/v1/appsec/projects.
// A server since PPSC-2019 pages by number (Page, PageSize, TotalItems,
// TotalPages); an older one by cursor (NextCursor, null on the last page, and
// Limit).
type ProjectListPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	// TotalPages is at least 1 from a server that pages by number, and 0
	// (absent) from one that pages by cursor.
	TotalPages int `json:"total_pages"`

	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
}

// ProjectListResponse is the body of GET /api/v1/appsec/projects.
type ProjectListResponse struct {
	Data       []Project             `json:"data"`
	Pagination ProjectListPagination `json:"pagination"`
}

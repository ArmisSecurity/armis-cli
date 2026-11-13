package model

// AppSec project types and statuses the CLI relies on (from the AppSec API's
// AppSecProjectType and AppSecProjectStatus enums).
const (
	// ProjectTypeCICD is the type of a project created by the CLI: it has no
	// repository binding, and the API reports its source as "cli".
	ProjectTypeCICD = "ci_cd"

	// ProjectStatusActive is a project that records runs.
	ProjectStatusActive = "active"
	// ProjectStatusPaused is a project that does not record runs until resumed.
	ProjectStatusPaused = "paused"
	// ProjectStatusArchived is a hidden project that does not record runs; its
	// name stays reserved until it is deleted.
	ProjectStatusArchived = "archived"
)

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
type ProjectListPagination struct {
	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
}

// ProjectListResponse is the body of GET /api/v1/appsec/projects.
type ProjectListResponse struct {
	Data       []Project             `json:"data"`
	Pagination ProjectListPagination `json:"pagination"`
}

package project

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

const (
	// lookupPageSize is the largest page GET /projects serves.
	lookupPageSize = api.MaxProjectListLimit
	// maxLookupPages bounds the name lookup at 10,000 substring matches. Past
	// that the resolver falls back to creating the project, which the API
	// answers with the existing project's id when the name is taken.
	maxLookupPages = 50
	// lookupSort keeps paging stable; the API pins a cursor to its sort.
	lookupSort = "name_asc"
)

// lookupStatuses includes archived projects, which the API hides by default:
// an archived project still holds its name, so it must be found rather than
// collided with.
var lookupStatuses = []string{model.ProjectStatusActive, model.ProjectStatusPaused, model.ProjectStatusArchived}

var (
	// ErrProjectsUnavailable means the tenant has no AppSec projects API (the
	// API answers 404 when AppSec is not enabled for the tenant).
	ErrProjectsUnavailable = errors.New("AppSec projects are not available for this tenant")
	// ErrProjectsForbidden means the credentials may not read or create projects.
	ErrProjectsForbidden = errors.New("not permitted to manage AppSec projects")
	// ErrProjectsUnauthorized means the projects API rejected the credentials.
	ErrProjectsUnauthorized = errors.New("the AppSec projects API rejected the credentials")
)

// API is the part of the API client the resolver uses.
type API interface {
	ListProjects(ctx context.Context, tenantID string, opts api.ProjectListOptions) (*model.ProjectListResponse, error)
	CreateProject(ctx context.Context, tenantID string, req model.ProjectCreateRequest) (*model.Project, error)
	GetProject(ctx context.Context, tenantID, projectID string) (*model.Project, error)
}

// Resolution is the project a published scan is recorded on.
type Resolution struct {
	Project model.Project
	// Created is true when Resolve created the project.
	Created bool
}

// StatusWarning explains why a scan published to this project will not be
// recorded as one of its runs, or returns "" when the project records runs.
func (r *Resolution) StatusWarning() string {
	switch r.Project.Status {
	case model.ProjectStatusPaused:
		return fmt.Sprintf("project %q is paused: this scan still runs and gates, "+
			"but it is not recorded as a run until the project is resumed", r.Project.Name)
	case model.ProjectStatusArchived:
		return fmt.Sprintf("project %q is archived: this scan still runs and gates, "+
			"but it is not recorded as a run; resume the project in Armis to record runs again "+
			"(an archived project keeps its name reserved)", r.Project.Name)
	default:
		return ""
	}
}

// CaseMismatchError reports that no project has the exact name, but some
// differ from it only in case. Project names are case-sensitive and such
// projects share a slug, so creating one would add a near-duplicate.
type CaseMismatchError struct {
	Name     string
	Existing []string
}

func (e *CaseMismatchError) Error() string {
	quoted := make([]string, len(e.Existing))
	for i, n := range e.Existing {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Sprintf("no project is named %q, but %s differs only in case. "+
		"Project names are case-sensitive, so publishing would create a near-duplicate project. "+
		"Use --project %s to publish to the existing project, or choose a distinct name",
		e.Name, strings.Join(quoted, ", "), e.Existing[0])
}

// Resolve returns the tenant's project named exactly name (case-sensitive, as
// the API compares names), creating it when no project has that name. A
// created project is a ci_cd project, which has no repository binding and
// which the API labels with source "cli" — so a folder that is not a git
// repository gets the same kind of project as one that is.
//
// The name is validated with ValidateName first, whatever the caller already
// checked, so nothing invalid is ever looked up or created.
func Resolve(ctx context.Context, client API, tenantID, name string) (*Resolution, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	found, err := lookup(ctx, client, tenantID, name)
	if err != nil {
		return nil, explain(err, tenantID, "look up")
	}
	if found.exact != nil {
		return &Resolution{Project: *found.exact}, nil
	}
	// Only a complete lookup proves the variants are all there is; a partial
	// one still falls through to create, whose 409 finds an existing project.
	if found.complete && len(found.variants) > 0 {
		return nil, &CaseMismatchError{Name: name, Existing: found.variants}
	}

	created, err := client.CreateProject(ctx, tenantID, model.ProjectCreateRequest{
		Name:        name,
		ProjectType: model.ProjectTypeCICD,
	})
	if err == nil {
		return &Resolution{Project: *created, Created: true}, nil
	}

	// Another run (say a parallel CI job) created the project between the
	// lookup and the create: the 409 names it, so use it.
	var apiErr *api.AppSecError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict &&
		apiErr.Code == api.AppSecCodeProjectNameConflict {
		if id := apiErr.ContextString("conflicting_project_id"); api.IsValidProjectID(id) {
			if p, getErr := client.GetProject(ctx, tenantID, id); getErr == nil {
				return &Resolution{Project: *p}, nil
			}
			// The project exists; its status is unknown, but the id is enough
			// to record the run.
			return &Resolution{Project: model.Project{ProjectID: id, Name: name}}, nil
		}
	}
	return nil, explain(err, tenantID, "create")
}

// lookupResult is what a name lookup found.
type lookupResult struct {
	// exact is the project named exactly name, if one was seen.
	exact *model.Project
	// variants are the names seen that differ from name only in case.
	variants []string
	// complete is true when every matching page was read.
	complete bool
}

// lookup pages through the projects whose name contains name (the API's only
// name filter is a case-insensitive substring) for the one named exactly name,
// noting those that differ only in case. It stops early on an exact match, and
// gives up (complete=false) after maxLookupPages or on a cursor that does not
// advance.
func lookup(ctx context.Context, client API, tenantID, name string) (lookupResult, error) {
	var found lookupResult
	cursor := ""
	for page := 0; page < maxLookupPages; page++ {
		resp, err := client.ListProjects(ctx, tenantID, api.ProjectListOptions{
			Query:    name,
			Statuses: lookupStatuses,
			Sort:     lookupSort,
			Limit:    lookupPageSize,
			Cursor:   cursor,
		})
		if err != nil {
			return lookupResult{}, err
		}
		for i := range resp.Data {
			p := resp.Data[i]
			if p.Name == name {
				found.exact = &p
				return found, nil
			}
			if strings.EqualFold(p.Name, name) {
				found.variants = append(found.variants, p.Name)
			}
		}
		next := resp.Pagination.NextCursor
		if next == nil || *next == "" {
			found.complete = true
			return found, nil
		}
		if *next == cursor {
			return found, nil
		}
		cursor = *next
	}
	return found, nil
}

// explain turns a projects API failure into an actionable error.
func explain(err error, tenantID, action string) error {
	var apiErr *api.AppSecError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == http.StatusUnauthorized:
			return fmt.Errorf("%w (401); check the credentials or run 'armis-cli auth login': %w",
				ErrProjectsUnauthorized, err)
		case apiErr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("%w: finding or creating a project needs the admin or developer role, "+
				"so use credentials with one of them, or drop --project to scan without publishing: %w",
				ErrProjectsForbidden, err)
		case apiErr.StatusCode == http.StatusNotFound && apiErr.Code == "":
			return fmt.Errorf("%w (tenant %s): the AppSec UI is not enabled for it, so there is nothing to publish to; "+
				"drop --project to scan without publishing: %w", ErrProjectsUnavailable, tenantID, err)
		}
	}
	// Anything else keeps the underlying error so the operator can diagnose it.
	// armis:ignore cwe:209 reason:err is a client-side failure (transport, auth, decode), the retrying client's 5xx summary or the API's error detail, wrapped with %w as on every client.go call; shown only to the CLI's operator, secret-masked by cli.PrintError
	return fmt.Errorf("could not %s the project: %w", action, err)
}

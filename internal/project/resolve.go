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
	// maxLookupPages bounds the name lookup at about 10,000 substring matches.
	// Past that the resolver falls back to creating the project, which the API
	// answers with the existing project's id when the name is taken.
	maxLookupPages = 50
	// lookupSort keeps paging stable: each sort ends on a unique key, and a
	// server that pages by cursor pins the cursor to its sort.
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
	// Labels are the labels the project was created with.
	Labels []string
	// Setup is what the first-time setup decided, when Resolve ran it (also
	// when another run then created the project first: its filters still
	// belong to the repository).
	Setup *Setup
	// LabelsSkipped says why the labels asked for were not applied (one of
	// the LabelsSkipped* reasons), and RequestedLabels holds them.
	LabelsSkipped   string
	RequestedLabels []string
}

// Why the labels asked for were not applied (Resolution.LabelsSkipped).
const (
	// LabelsSkippedExists: the project exists, with other labels, which a
	// run never changes.
	LabelsSkippedExists = "exists"
	// LabelsSkippedRace: another run created the project first.
	LabelsSkippedRace = "race"
	// LabelsSkippedUnsupported: the server takes no labels on create.
	LabelsSkippedUnsupported = "unsupported"
)

// ResolveOptions say how Resolve creates a missing project.
type ResolveOptions struct {
	// Labels are the labels (normalized) a created project gets, unless
	// Configure returns others.
	Labels []string
	// Configure, when set, runs the first-time setup once Resolve knows it
	// is about to create the project, and returns its labels and filters (a
	// nil Setup is the defaults: Labels, and no filters). It is never called
	// for an existing project. ErrSetupCancelled stops the resolution before
	// anything is created.
	Configure func(ctx context.Context, name string) (*Setup, error)
}

// StatusWarning explains why a scan published to this project will not be
// recorded as one of its runs, or returns "" when the project records runs. A
// paused project does: its schedules stop, but the runs that name it record.
func (r *Resolution) StatusWarning() string {
	switch {
	case r.Project.Status == model.ProjectStatusArchived:
		return fmt.Sprintf("project %q is archived: this scan still runs and gates, "+
			"but it is not recorded as a run; resume the project in Armis to record runs again "+
			"(an archived project keeps its name reserved)", r.Project.Name)
	case r.Project.ProjectType != "" && r.Project.ProjectType != model.ProjectTypeCICD:
		return fmt.Sprintf("project %q is not a CLI project (it is a %s project): this scan still "+
			"runs and gates, but Armis records CLI scans only as runs of a CLI project; "+
			"name a project of its own for CLI scans", r.Project.Name, r.Project.ProjectType)
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
func Resolve(ctx context.Context, client API, tenantID, name string, opts ResolveOptions) (*Resolution, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	found, err := lookup(ctx, client, tenantID, name)
	if err != nil {
		return nil, explain(err, tenantID, "look up")
	}
	if found.exact != nil {
		res := &Resolution{Project: *found.exact}
		// An existing project's labels are its own: a run never changes them.
		if len(opts.Labels) > 0 && !SameLabels(opts.Labels, found.exact.Tags) {
			res.LabelsSkipped, res.RequestedLabels = LabelsSkippedExists, opts.Labels
		}
		return res, nil
	}
	// Only a complete lookup proves the variants are all there is; a partial
	// one still falls through to create, whose 409 finds an existing project.
	if found.complete && len(found.variants) > 0 {
		return nil, &CaseMismatchError{Name: name, Existing: found.variants}
	}

	labels := opts.Labels
	var setup *Setup
	if opts.Configure != nil {
		if setup, err = opts.Configure(ctx, name); err != nil {
			return nil, err
		}
		if setup != nil {
			labels = setup.Labels
		}
	}
	// Normalized here too, so a create never carries labels past the API's
	// limits, whoever built them.
	if labels, err = NormalizeLabels(labels); err != nil {
		return nil, fmt.Errorf("invalid project labels: %w", err)
	}

	created, skipped, err := create(ctx, client, tenantID, name, labels)
	if err == nil {
		// Without a valid id the scan would go out unpublished (an empty
		// project_id is omitted) while the CLI reported the project.
		if !api.IsValidProjectID(created.ProjectID) {
			return nil, fmt.Errorf("could not create the project: the API answered without a valid project id (got %q)",
				created.ProjectID)
		}
		res := &Resolution{Project: *created, Created: true, Setup: setup}
		if skipped {
			res.LabelsSkipped, res.RequestedLabels = LabelsSkippedUnsupported, labels
		} else {
			res.Labels = labels
		}
		return res, nil
	}

	// Another run (say a parallel CI job) created the project between the
	// lookup and the create: the 409 names it, so use it, holding it to the
	// same rule as the lookup (exactly this name, case included).
	var apiErr *api.AppSecError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict &&
		apiErr.Code == api.AppSecCodeProjectNameConflict {
		if id := apiErr.ContextString("conflicting_project_id"); api.IsValidProjectID(id) {
			p, getErr := client.GetProject(ctx, tenantID, id)
			if getErr != nil {
				// Unfetched, its name cannot be checked, and adopting it
				// unchecked could publish to a case variant the lookup refuses.
				return nil, explain(getErr, tenantID, "check")
			}
			switch {
			case p.Name == name:
				res := &Resolution{Project: *p, Setup: setup}
				if len(labels) > 0 {
					res.LabelsSkipped, res.RequestedLabels = LabelsSkippedRace, labels
				}
				return res, nil
			case equalFoldASCII(p.Name, name):
				return nil, &CaseMismatchError{Name: name, Existing: []string{p.Name}}
			default:
				return nil, fmt.Errorf("could not create the project: the API reports that the name %q is taken "+
					"by project %s, which is named %q", name, id, p.Name)
			}
		}
	}
	return nil, explain(err, tenantID, "create")
}

// create creates the project as a ci_cd project with labels. A server that
// takes no labels on create (a 422 refusing tags) gets the project without
// them: skipped is then true.
func create(ctx context.Context, client API, tenantID, name string, labels []string) (*model.Project, bool, error) {
	req := model.ProjectCreateRequest{Name: name, ProjectType: model.ProjectTypeCICD, Tags: labels}
	created, err := client.CreateProject(ctx, tenantID, req)
	var apiErr *api.AppSecError
	if err != nil && len(labels) > 0 && errors.As(err, &apiErr) && apiErr.RefusesField("tags") {
		req.Tags = nil
		created, err = client.CreateProject(ctx, tenantID, req)
		return created, err == nil, err
	}
	return created, false, err
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

// lookup pages through the projects whose name, repository or labels contain
// name (the API's only name filter is a case-insensitive substring) for the one
// named exactly name, noting those that differ only in case. It stops early on
// an exact match, and once the pages have gone past every name that could
// match (see below). It gives up (complete=false) after maxLookupPages or on a
// cursor that does not advance.
//
// A server since PPSC-2019 pages by number and says how many pages there are;
// it answers 422 to a cursor or a limit. An older one ignores page and
// page_size: it serves its default page with a next_cursor, and the lookup
// then follows the cursor.
//
// The API sorts name_asc in byte order (checked on dev, uppercase before
// lowercase). Every case variant of an ASCII name sorts at or below its
// all-lowercase form, so once a page ends past that form, no later page can
// hold the name or a variant. That bounds the work for a short name such as
// "api", which matches most projects of a large tenant. The stop is taken only
// between pages, and only while every name seen so far was in byte order, so
// an API that sorted differently would just be read to the end.
func lookup(ctx context.Context, client API, tenantID, name string) (lookupResult, error) {
	var found lookupResult
	cursor := ""
	last := strings.ToLower(name) // the highest any variant can sort
	prev, ordered := "", true
	for page := 1; page <= maxLookupPages; page++ {
		opts := api.ProjectListOptions{
			Query:    name,
			Statuses: lookupStatuses,
			Sort:     lookupSort,
			PageSize: lookupPageSize,
		}
		if cursor != "" {
			opts.Cursor = cursor
		} else {
			opts.Page = page
		}
		resp, err := client.ListProjects(ctx, tenantID, opts)
		if err != nil {
			return lookupResult{}, err
		}
		for i := range resp.Data {
			p := resp.Data[i]
			if p.Name == name {
				found.exact = &p
				return found, nil
			}
			if equalFoldASCII(p.Name, name) {
				found.variants = append(found.variants, p.Name)
			}
			if p.Name < prev {
				ordered = false
			}
			prev = p.Name
		}
		more, next := morePages(resp.Pagination, page)
		if !more {
			found.complete = true
			return found, nil
		}
		if ordered && prev > last {
			found.complete = true
			return found, nil
		}
		if next != "" {
			if next == cursor {
				return found, nil
			}
			cursor = next
		}
	}
	return found, nil
}

// morePages reports whether page is followed by another, and the cursor to it
// from a server that pages by cursor ("" from one that pages by number).
func morePages(p model.ProjectListPagination, page int) (bool, string) {
	if p.TotalPages > 0 {
		return page < p.TotalPages, ""
	}
	if p.NextCursor == nil || *p.NextCursor == "" {
		return false, ""
	}
	return true, *p.NextCursor
}

// equalFoldASCII reports whether a and b are equal ignoring ASCII case. Names
// the CLI accepts are ASCII, so this is what "differs only in case" means for
// them, and it keeps every variant at or below the lowercase name in byte
// order, which lookup relies on.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
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
			// The API answers an unknown tenant and a tenant without AppSec with
			// the same bare 404, so name both: a mistyped tenant ID is the likelier.
			return fmt.Errorf("%w (tenant %s): either no tenant has this ID, or the AppSec UI is not enabled for it. "+
				"Check the tenant ID, or drop --project to scan without publishing: %w", ErrProjectsUnavailable, tenantID, err)
		}
	}
	// Anything else keeps the underlying error so the operator can diagnose it.
	// armis:ignore cwe:209 reason:err is a client-side failure (transport, auth, decode), the retrying client's 5xx summary or the API's error detail, wrapped with %w as on every client.go call; shown only to the CLI's operator, secret-masked by cli.PrintError
	return fmt.Errorf("could not %s the project: %w", action, err)
}

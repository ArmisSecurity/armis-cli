package project

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

const testTenant = "tenant-1"

// testName is the project name most resolver tests look up.
const testName = "svc"

// winnerID is the project a concurrent creator won the name race with.
const winnerID = "p_winner"

// fakeAPI serves scripted project pages and records every call.
type fakeAPI struct {
	// pages maps a cursor ("" for the first page) to the page served for
	// it, as a server before PPSC-2019 pages: by cursor, ignoring page.
	pages map[string]model.ProjectListResponse
	// numbered, when set, are the pages a server since PPSC-2019 serves by
	// number, from 1. It refuses a cursor, and a page past the last is
	// empty.
	numbered []model.ProjectListResponse
	// listErr, when set, fails every ListProjects call.
	listErr error
	// createFn handles CreateProject; nil means "create succeeds".
	createFn func(req model.ProjectCreateRequest) (*model.Project, error)
	// getFn handles GetProject; nil means "not found".
	getFn func(id string) (*model.Project, error)

	listCalls   []api.ProjectListOptions
	createCalls []model.ProjectCreateRequest
	getCalls    []string
}

func (f *fakeAPI) ListProjects(_ context.Context, tenantID string, opts api.ProjectListOptions) (*model.ProjectListResponse, error) {
	if tenantID != testTenant {
		return nil, fmt.Errorf("unexpected tenant %q", tenantID)
	}
	f.listCalls = append(f.listCalls, opts)
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.numbered != nil {
		if opts.Cursor != "" {
			return nil, &api.AppSecError{StatusCode: http.StatusUnprocessableEntity,
				Detail: "query.cursor: Extra inputs are not permitted"}
		}
		n := max(opts.Page, 1)
		if n > len(f.numbered) {
			return &model.ProjectListResponse{Pagination: model.ProjectListPagination{
				Page: n, PageSize: lookupPageSize, TotalPages: len(f.numbered)}}, nil
		}
		resp := f.numbered[n-1]
		return &resp, nil
	}
	page, ok := f.pages[opts.Cursor]
	if !ok {
		return &model.ProjectListResponse{}, nil
	}
	return &page, nil
}

func (f *fakeAPI) CreateProject(_ context.Context, tenantID string, req model.ProjectCreateRequest) (*model.Project, error) {
	if tenantID != testTenant {
		return nil, fmt.Errorf("unexpected tenant %q", tenantID)
	}
	f.createCalls = append(f.createCalls, req)
	if f.createFn != nil {
		return f.createFn(req)
	}
	source := "cli"
	return &model.Project{ProjectID: "p_created", Name: req.Name, ProjectType: req.ProjectType,
		Status: model.ProjectStatusActive, Source: &source}, nil
}

func (f *fakeAPI) GetProject(_ context.Context, tenantID, id string) (*model.Project, error) {
	if tenantID != testTenant {
		return nil, fmt.Errorf("unexpected tenant %q", tenantID)
	}
	f.getCalls = append(f.getCalls, id)
	if f.getFn != nil {
		return f.getFn(id)
	}
	return nil, &api.AppSecError{StatusCode: http.StatusNotFound, Code: "project_not_found"}
}

func page(next string, projects ...model.Project) model.ProjectListResponse {
	resp := model.ProjectListResponse{Data: projects}
	if next != "" {
		resp.Pagination.NextCursor = &next
	}
	return resp
}

// numberedPages are a server's pages by number, each with the page count.
func numberedPages(pages ...[]model.Project) []model.ProjectListResponse {
	total := 0
	for _, projects := range pages {
		total += len(projects)
	}
	out := make([]model.ProjectListResponse, len(pages))
	for i, projects := range pages {
		out[i] = model.ProjectListResponse{Data: projects, Pagination: model.ProjectListPagination{
			Page: i + 1, PageSize: lookupPageSize, TotalItems: total, TotalPages: len(pages)}}
	}
	return out
}

func proj(id, name, status string) model.Project {
	return model.Project{ProjectID: id, Name: name, Status: status, ProjectType: model.ProjectTypeCICD}
}

func conflict(id string) error {
	ctx := map[string]any{}
	if id != "" {
		ctx["conflicting_project_id"] = id
	}
	return &api.AppSecError{StatusCode: http.StatusConflict, Code: api.AppSecCodeProjectNameConflict,
		Detail: "A project with that name already exists", Context: ctx}
}

func TestResolve_ExistingProjectIsReused(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		// Substring matches around the exact one must be skipped.
		"": page("", proj("p_1", "svc-legacy", "active"), proj("p_2", testName, "active"), proj("p_3", "my-svc", "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Created || res.Project.ProjectID != "p_2" {
		t.Errorf("got %+v, want the existing p_2", res)
	}
	if len(f.createCalls) != 0 {
		t.Errorf("an existing project must never be re-created; create calls: %v", f.createCalls)
	}
	if w := res.StatusWarning(); w != "" {
		t.Errorf("active project should not warn, got %q", w)
	}

	// The lookup asks for every status (archived names are still reserved)
	// with the largest page and a stable sort.
	if len(f.listCalls) != 1 {
		t.Fatalf("list calls = %d, want 1", len(f.listCalls))
	}
	got := f.listCalls[0]
	if got.Query != testName || got.Sort != "name_asc" || got.PageSize != 200 || got.Page != 1 || got.Cursor != "" ||
		strings.Join(got.Statuses, ",") != "active,paused,archived" {
		t.Errorf("lookup options = %+v", got)
	}
}

// A server before PPSC-2019 ignores page and page_size, and pages by cursor.
func TestResolve_FollowsAnOlderServersCursor(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		// Sorted as the API sorts (byte order): matches before "svc" first.
		"":   page("c1", proj("p_1", "a-svc", "active")),
		"c1": page("c2", proj("p_2", "my-svc", "active")),
		"c2": page("", proj("p_3", testName, "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Project.ProjectID != "p_3" || res.Created {
		t.Errorf("got %+v, want the existing p_3 from the last page", res)
	}
	cursors := make([]string, 0, len(f.listCalls))
	for i, c := range f.listCalls {
		cursors = append(cursors, c.Cursor)
		// Page 1 is asked by number, as a newer server wants; the cursor's
		// pages by cursor alone.
		wantPage := 0
		if i == 0 {
			wantPage = 1
		}
		if c.Page != wantPage || c.PageSize != 200 {
			t.Errorf("call %d: page %d, page size %d", i, c.Page, c.PageSize)
		}
	}
	if strings.Join(cursors, "|") != "|c1|c2" {
		t.Errorf("cursors = %q, want \"|c1|c2\"", cursors)
	}
}

// A server since PPSC-2019 pages by number, says how many pages there are,
// and refuses a cursor.
func TestResolve_PagesByNumber(t *testing.T) {
	f := &fakeAPI{numbered: numberedPages(
		[]model.Project{proj("p_1", "a-svc", "active")},
		[]model.Project{proj("p_2", "my-svc", "active")},
		[]model.Project{proj("p_3", testName, "active")},
	)}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Project.ProjectID != "p_3" || res.Created {
		t.Errorf("got %+v, want the existing p_3 from the last page", res)
	}
	for i, c := range f.listCalls {
		if c.Page != i+1 || c.Cursor != "" || c.PageSize != 200 {
			t.Errorf("call %d = %+v, want page %d by number", i, c, i+1)
		}
	}
	if len(f.listCalls) != 3 {
		t.Errorf("list calls = %d, want 3", len(f.listCalls))
	}
}

func TestResolve_NumberedLookupEndsOnTheLastPage(t *testing.T) {
	f := &fakeAPI{numbered: numberedPages(
		[]model.Project{proj("p_1", "a-svc", "active")},
		[]model.Project{proj("p_2", "my-svc", "active")},
	)}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !res.Created || len(f.listCalls) != 2 {
		t.Errorf("created = %v after %d list calls; want a create after reading both pages", res.Created, len(f.listCalls))
	}
}

func TestResolve_NumberedLookupStopsOncePastTheName(t *testing.T) {
	f := &fakeAPI{numbered: numberedPages(
		[]model.Project{proj("p_1", "SVC", "active"), proj("p_2", "a-svc", "active")},
		[]model.Project{proj("p_3", "t-svc", "active")},
		[]model.Project{proj("p_4", "svC", "active")}, // never reached: past "svc"
	)}
	_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	var mismatch *CaseMismatchError
	if !errors.As(err, &mismatch) || strings.Join(mismatch.Existing, ",") != "SVC" {
		t.Fatalf("err = %v, want a case mismatch naming SVC", err)
	}
	if len(f.listCalls) != 2 {
		t.Errorf("list calls = %d, want 2 (the second page ends past %q)", len(f.listCalls), testName)
	}
}

func TestResolve_NumberedLookupIsBounded(t *testing.T) {
	pages := make([][]model.Project, maxLookupPages+5)
	for i := range pages {
		// Zero-padded so the pages stay in byte order, all before "svc".
		pages[i] = []model.Project{proj("p_"+strconv.Itoa(i), fmt.Sprintf("a-svc-%03d", i), "active")}
	}
	f := &fakeAPI{numbered: numberedPages(pages...)}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(f.listCalls) != maxLookupPages || !res.Created {
		t.Errorf("list calls = %d, created = %v; want the bound %d, then the fallback create",
			len(f.listCalls), res.Created, maxLookupPages)
	}
}

func TestResolve_StatusWarnings(t *testing.T) {
	scm := proj("p_1", testName, model.ProjectStatusActive)
	scm.ProjectType = "scm"
	for _, tt := range []struct {
		name    string
		project model.Project
		want    string
	}{
		{"archived", proj("p_1", testName, model.ProjectStatusArchived), "is archived"},
		{"not a CLI project", scm, "is not a CLI project (it is a scm project)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("", tt.project)}}
			res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			w := res.StatusWarning()
			if !strings.Contains(w, tt.want) || !strings.Contains(w, "still runs and gates") {
				t.Errorf("warning = %q, want it to mention %q and that the gate still applies", w, tt.want)
			}
			if len(f.createCalls) != 0 {
				t.Error("a found project must not be re-created")
			}
		})
	}
}

// A paused project's schedules stop, but the runs that name it still record
// (AppSec spec 11 Q2), so a CLI scan that names it is no cause for a warning.
func TestResolve_APausedProjectRecordsTheRun(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"": page("", proj("p_1", testName, model.ProjectStatusPaused)),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if w := res.StatusWarning(); w != "" {
		t.Errorf("warning = %q, want none for a paused project", w)
	}
	if len(f.createCalls) != 0 {
		t.Error("a paused project must not be re-created")
	}
}

func TestResolve_CreatesAMissingProject(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"": page("", proj("p_1", "svc-legacy", "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !res.Created || res.Project.ProjectID != "p_created" {
		t.Errorf("got %+v, want a created project", res)
	}
	if len(f.createCalls) != 1 {
		t.Fatalf("create calls = %d, want 1", len(f.createCalls))
	}
	if req := f.createCalls[0]; req.Name != testName || req.ProjectType != model.ProjectTypeCICD {
		t.Errorf("create request = %+v, want name svc and type ci_cd", req)
	}
}

func TestResolve_RefusesCaseOnlyMatch(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"": page("", proj("p_1", "Svc", "active"), proj("p_2", "SVC", "archived")),
	}}
	_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	var caseErr *CaseMismatchError
	if !errors.As(err, &caseErr) {
		t.Fatalf("err = %v, want *CaseMismatchError", err)
	}
	if strings.Join(caseErr.Existing, ",") != "Svc,SVC" {
		t.Errorf("existing = %v", caseErr.Existing)
	}
	msg := err.Error()
	for _, want := range []string{`no project is named "svc"`, "case-sensitive", "--project Svc"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
	if len(f.createCalls) != 0 {
		t.Error("a case-only match must not create a near-duplicate")
	}
}

func TestResolve_ExactMatchWinsOverCaseVariant(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"": page("", proj("p_1", "SVC", "active"), proj("p_2", testName, "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Project.ProjectID != "p_2" {
		t.Errorf("got %s, want the exact match p_2", res.Project.ProjectID)
	}
}

// TestResolve_CreateRace covers two CI jobs creating the same project at once:
// the loser's create returns 409 naming the winner, which it then uses.
func TestResolve_CreateRace(t *testing.T) {
	t.Run("uses the project named by the conflict", func(t *testing.T) {
		f := &fakeAPI{
			pages:    map[string]model.ProjectListResponse{"": page("")},
			createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(winnerID) },
			getFn: func(id string) (*model.Project, error) {
				p := proj(id, testName, model.ProjectStatusActive)
				return &p, nil
			},
		}
		res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if res.Created || res.Project.ProjectID != winnerID || res.Project.Status != model.ProjectStatusActive {
			t.Errorf("got %+v, want the winner p_winner (not created by us)", res)
		}
		if strings.Join(f.getCalls, ",") != winnerID {
			t.Errorf("get calls = %v", f.getCalls)
		}
	})

	// Unfetched, the project's name cannot be held to the lookup's rule, so it
	// is not adopted.
	t.Run("a project that cannot be fetched is not adopted", func(t *testing.T) {
		errReset := errors.New("connection reset")
		f := &fakeAPI{
			pages:    map[string]model.ProjectListResponse{"": page("")},
			createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(winnerID) },
			getFn:    func(string) (*model.Project, error) { return nil, errReset },
		}
		res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
		if !errors.Is(err, errReset) || !strings.Contains(err.Error(), "could not check the project") {
			t.Fatalf("Resolve = %+v, %v; want a check error wrapping %v", res, err, errReset)
		}
	})

	t.Run("a conflict without a usable id is an error", func(t *testing.T) {
		for _, id := range []string{"", "../tenants"} {
			f := &fakeAPI{
				pages:    map[string]model.ProjectListResponse{"": page("")},
				createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(id) },
			}
			if _, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{}); err == nil ||
				!strings.Contains(err.Error(), "could not create the project") {
				t.Fatalf("id %q: err = %v, want a create error", id, err)
			}
			if len(f.getCalls) != 0 {
				t.Errorf("id %q: an unusable id must not be fetched", id)
			}
		}
	})
}

// TestResolve_IncompleteLookupFallsBackToCreate: when the lookup cannot be
// finished, creating is still safe, since a taken name comes back as a 409.
func TestResolve_IncompleteLookupFallsBackToCreate(t *testing.T) {
	t.Run("cursor that does not advance", func(t *testing.T) {
		f := &fakeAPI{
			pages: map[string]model.ProjectListResponse{
				"":   page("c1", proj("p_1", "SVC", "active")),
				"c1": page("c1"), // repeats its own cursor
			},
			createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict("p_svc") },
			getFn: func(id string) (*model.Project, error) {
				p := proj(id, testName, model.ProjectStatusActive)
				return &p, nil
			},
		}
		res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		// A partial lookup cannot prove "SVC" is the only near match, so it
		// does not refuse; the create's 409 then finds the real "svc".
		if res.Project.ProjectID != "p_svc" {
			t.Errorf("got %+v, want p_svc", res.Project)
		}
		if len(f.listCalls) != 2 {
			t.Errorf("list calls = %d, want 2 (stop when the cursor repeats)", len(f.listCalls))
		}
	})

	t.Run("too many pages", func(t *testing.T) {
		pages := map[string]model.ProjectListResponse{}
		for i := 0; i < maxLookupPages+5; i++ {
			cursor := ""
			if i > 0 {
				cursor = "c" + strconv.Itoa(i)
			}
			// Zero-padded so the pages stay in byte order, all before "svc".
			pages[cursor] = page("c"+strconv.Itoa(i+1), proj("p_"+strconv.Itoa(i), fmt.Sprintf("a-svc-%03d", i), "active"))
		}
		f := &fakeAPI{pages: pages}
		res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if len(f.listCalls) != maxLookupPages {
			t.Errorf("list calls = %d, want the bound %d", len(f.listCalls), maxLookupPages)
		}
		if !res.Created {
			t.Error("expected the fallback create")
		}
	})
}

// TestResolve_ValidatesTheName: Resolve checks the name itself, so a caller
// that skipped ValidateName still cannot look up or create an invalid project.
func TestResolve_ValidatesTheName(t *testing.T) {
	for _, name := range []string{"", "my project", "--sync", "null", strings.Repeat("a", 65)} {
		f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
		_, err := Resolve(context.Background(), f, testTenant, name, ResolveOptions{})
		if !errors.Is(err, ErrInvalidName) {
			t.Errorf("Resolve(%q) err = %v, want ErrInvalidName", name, err)
		}
		if len(f.listCalls)+len(f.createCalls)+len(f.getCalls) != 0 {
			t.Errorf("Resolve(%q) must not call the API", name)
		}
	}
}

func TestResolve_ExplainsAPIFailures(t *testing.T) {
	tests := []struct {
		name      string
		listErr   error
		createErr error
		wantIs    error
		wantInMsg []string
	}{
		{
			// The API sends this same bare 404 for an unknown tenant id (seen live
			// on dev) and for a tenant without AppSec, so both must be named.
			name:      "unknown tenant or projects not enabled for it",
			listErr:   &api.AppSecError{StatusCode: http.StatusNotFound, Detail: "Not Found"},
			wantIs:    ErrProjectsUnavailable,
			wantInMsg: []string{"tenant-1", "no tenant has this ID", "AppSec UI is not enabled", "Check the tenant ID", "drop --project"},
		},
		{
			name:      "role cannot list projects",
			listErr:   &api.AppSecError{StatusCode: http.StatusForbidden, Code: api.AppSecCodeInsufficientRole},
			wantIs:    ErrProjectsForbidden,
			wantInMsg: []string{"admin or developer role"},
		},
		{
			name:      "role cannot create projects",
			createErr: &api.AppSecError{StatusCode: http.StatusForbidden, Code: api.AppSecCodeInsufficientRole},
			wantIs:    ErrProjectsForbidden,
		},
		{
			name:      "credentials rejected",
			listErr:   &api.AppSecError{StatusCode: http.StatusUnauthorized, Detail: "Missing or invalid Authorization header"},
			wantIs:    ErrProjectsUnauthorized,
			wantInMsg: []string{"armis-cli auth login"},
		},
		{
			name:      "transport failure",
			listErr:   errors.New("dial tcp: connection refused"),
			wantInMsg: []string{"could not look up the project", "connection refused"},
		},
		{
			name:      "unexpected create failure keeps the API detail",
			createErr: &api.AppSecError{StatusCode: http.StatusUnprocessableEntity, Detail: "name: String should have at most 64 characters"},
			wantInMsg: []string{"could not create the project", "at most 64 characters"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}, listErr: tt.listErr}
			if tt.createErr != nil {
				f.createFn = func(model.ProjectCreateRequest) (*model.Project, error) { return nil, tt.createErr }
			}
			_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("errors.Is(err, %v) = false: %v", tt.wantIs, err)
			}
			for _, want := range tt.wantInMsg {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message missing %q: %v", want, err)
				}
			}
			// The underlying API error stays inspectable.
			var apiErr *api.AppSecError
			if (tt.listErr != nil || tt.createErr != nil) && errors.As(tt.listErr, &apiErr) && !errors.As(err, &apiErr) {
				t.Error("the AppSecError should still be reachable with errors.As")
			}
		})
	}
}

// The API sorts name_asc in byte order, so a new name stops the lookup once a
// page ends past it, instead of paging through every substring match.
func TestResolve_LookupStopsOncePastTheName(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"":   page("c1", proj("p_1", "a-svc", "active"), proj("p_2", "my-svc", "active")),
		"c1": page("c2", proj("p_3", "svc-legacy", "active"), proj("p_4", "t-svc", "active")),
		"c2": page("", proj("p_5", "zz-svc", "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !res.Created {
		t.Errorf("got %+v, want a created project", res)
	}
	if len(f.listCalls) != 2 {
		t.Errorf("list calls = %d, want 2 (the second page ends past %q)", len(f.listCalls), testName)
	}
}

// Uppercase sorts before lowercase, so a case variant is seen before the
// lookup stops, and refused.
func TestResolve_LookupStopStillFindsCaseVariants(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"":   page("c1", proj("p_1", "SVC", "active"), proj("p_2", "a-svc", "active")),
		"c1": page("c2", proj("p_3", "t-svc", "active")),
		"c2": page("", proj("p_4", "svC", "active")), // never reached: past "svc"
	}}
	_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	var mismatch *CaseMismatchError
	if !errors.As(err, &mismatch) || strings.Join(mismatch.Existing, ",") != "SVC" {
		t.Fatalf("err = %v, want a case mismatch naming SVC", err)
	}
	if len(f.createCalls) != 0 || len(f.listCalls) != 2 {
		t.Errorf("create calls = %d, list calls = %d; want 0 and 2", len(f.createCalls), len(f.listCalls))
	}
}

// Names out of byte order mean the API sorted some other way: the lookup then
// reads on rather than trusting the early stop.
func TestResolve_LookupReadsOnWhenNamesAreNotInByteOrder(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"":   page("c1", proj("p_1", "t-svc", "active"), proj("p_2", "a-svc", "active")),
		"c1": page("", proj("p_3", testName, "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Created || res.Project.ProjectID != "p_3" {
		t.Errorf("got %+v, want the existing p_3", res)
	}
}

func TestResolve_CreateMustReturnAValidProjectID(t *testing.T) {
	for _, id := range []string{"", "p/../x"} {
		f := &fakeAPI{
			pages: map[string]model.ProjectListResponse{"": page("")},
			createFn: func(req model.ProjectCreateRequest) (*model.Project, error) {
				return &model.Project{ProjectID: id, Name: req.Name}, nil
			},
		}
		_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
		if err == nil || !strings.Contains(err.Error(), "without a valid project id") {
			t.Errorf("id %q: err = %v, want a missing-id error (an empty project_id would publish nothing)", id, err)
		}
	}
}

// The 409 path holds the project it adopts to the lookup's rule: exactly the
// requested name, case included.
func TestResolve_ConflictAdoptsOnlyTheSameName(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		wantErr  string
	}{
		{name: "the same name is adopted", existing: testName},
		{name: "a case variant is refused", existing: "SVC", wantErr: "differs only in case"},
		{name: "another name is an error", existing: "other", wantErr: `taken by project p_winner, which is named "other"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAPI{
				pages:    map[string]model.ProjectListResponse{"": page("")},
				createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(winnerID) },
				getFn: func(id string) (*model.Project, error) {
					p := proj(id, tt.existing, model.ProjectStatusActive)
					return &p, nil
				},
			}
			res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{})
			if tt.wantErr == "" {
				if err != nil || res.Project.ProjectID != winnerID {
					t.Fatalf("Resolve = %+v, %v; want project %s", res, err, winnerID)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestEqualFoldASCII(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"svc", "SVC", true},
		{"Team/Svc-1.x", "team/svc-1.X", true},
		{"svc", "svcs", false},
		{"svc", "svd", false},
		// Unicode folding (strings.EqualFold) would call these equal; for
		// ASCII project names they are distinct.
		{"ſvc", "svc", false},
		{"\u212Avc", "kvc", false}, // the Kelvin sign folds to k in Unicode
	}
	for _, tt := range tests {
		if got := equalFoldASCII(tt.a, tt.b); got != tt.want {
			t.Errorf("equalFoldASCII(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestResolve_ConfigureRunsOnlyWhenCreating(t *testing.T) {
	ctx := context.Background()
	called := false
	configure := func(context.Context, string) (*Setup, error) {
		called = true
		return &Setup{}, nil
	}

	// An existing project is used as it is: no setup.
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("", proj("p_1", testName, "active"))}}
	res, err := Resolve(ctx, f, testTenant, testName, ResolveOptions{Configure: configure})
	if err != nil || res.Project.ProjectID != "p_1" || called || len(f.createCalls) != 0 {
		t.Fatalf("existing project: res %+v, err %v, setup called %v, creates %d", res, err, called, len(f.createCalls))
	}

	// A missing one runs the setup once, and is created with its labels.
	f = &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	setup := &Setup{Labels: []string{"team-a"}, Filters: Filters{CWEs: []int{79}}}
	var gotName string
	res, err = Resolve(ctx, f, testTenant, testName, ResolveOptions{
		Labels: []string{"from-flag"},
		Configure: func(_ context.Context, name string) (*Setup, error) {
			gotName = name
			return setup, nil
		},
	})
	if err != nil || !res.Created || res.Setup != setup || gotName != testName {
		t.Fatalf("missing project: res %+v, err %v, setup asked for %q", res, err, gotName)
	}
	if len(f.createCalls) != 1 || strings.Join(f.createCalls[0].Tags, ",") != "team-a" ||
		strings.Join(res.Labels, ",") != "team-a" || res.LabelsSkipped != "" {
		t.Errorf("created with %+v; resolution labels %q, skipped %q", f.createCalls, res.Labels, res.LabelsSkipped)
	}
}

func TestResolve_ANilSetupIsTheDefaults(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{
		Labels:    []string{"from-flag"},
		Configure: func(context.Context, string) (*Setup, error) { return nil, nil },
	})
	if err != nil || !res.Created || res.Setup != nil || strings.Join(f.createCalls[0].Tags, ",") != "from-flag" {
		t.Errorf("res %+v, err %v, creates %+v; want a create with the flag's labels and no setup", res, err, f.createCalls)
	}
}

func TestResolve_ACancelledSetupCreatesNothing(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	_, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{
		Configure: func(context.Context, string) (*Setup, error) { return nil, ErrSetupCancelled },
	})
	if !errors.Is(err, ErrSetupCancelled) || len(f.createCalls) != 0 {
		t.Errorf("err = %v after %d creates; want ErrSetupCancelled and none", err, len(f.createCalls))
	}
}

func TestResolve_SendsTheLabelsWithoutASetup(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{Labels: []string{"pci"}})
	if err != nil || strings.Join(f.createCalls[0].Tags, ",") != "pci" || strings.Join(res.Labels, ",") != "pci" {
		t.Fatalf("res %+v, err %v, creates %+v", res, err, f.createCalls)
	}

	// No labels: the create body carries none (tags is omitted).
	f = &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	if _, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{}); err != nil || f.createCalls[0].Tags != nil {
		t.Errorf("err %v, tags %q", err, f.createCalls[0].Tags)
	}
}

func TestResolve_LeavesAnExistingProjectsLabels(t *testing.T) {
	existing := proj("p_1", testName, "active")
	existing.Tags = []string{"team", "pci"}
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("", existing)}}

	// The same labels, in another order and case: nothing to say.
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{Labels: []string{"PCI", "team"}})
	if err != nil || res.LabelsSkipped != "" {
		t.Errorf("same labels: skipped %q, err %v", res.LabelsSkipped, err)
	}
	// Others are not applied, and say so.
	res, err = Resolve(context.Background(), f, testTenant, testName, ResolveOptions{Labels: []string{"other"}})
	if err != nil || res.LabelsSkipped != LabelsSkippedExists || strings.Join(res.RequestedLabels, ",") != "other" {
		t.Errorf("other labels: res %+v, err %v", res, err)
	}
	if len(f.createCalls) != 0 {
		t.Errorf("an existing project must never be re-created: %+v", f.createCalls)
	}
}

func TestResolve_ARaceKeepsTheSetupButNotTheLabels(t *testing.T) {
	f := &fakeAPI{
		pages:    map[string]model.ProjectListResponse{"": page("")},
		createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(winnerID) },
		getFn: func(id string) (*model.Project, error) {
			p := proj(id, testName, model.ProjectStatusActive)
			return &p, nil
		},
	}
	setup := &Setup{Labels: []string{"pci"}, Filters: Filters{CWEs: []int{79}}}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{
		Configure: func(context.Context, string) (*Setup, error) { return setup, nil },
	})
	if err != nil || res.Project.ProjectID != winnerID || res.Created {
		t.Fatalf("res %+v, err %v; want the winner, adopted", res, err)
	}
	// The filters belong to the repository, so they are still written; the
	// labels were not applied.
	if res.Setup != setup || res.LabelsSkipped != LabelsSkippedRace || strings.Join(res.RequestedLabels, ",") != "pci" {
		t.Errorf("res %+v", res)
	}
}

func TestResolve_AServerWithoutLabelsGetsTheProjectWithoutThem(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	f.createFn = func(req model.ProjectCreateRequest) (*model.Project, error) {
		if len(req.Tags) > 0 {
			return nil, &api.AppSecError{StatusCode: http.StatusUnprocessableEntity,
				Invalid: []api.InvalidField{{Field: "tags", Type: "extra_forbidden"}}}
		}
		p := proj("p_created", req.Name, model.ProjectStatusActive)
		return &p, nil
	}
	res, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{Labels: []string{"pci"}})
	if err != nil || !res.Created || len(f.createCalls) != 2 || f.createCalls[1].Tags != nil {
		t.Fatalf("res %+v, err %v, creates %+v", res, err, f.createCalls)
	}
	if res.LabelsSkipped != LabelsSkippedUnsupported || res.Labels != nil {
		t.Errorf("labels %q, skipped %q", res.Labels, res.LabelsSkipped)
	}

	// Any other 422 is the create's own failure, never retried.
	f = &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("")}}
	f.createFn = func(model.ProjectCreateRequest) (*model.Project, error) {
		return nil, &api.AppSecError{StatusCode: http.StatusUnprocessableEntity,
			Invalid: []api.InvalidField{{Field: "tags", Type: "string_too_long"}}}
	}
	if _, err := Resolve(context.Background(), f, testTenant, testName, ResolveOptions{Labels: []string{"pci"}}); err == nil || len(f.createCalls) != 1 {
		t.Errorf("err %v after %d creates; want the 422, once", err, len(f.createCalls))
	}
}

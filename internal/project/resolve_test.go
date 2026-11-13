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
	// pages maps a cursor ("" for the first page) to the page served for it.
	pages map[string]model.ProjectListResponse
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
	res, err := Resolve(context.Background(), f, testTenant, testName)
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
	if got.Query != testName || got.Sort != "name_asc" || got.Limit != 200 ||
		strings.Join(got.Statuses, ",") != "active,paused,archived" {
		t.Errorf("lookup options = %+v", got)
	}
}

func TestResolve_FollowsPagination(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"":   page("c1", proj("p_1", "svc-a", "active")),
		"c1": page("c2", proj("p_2", "svc-b", "active")),
		"c2": page("", proj("p_3", testName, "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if res.Project.ProjectID != "p_3" || res.Created {
		t.Errorf("got %+v, want the existing p_3 from the last page", res)
	}
	cursors := make([]string, 0, len(f.listCalls))
	for _, c := range f.listCalls {
		cursors = append(cursors, c.Cursor)
	}
	if strings.Join(cursors, "|") != "|c1|c2" {
		t.Errorf("cursors = %q, want \"|c1|c2\"", cursors)
	}
}

func TestResolve_StatusWarnings(t *testing.T) {
	for _, tt := range []struct {
		status string
		want   string
	}{
		{model.ProjectStatusPaused, "is paused"},
		{model.ProjectStatusArchived, "is archived"},
	} {
		t.Run(tt.status, func(t *testing.T) {
			f := &fakeAPI{pages: map[string]model.ProjectListResponse{"": page("", proj("p_1", testName, tt.status))}}
			res, err := Resolve(context.Background(), f, testTenant, testName)
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			w := res.StatusWarning()
			if !strings.Contains(w, tt.want) || !strings.Contains(w, "still runs and gates") {
				t.Errorf("warning = %q, want it to mention %q and that the gate still applies", w, tt.want)
			}
			if len(f.createCalls) != 0 {
				t.Error("a paused or archived project must not be re-created")
			}
		})
	}
}

func TestResolve_CreatesAMissingProject(t *testing.T) {
	f := &fakeAPI{pages: map[string]model.ProjectListResponse{
		"": page("", proj("p_1", "svc-legacy", "active")),
	}}
	res, err := Resolve(context.Background(), f, testTenant, testName)
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
	_, err := Resolve(context.Background(), f, testTenant, testName)
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
	res, err := Resolve(context.Background(), f, testTenant, testName)
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
		res, err := Resolve(context.Background(), f, testTenant, testName)
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

	t.Run("still uses the id when it cannot be fetched", func(t *testing.T) {
		f := &fakeAPI{
			pages:    map[string]model.ProjectListResponse{"": page("")},
			createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(winnerID) },
			getFn:    func(string) (*model.Project, error) { return nil, errors.New("connection reset") },
		}
		res, err := Resolve(context.Background(), f, testTenant, testName)
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if res.Project.ProjectID != winnerID || res.Project.Name != testName {
			t.Errorf("got %+v", res.Project)
		}
	})

	t.Run("a conflict without a usable id is an error", func(t *testing.T) {
		for _, id := range []string{"", "../tenants"} {
			f := &fakeAPI{
				pages:    map[string]model.ProjectListResponse{"": page("")},
				createFn: func(model.ProjectCreateRequest) (*model.Project, error) { return nil, conflict(id) },
			}
			if _, err := Resolve(context.Background(), f, testTenant, testName); err == nil ||
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
		res, err := Resolve(context.Background(), f, testTenant, testName)
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
			pages[cursor] = page("c"+strconv.Itoa(i+1), proj("p_"+strconv.Itoa(i), "svc-"+strconv.Itoa(i), "active"))
		}
		f := &fakeAPI{pages: pages}
		res, err := Resolve(context.Background(), f, testTenant, testName)
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
		_, err := Resolve(context.Background(), f, testTenant, name)
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
			_, err := Resolve(context.Background(), f, testTenant, testName)
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

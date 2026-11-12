package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const testProjectsTenant = "tenant-abc"

// testNextCursor is the next_cursor the list test serves.
const testNextCursor = "cursor-2"

// newProjectsClient builds a client for an httptest server with retries off,
// so error-path tests do not wait out backoff.
func newProjectsClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	c, err := NewClient(baseURL, testutil.NewTestAuthProvider("token123"), false, time.Minute,
		WithHTTPClient(httpClient), WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return c
}

func TestClient_ListProjects(t *testing.T) {
	t.Parallel()

	t.Run("sends every filter and decodes the page", func(t *testing.T) {
		t.Parallel()
		var gotQuery url.Values
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/appsec/projects" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Basic token123" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			gotQuery = r.URL.Query()
			next := testNextCursor
			testutil.JSONResponse(t, w, http.StatusOK, model.ProjectListResponse{
				Data: []model.Project{
					{ProjectID: "p_1", Name: "svc", ProjectType: model.ProjectTypeCICD, Status: model.ProjectStatusActive},
				},
				Pagination: model.ProjectListPagination{NextCursor: &next, Limit: 200},
			})
		})

		resp, err := newProjectsClient(t, srv.URL).ListProjects(context.Background(), testProjectsTenant, ProjectListOptions{
			Query:    "svc",
			Statuses: []string{model.ProjectStatusActive, model.ProjectStatusPaused, model.ProjectStatusArchived},
			Sort:     "name_asc",
			Limit:    200,
			Cursor:   "cursor-1",
		})
		if err != nil {
			t.Fatalf("ListProjects failed: %v", err)
		}

		want := url.Values{
			"tenant_id": {testProjectsTenant},
			"q":         {"svc"},
			"status":    {"active", "paused", "archived"},
			"sort":      {"name_asc"},
			"limit":     {"200"},
			"cursor":    {"cursor-1"},
		}
		for key, vals := range want {
			if strings.Join(gotQuery[key], ",") != strings.Join(vals, ",") {
				t.Errorf("query %s = %v, want %v", key, gotQuery[key], vals)
			}
		}
		if len(resp.Data) != 1 || resp.Data[0].ProjectID != "p_1" || resp.Data[0].Name != "svc" {
			t.Errorf("unexpected data: %+v", resp.Data)
		}
		if resp.Pagination.NextCursor == nil || *resp.Pagination.NextCursor != testNextCursor {
			t.Errorf("next_cursor = %v, want cursor-2", resp.Pagination.NextCursor)
		}
	})

	t.Run("omits unset filters", func(t *testing.T) {
		t.Parallel()
		var rawQuery string
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			rawQuery = r.URL.RawQuery
			testutil.JSONResponse(t, w, http.StatusOK, model.ProjectListResponse{})
		})
		if _, err := newProjectsClient(t, srv.URL).ListProjects(context.Background(), testProjectsTenant, ProjectListOptions{}); err != nil {
			t.Fatalf("ListProjects failed: %v", err)
		}
		if rawQuery != "tenant_id="+testProjectsTenant {
			t.Errorf("query = %q, want only tenant_id", rawQuery)
		}
	})

	t.Run("rejects an out-of-range page size without a request", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(_ http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		})
		client := newProjectsClient(t, srv.URL)
		for _, limit := range []int{-1, MaxProjectListLimit + 1} {
			if _, err := client.ListProjects(context.Background(), testProjectsTenant, ProjectListOptions{Limit: limit}); err == nil {
				t.Errorf("Limit %d: expected an error", limit)
			}
		}
	})

	t.Run("encodes a query with reserved URL characters", func(t *testing.T) {
		t.Parallel()
		var gotQ string
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			gotQ = r.URL.Query().Get("q")
			testutil.JSONResponse(t, w, http.StatusOK, model.ProjectListResponse{})
		})
		const name = "team/a&b=c"
		if _, err := newProjectsClient(t, srv.URL).ListProjects(context.Background(), testProjectsTenant, ProjectListOptions{Query: name}); err != nil {
			t.Fatalf("ListProjects failed: %v", err)
		}
		if gotQ != name {
			t.Errorf("q = %q, want %q", gotQ, name)
		}
	})
}

func TestClient_CreateProject(t *testing.T) {
	t.Parallel()

	t.Run("posts only declared fields and decodes the 201", func(t *testing.T) {
		t.Parallel()
		var gotBody []byte
		var gotTenant, gotContentType string
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/appsec/projects" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			gotTenant = r.URL.Query().Get("tenant_id")
			gotContentType = r.Header.Get("Content-Type")
			gotBody, _ = io.ReadAll(r.Body)
			source := "cli"
			testutil.JSONResponse(t, w, http.StatusCreated, model.Project{
				ProjectID: "p_new", Name: "svc", ProjectType: model.ProjectTypeCICD,
				Status: model.ProjectStatusActive, Source: &source,
			})
		})

		p, err := newProjectsClient(t, srv.URL).CreateProject(context.Background(), testProjectsTenant,
			model.ProjectCreateRequest{Name: "svc", ProjectType: model.ProjectTypeCICD})
		if err != nil {
			t.Fatalf("CreateProject failed: %v", err)
		}
		if gotTenant != testProjectsTenant {
			t.Errorf("tenant_id = %q", gotTenant)
		}
		if gotContentType != "application/json" {
			t.Errorf("Content-Type = %q", gotContentType)
		}
		// The API rejects unknown fields with 422, so the body must be exactly these two.
		if string(gotBody) != `{"name":"svc","project_type":"ci_cd"}` {
			t.Errorf("body = %s", gotBody)
		}
		if p.ProjectID != "p_new" || p.Source == nil || *p.Source != "cli" {
			t.Errorf("unexpected project: %+v", p)
		}
	})

	t.Run("name conflict is a typed AppSecError with the holder's id", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.JSONResponse(t, w, http.StatusConflict, map[string]any{
				"detail":  `A project named "svc" already exists in this tenant.`,
				"error":   "project_name_conflict",
				"context": map[string]any{"conflicting_project_id": "p_existing"},
			})
		})
		_, err := newProjectsClient(t, srv.URL).CreateProject(context.Background(), testProjectsTenant,
			model.ProjectCreateRequest{Name: "svc", ProjectType: model.ProjectTypeCICD})

		var apiErr *AppSecError
		if !errors.As(err, &apiErr) {
			t.Fatalf("error is %T (%v), want *AppSecError", err, err)
		}
		if apiErr.StatusCode != http.StatusConflict || apiErr.Code != AppSecCodeProjectNameConflict {
			t.Errorf("got %d/%q, want 409/%q", apiErr.StatusCode, apiErr.Code, AppSecCodeProjectNameConflict)
		}
		if got := apiErr.ContextString("conflicting_project_id"); got != "p_existing" {
			t.Errorf("conflicting_project_id = %q", got)
		}
		if !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("message = %q", err.Error())
		}
	})
}

func TestClient_GetProject(t *testing.T) {
	t.Parallel()

	t.Run("fetches by id without run history", func(t *testing.T) {
		t.Parallel()
		var gotPath, gotRecent string
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotRecent = r.URL.Query().Get("recent_scans")
			testutil.JSONResponse(t, w, http.StatusOK, model.Project{ProjectID: "p_1", Name: "svc", Status: model.ProjectStatusPaused})
		})
		p, err := newProjectsClient(t, srv.URL).GetProject(context.Background(), testProjectsTenant, "p_1")
		if err != nil {
			t.Fatalf("GetProject failed: %v", err)
		}
		if gotPath != "/api/v1/appsec/projects/p_1" || gotRecent != "0" {
			t.Errorf("path = %q recent_scans = %q", gotPath, gotRecent)
		}
		if p.Status != model.ProjectStatusPaused {
			t.Errorf("status = %q", p.Status)
		}
	})

	t.Run("rejects an id with path syntax, or none, without a request", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(_ http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		})
		client := newProjectsClient(t, srv.URL)
		for _, id := range []string{"", "..", "../tenants?x=1", "p/1", "p%2F1", "p_1#x", strings.Repeat("p", 129)} {
			if _, err := client.GetProject(context.Background(), testProjectsTenant, id); err == nil {
				t.Errorf("GetProject(%q): expected an error", id)
			}
		}
	})
}

func TestParseAppSecError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		body       string
		wantCode   string
		wantDetail string
	}{
		{
			name:       "AppSec envelope",
			status:     http.StatusForbidden,
			body:       `{"detail":"Caller lacks the required role","error":"insufficient_role","context":{"required":["admin","developer"]}}`,
			wantCode:   AppSecCodeInsufficientRole,
			wantDetail: "Caller lacks the required role",
		},
		{
			// The 404 returned when appsec_ui_enabled is off has no code.
			name:       "bare detail",
			status:     http.StatusNotFound,
			body:       `{"detail":"Not Found"}`,
			wantDetail: "Not Found",
		},
		{
			name:       "FastAPI validation list",
			status:     http.StatusUnprocessableEntity,
			body:       `{"detail":[{"type":"string_too_long","loc":["body","name"],"msg":"String should have at most 64 characters"},{"loc":["query","tenant_id"],"msg":"Field required"}]}`,
			wantDetail: "name: String should have at most 64 characters; tenant_id: Field required",
		},
		{
			name:       "non-JSON body from a proxy",
			status:     http.StatusBadGateway,
			body:       "<html>bad gateway</html>",
			wantDetail: "<html>bad gateway</html>",
		},
		{
			name:       "empty body",
			status:     http.StatusUnauthorized,
			body:       "",
			wantDetail: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseAppSecError(tt.status, []byte(tt.body))
			if got.StatusCode != tt.status || got.Code != tt.wantCode || got.Detail != tt.wantDetail {
				t.Errorf("got {%d %q %q}, want {%d %q %q}", got.StatusCode, got.Code, got.Detail, tt.status, tt.wantCode, tt.wantDetail)
			}
			if got.Error() == "" {
				t.Error("Error() is empty")
			}
		})
	}

	t.Run("long unparseable body is truncated", func(t *testing.T) {
		t.Parallel()
		got := parseAppSecError(http.StatusBadGateway, []byte(strings.Repeat("x", 5000)))
		if len(got.Detail) > maxErrorDetailLen+3 {
			t.Errorf("detail length = %d, want <= %d", len(got.Detail), maxErrorDetailLen+3)
		}
	})

	t.Run("empty detail falls back to the status text", func(t *testing.T) {
		t.Parallel()
		got := parseAppSecError(http.StatusUnauthorized, nil)
		if !strings.Contains(got.Error(), "Unauthorized") {
			t.Errorf("Error() = %q, want the status text", got.Error())
		}
	})
}

// TestAppSecURL_StaysOnTheAPIHost: whatever path a caller passes, the request
// can never leave the configured API host.
func TestAppSecURL_StaysOnTheAPIHost(t *testing.T) {
	t.Parallel()
	c, err := NewClient("https://moose.example.com", testutil.NewTestAuthProvider("t"), false, time.Minute)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	got, err := c.appSecURL("/api/v1/appsec/projects/p_1", url.Values{"tenant_id": {"t1"}, "q": {"a&b"}})
	if err != nil {
		t.Fatalf("appSecURL failed: %v", err)
	}
	if got != "https://moose.example.com/api/v1/appsec/projects/p_1?q=a%26b&tenant_id=t1" {
		t.Errorf("url = %q", got)
	}

	if got, err := c.appSecURL("/api/v1/appsec/projects", nil); err != nil || strings.Contains(got, "?") {
		t.Errorf("no params should mean no query: %q, %v", got, err)
	}

	// Only the allowlisted routes are accepted.
	for _, path := range []string{
		"@evil.example/steal",               // would make the API host userinfo
		"//evil.example/x",                  // scheme-relative
		"evil.example",                      // relative
		"",                                  //
		"/api/v1/tenants",                   // another route
		"/api/v1/appsec/projects/../x",      // traversal
		"/api/v1/appsec/projects/p_1/extra", // extra segment
		"/api/v1/appsec/projects/p_1?x=1",   // query smuggled in the path
		"/api/v1/appsec/projects/p%2F1",     // escaped separator
		"/api/v1/appsec/projectsX",          // prefix only
	} {
		if got, err := c.appSecURL(path, nil); err == nil {
			t.Errorf("appSecURL(%q) = %q, want an error", path, got)
		}
	}
}

func TestIsValidProjectID(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{
		"p_507f1f77bcf86cd799439012": true,
		"p-1":                        true,
		"":                           false,
		"..":                         false,
		"p/1":                        false,
		"p 1":                        false,
		strings.Repeat("a", 128):     true,
		strings.Repeat("a", 129):     false,
	} {
		if got := IsValidProjectID(id); got != want {
			t.Errorf("IsValidProjectID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestClient_ProjectsDecodeError(t *testing.T) {
	t.Parallel()
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	})
	_, err := newProjectsClient(t, srv.URL).ListProjects(context.Background(), testProjectsTenant, ProjectListOptions{})
	if err == nil || !strings.Contains(err.Error(), "failed to decode") {
		t.Fatalf("err = %v, want a decode error", err)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Errorf("decode error should wrap the JSON error, got %T", err)
	}
}

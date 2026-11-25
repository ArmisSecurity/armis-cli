package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const (
	testRunProject = "p_66f2a1b2c3d4e5f6a7b8c9d0"
	testRunID      = "s_6730a1b2c3d4e5f6a7b8c9d0"
	testRunPath    = "/api/v1/appsec/projects/" + testRunProject + "/scans/" + testRunID + "/findings"
)

// runFindingsPage is one page of a run's findings, as the AppSec route
// answers for a run of total findings over pages, one of them suppressed.
func runFindingsPage(page, pages, total int, ids ...string) map[string]any {
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, map[string]any{
			"finding_id": id, "title": "t", "type": "sast", "severity": "high",
			"detail": map[string]any{"finding_id": id, "identifiers": map[string]any{"cwes": []string{"CWE-89"}}},
		})
	}
	return map[string]any{
		"data":        rows,
		"pagination":  map[string]any{"page": page, "page_size": 100, "total_items": total, "total_pages": pages},
		"counts":      map[string]any{"total": total - 1, "matching": total, "suppressed": 1},
		"truncated":   false,
		"empty_state": nil,
		"scan":        map[string]any{"scan_id": testRunID},
	}
}

func TestClient_ListProjectRunFindings(t *testing.T) {
	t.Parallel()
	var gotPath, gotAuth string
	var gotQuery map[string][]string
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotQuery = r.URL.Path, r.Header.Get("Authorization"), r.URL.Query()
		testutil.JSONResponse(t, w, http.StatusOK, runFindingsPage(2, 3, 250, "f_a"))
	})

	page, err := newProjectsClient(t, srv.URL).ListProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID, 2)
	if err != nil {
		t.Fatalf("ListProjectRunFindings failed: %v", err)
	}
	if gotPath != testRunPath {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth == "" {
		t.Error("the request carried no Authorization header")
	}
	want := map[string]string{
		"tenant_id": testProjectsTenant, "page": "2", "page_size": "100",
		"expand": "detail", "suppressed": "include",
	}
	if len(gotQuery) != len(want) {
		t.Errorf("query = %v, want exactly %v", gotQuery, want)
	}
	for key, value := range want {
		if got := gotQuery[key]; len(got) != 1 || got[0] != value {
			t.Errorf("query %s = %v, want %q", key, got, value)
		}
	}
	if len(page.Data) != 1 || page.Data[0].Detail == nil || page.Data[0].Detail.Identifiers.CWEs[0] != "CWE-89" {
		t.Errorf("page = %+v", page.Data)
	}
	if page.Counts == nil || page.Counts.Suppressed != 1 || page.Pagination.TotalPages != 3 {
		t.Errorf("counts = %+v, pagination = %+v", page.Counts, page.Pagination)
	}
}

func TestClient_ListProjectRunFindings_RefusesIDsAndPagesWithoutARequest(t *testing.T) {
	t.Parallel()
	srv := testutil.NewTestServer(t, func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	client := newProjectsClient(t, srv.URL)
	for _, tt := range []struct {
		name, project, run string
		page               int
	}{
		{"a project id with path syntax", "p/1", testRunID, 1},
		{"no run id", testRunProject, "", 1},
		{"a run id of another shape", testRunProject, "s_1", 1},
		{"a run id with path syntax", testRunProject, "s_6730a1b2c3d4e5f6a7b8c9d0/../x", 1},
		{"an upper-case run id", testRunProject, "s_6730A1B2C3D4E5F6A7B8C9D0", 1},
		{"page 0", testRunProject, testRunID, 0},
		{"a page past the cap", testRunProject, testRunID, MaxProjectRunFindingsPages + 1},
	} {
		if _, err := client.ListProjectRunFindings(context.Background(), testProjectsTenant, tt.project, tt.run, tt.page); err == nil {
			t.Errorf("%s: expected an error", tt.name)
		}
	}
}

func TestClient_FetchAllProjectRunFindings(t *testing.T) {
	t.Parallel()

	t.Run("reads every page up to total_pages", func(t *testing.T) {
		t.Parallel()
		var pages []string
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			pages = append(pages, page)
			n, _ := strconv.Atoi(page)
			testutil.JSONResponse(t, w, http.StatusOK, runFindingsPage(n, 3, 3, fmt.Sprintf("f_%d", n)))
		})
		read, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if err != nil {
			t.Fatalf("FetchAllProjectRunFindings failed: %v", err)
		}
		if strings.Join(pages, ",") != "1,2,3" {
			t.Errorf("pages read = %v", pages)
		}
		if len(read.Findings) != 3 || read.Findings[2].FindingID != "f_3" {
			t.Errorf("findings = %+v", read.Findings)
		}
		if read.Counts.Total != 2 || read.EmptyReason != "" || read.Truncated {
			t.Errorf("read = %+v", read)
		}
	})

	t.Run("an empty state reads one page", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			testutil.JSONResponse(t, w, http.StatusOK, map[string]any{
				"data": []any{}, "pagination": map[string]any{"page": 1, "page_size": 100, "total_items": 0, "total_pages": 1},
				"counts": nil, "truncated": false, "empty_state": map[string]any{"reason": "not_finished"},
			})
		})
		read, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if err != nil {
			t.Fatalf("FetchAllProjectRunFindings failed: %v", err)
		}
		if read.EmptyReason != model.RunFindingsNotFinished || calls.Load() != 1 {
			t.Errorf("reason = %q after %d calls", read.EmptyReason, calls.Load())
		}
	})

	t.Run("more pages than the history holds is an error, not a partial read", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			testutil.JSONResponse(t, w, http.StatusOK, runFindingsPage(1, MaxProjectRunFindingsPages+1, MaxProjectRunFindings+1, "f_1"))
		})
		_, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if !errors.Is(err, ErrRunFindingsTooLarge) {
			t.Errorf("err = %v, want ErrRunFindingsTooLarge", err)
		}
		if calls.Load() != 1 {
			t.Errorf("read %d pages, want 1", calls.Load())
		}
	})

	t.Run("a page larger than its page size is refused", func(t *testing.T) {
		t.Parallel()
		ids := make([]string, ProjectRunFindingsPageSize+1)
		for i := range ids {
			ids[i] = fmt.Sprintf("f_%d", i)
		}
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.JSONResponse(t, w, http.StatusOK, runFindingsPage(1, 1, len(ids), ids...))
		})
		_, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if !errors.Is(err, ErrRunFindingsTooLarge) {
			t.Errorf("err = %v, want ErrRunFindingsTooLarge", err)
		}
	})

	// AC 28: a read never passes on findings it didn't read. Each case is a
	// list that doesn't add up, page by page.
	for _, tt := range []struct {
		name  string
		pages func(page int) map[string]any
	}{
		{"a page short of what the list holds", func(page int) map[string]any {
			if page == 1 {
				return runFindingsPage(1, 2, 3, "f_1", "f_2")
			}
			return runFindingsPage(2, 2, 3)
		}},
		{"a later page with an empty state", func(page int) map[string]any {
			if page == 1 {
				return runFindingsPage(1, 2, 2, "f_1")
			}
			answer := runFindingsPage(2, 1, 0)
			answer["counts"], answer["empty_state"] = nil, map[string]any{"reason": "not_recorded"}
			return answer
		}},
		{"a later page that lists another total", func(page int) map[string]any {
			if page == 1 {
				return runFindingsPage(1, 2, 2, "f_1")
			}
			return runFindingsPage(2, 3, 3, "f_2")
		}},
		{"a finding on two pages", func(page int) map[string]any {
			return runFindingsPage(page, 2, 2, "f_1")
		}},
		{"a run that counts a finding it served no row for", func(int) map[string]any {
			answer := runFindingsPage(1, 1, 2, "f_1", "f_2")
			answer["counts"] = map[string]any{"total": 2, "matching": 2, "suppressed": 1}
			return answer
		}},
		{"a run served without its counts", func(int) map[string]any {
			answer := runFindingsPage(1, 1, 1, "f_1")
			answer["counts"] = nil
			return answer
		}},
	} {
		t.Run(tt.name+" is incomplete", func(t *testing.T) {
			t.Parallel()
			srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				testutil.JSONResponse(t, w, http.StatusOK, tt.pages(page))
			})
			read, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
			if !errors.Is(err, ErrRunFindingsIncomplete) {
				t.Errorf("read = %+v, err = %v, want ErrRunFindingsIncomplete", read, err)
			}
		})
	}

	t.Run("a truncated run counts more findings than it kept", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			answer := runFindingsPage(1, 1, 2, "f_1", "f_2")
			answer["truncated"] = true
			answer["counts"] = map[string]any{"total": 60_000, "matching": 2, "suppressed": 5}
			testutil.JSONResponse(t, w, http.StatusOK, answer)
		})
		read, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if err != nil || len(read.Findings) != 2 || !read.Truncated {
			t.Errorf("read = %+v, err = %v", read, err)
		}
	})

	t.Run("a run whose every finding is suppressed adds up", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			answer := runFindingsPage(1, 1, 2, "f_1", "f_2")
			answer["counts"] = map[string]any{"total": 0, "matching": 2, "suppressed": 2}
			testutil.JSONResponse(t, w, http.StatusOK, answer)
		})
		read, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if err != nil || len(read.Findings) != 2 {
			t.Errorf("read = %+v, err = %v", read, err)
		}
	})

	t.Run("a 4xx is an AppSecError", func(t *testing.T) {
		t.Parallel()
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"No such scan run in this project.","error":"scan_not_found","context":{}}`))
		})
		_, err := newProjectsClient(t, srv.URL).FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		var appSecErr *AppSecError
		if !errors.As(err, &appSecErr) || appSecErr.StatusCode != http.StatusNotFound || appSecErr.Code != "scan_not_found" {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a 5xx is retried", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		srv := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			testutil.JSONResponse(t, w, http.StatusOK, runFindingsPage(1, 1, 1, "f_1"))
		})
		httpClient := httpclient.NewClient(httpclient.Config{
			Timeout: 5 * time.Second, RetryMax: 2, RetryWaitMin: time.Millisecond, RetryWaitMax: 5 * time.Millisecond,
		})
		client, err := NewClient(srv.URL, testutil.NewTestAuthProvider("token123"), false, time.Minute,
			WithHTTPClient(httpClient), WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		read, err := client.FetchAllProjectRunFindings(context.Background(), testProjectsTenant, testRunProject, testRunID)
		if err != nil || len(read.Findings) != 1 || calls.Load() != 2 {
			t.Errorf("read = %+v, err = %v after %d calls", read, err, calls.Load())
		}
	})
}

func TestRunFindingsPage_EmptyReason(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]string{
		"not_finished": model.RunFindingsNotFinished,
		"run_failed":   model.RunFindingsRunFailed,
		"no_findings":  model.RunFindingsNoFindings,
		"not_recorded": model.RunFindingsNotRecorded,
		// A newer server's reason takes the legacy read.
		"archived_somehow": model.RunFindingsNotRecorded,
	} {
		page := model.RunFindingsPage{EmptyState: &model.RunFindingsEmptyState{Reason: reason}}
		if got := page.EmptyReason(); got != want {
			t.Errorf("EmptyReason(%q) = %q, want %q", reason, got, want)
		}
	}
	if got := (&model.RunFindingsPage{}).EmptyReason(); got != "" {
		t.Errorf("a page with findings has reason %q", got)
	}
}

func TestIsValidRunID(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{
		testRunID:                      true,
		"s_6730a1b2c3d4e5f6a7b8c9d":    false,
		"s_6730a1b2c3d4e5f6a7b8c9d0a":  false,
		"p_6730a1b2c3d4e5f6a7b8c9d0":   false,
		"6730a1b2c3d4e5f6a7b8c9d0":     false,
		"s_6730a1b2c3d4e5f6a7b8c9dg":   false,
		"s_6730a1b2c3d4e5f6a7b8c9d0\n": false,
	} {
		if got := IsValidRunID(id); got != want {
			t.Errorf("IsValidRunID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestAppSecURL_TakesARunsFindingsAndAProjectsScanFilters(t *testing.T) {
	t.Parallel()
	c, err := NewClient("https://moose.example.com", testutil.NewTestAuthProvider("t"), false, time.Minute)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	for _, path := range []string{testRunPath, "/api/v1/appsec/projects/" + testRunProject + "/scan-filters"} {
		if _, err := c.appSecURL(path, nil); err != nil {
			t.Errorf("appSecURL(%q): %v", path, err)
		}
	}
	for _, path := range []string{
		"/api/v1/appsec/projects/" + testRunProject + "/scans/s_1/findings",
		"/api/v1/appsec/projects/" + testRunProject + "/scans/" + testRunID,
		testRunPath + "/f_1",
		"/api/v1/appsec/projects/" + testRunProject + "/scans/" + testRunID + "/findings/../x",
		"/api/v1/appsec/projects/" + testRunProject + "/scan-filters/x",
		"/api/v1/appsec/projects/scan-filters/" + testRunProject,
	} {
		if got, err := c.appSecURL(path, nil); err == nil {
			t.Errorf("appSecURL(%q) = %q, want an error", path, got)
		}
	}
}

func TestParseAppSecError_ReadsTheIngestEnvelope(t *testing.T) {
	t.Parallel()
	body := `{"detail":{"code":"project_run_findings","message":"This scan is a run of an AppSec project",` +
		`"context":{"project_id":"` + testRunProject + `","run_id":"` + testRunID + `"}}}`
	got := parseAppSecError(http.StatusConflict, []byte(body))
	if got.Code != AppSecCodeProjectRunFindings || got.Detail != "This scan is a run of an AppSec project" {
		t.Errorf("parsed = %+v", got)
	}
	if got.ContextString("project_id") != testRunProject || got.ContextString("run_id") != testRunID {
		t.Errorf("context = %+v", got.Context)
	}
}

func TestProjectRunFindingsRefusal(t *testing.T) {
	t.Parallel()
	refusal := `{"detail":{"code":"project_run_findings","message":"m","context":{"project_id":"p_1","run_id":null}}}`
	got, ok := ProjectRunFindingsRefusal(fmt.Errorf("wrapped: %w", &APIError{StatusCode: http.StatusConflict, Body: refusal}))
	if !ok || got.ContextString("project_id") != "p_1" || got.ContextString("run_id") != "" {
		t.Errorf("refusal = %+v, %v", got, ok)
	}
	for name, err := range map[string]error{
		"another 409":       &APIError{StatusCode: http.StatusConflict, Body: `{"detail":"already in status COMPLETED"}`},
		"the code on a 422": &APIError{StatusCode: http.StatusUnprocessableEntity, Body: refusal},
		"another error":     errors.New("boom"),
		"no error":          nil,
	} {
		if _, ok := ProjectRunFindingsRefusal(err); ok {
			t.Errorf("%s: read as the refusal", name)
		}
	}
}

func TestClient_GetProjectScanFilters(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotQuery map[string][]string
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query()
		testutil.JSONResponse(t, w, http.StatusOK, map[string]any{
			"armisignore": "severity:LOW\ncwe:79\n", "fingerprint": strings.Repeat("a", 64),
		})
	})
	filters, err := newProjectsClient(t, srv.URL).GetProjectScanFilters(context.Background(), testProjectsTenant, testRunProject)
	if err != nil {
		t.Fatalf("GetProjectScanFilters failed: %v", err)
	}
	if gotPath != "/api/v1/appsec/projects/"+testRunProject+"/scan-filters" {
		t.Errorf("path = %q", gotPath)
	}
	// The route refuses any query parameter it doesn't declare.
	if len(gotQuery) != 1 || gotQuery["tenant_id"][0] != testProjectsTenant {
		t.Errorf("query = %v", gotQuery)
	}
	if filters.Armisignore != "severity:LOW\ncwe:79\n" {
		t.Errorf("armisignore = %q", filters.Armisignore)
	}
}

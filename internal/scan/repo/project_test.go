package repo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/history"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// ingestRecorder is a mock API that records the /scan body and counts the
// calls made after the scan is triggered.
type ingestRecorder struct {
	mu           sync.Mutex
	scanBody     []byte
	presignCalls int
	statusCalls  int
	resultsCalls int
	// projectRun is what /scan answers of the run; nil answers as a server
	// that predates project runs.
	projectRun *model.ProjectRun
}

func newIngestRecorderServer(t *testing.T) (*ingestRecorder, string) {
	t.Helper()
	rec := &ingestRecorder{}
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			rec.mu.Lock()
			rec.presignCalls++
			rec.mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       testScanID,
				PresignedURL: testhelpers.SchemeFromRequest(r) + "://" + r.Host + "/_s3/upload",
				Fields:       map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/"):
			testutil.AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan"):
			body, _ := io.ReadAll(r.Body)
			rec.mu.Lock()
			rec.scanBody = body
			run := rec.projectRun
			rec.mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID: testScanID, ScanStatus: "INITIATED", ProjectRun: run,
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
			rec.mu.Lock()
			rec.statusCalls++
			rec.mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{ScanID: testScanID, ScanStatus: "COMPLETED"}},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
			rec.mu.Lock()
			rec.resultsCalls++
			rec.mu.Unlock()
			// A clean scan still gets its own entry, as on the real API.
			testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{ScanResults: []model.ScanResultData{{ScanID: testScanID}}},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/results"):
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return rec, srv.URL
}

func newProjectTestScanner(t *testing.T, baseURL string) *Scanner {
	t.Helper()
	return newProjectTestScannerTimingOut(t, baseURL, 5*time.Second)
}

// newProjectTestScannerTimingOut is newProjectTestScanner, whose API calls
// (not the upload) time out after apiTimeout.
func newProjectTestScannerTimingOut(t *testing.T, baseURL string, apiTimeout time.Duration) *Scanner {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: apiTimeout, DisableRetry: true})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	// armis:ignore cwe:798 reason:test fixture literal for the local mock API, not a real credential; the same placeholder token as every other test in this package
	client, err := api.NewClient(baseURL, testutil.NewTestAuthProvider("token123"), false, time.Minute,
		api.WithHTTPClient(httpClient), api.WithUploadHTTPClient(uploadClient), api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	// armis:ignore cwe:798 reason:a made-up tenant id for the local mock API, not a credential; the same fixture as every other test in this package
	return NewScanner(client, true, "tenant-456", 100, false, time.Minute, false).
		WithPollInterval(5 * time.Millisecond)
}

func newProjectTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func TestScan_WithProjectStampsTheScanRequest(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	rec, url := newIngestRecorderServer(t)

	_, err := newProjectTestScanner(t, url).WithProject("p_42", "cli_ci").Scan(context.Background(), newProjectTestRepo(t))
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	var req model.IngestScanStartRequest
	if err := json.Unmarshal(rec.scanBody, &req); err != nil {
		t.Fatalf("decode /scan body: %v", err)
	}
	if req.ProjectID != "p_42" || req.Trigger != "cli_ci" {
		t.Errorf("project_id/trigger = %q/%q, want p_42/cli_ci", req.ProjectID, req.Trigger)
	}
}

func TestScan_WithoutProjectSendsNoProjectFields(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	rec, url := newIngestRecorderServer(t)

	if _, err := newProjectTestScanner(t, url).Scan(context.Background(), newProjectTestRepo(t)); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, key := range []string{"project_id", "trigger"} {
		if strings.Contains(string(rec.scanBody), key) {
			t.Errorf("a scan without a project must not send %s; body: %s", key, rec.scanBody)
		}
	}
}

func TestScan_AsyncReturnsOnceAccepted(t *testing.T) {
	historyDir := t.TempDir()
	t.Setenv("ARMIS_HISTORY_DIR", historyDir)
	rec, url := newIngestRecorderServer(t)

	result, err := newProjectTestScanner(t, url).WithAsync().Scan(context.Background(), newProjectTestRepo(t))
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.ScanID != testScanID || result.Status != StatusAccepted || len(result.Findings) != 0 {
		t.Errorf("result = %+v, want an accepted scan %s without findings", result, testScanID)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.scanBody == nil {
		t.Error("the scan must still be triggered")
	}
	if rec.statusCalls != 0 || rec.resultsCalls != 0 {
		t.Errorf("async must not wait: status calls = %d, results calls = %d", rec.statusCalls, rec.resultsCalls)
	}

	// The scan ID is recorded so `armis-cli scan status` can follow it up.
	entry, err := history.NewStoreWithDir(historyDir).Latest(url, "tenant-456")
	if err != nil || entry == nil || entry.ScanID != testScanID {
		t.Errorf("history entry = %+v (err %v), want scan %s", entry, err, testScanID)
	}
}

// resolvedProjectID is the project id the resolvers in these tests return.
const resolvedProjectID = "p_77"

func TestScan_ProjectResolverStampsTheScanRequest(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	rec, url := newIngestRecorderServer(t)

	calls := 0
	resolve := func(context.Context) (string, string, error) {
		calls++
		return resolvedProjectID, "cli_dev", nil
	}
	if _, err := newProjectTestScanner(t, url).WithProjectResolver(resolve).Scan(context.Background(), newProjectTestRepo(t)); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	var req model.IngestScanStartRequest
	if err := json.Unmarshal(rec.scanBody, &req); err != nil {
		t.Fatalf("decode /scan body: %v", err)
	}
	if req.ProjectID != resolvedProjectID || req.Trigger != "cli_dev" || calls != 1 {
		t.Errorf("project_id/trigger = %q/%q after %d resolver calls, want p_77/cli_dev after 1", req.ProjectID, req.Trigger, calls)
	}
}

// A scan rejected by its local checks must not create a project: the resolver
// runs only once they pass.
func TestScan_ProjectResolverRunsOnlyAfterLocalChecks(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	unreadableIgnore := newProjectTestRepo(t)
	ignorePath := filepath.Join(unreadableIgnore, ".armisignore")
	if err := os.WriteFile(ignorePath, []byte("*.log\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, skip string
	}{
		{name: "the path is not a directory", path: notADir},
		{name: "the .armisignore cannot be read", path: unreadableIgnore, skip: unreadableSkipReason()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip != "" {
				t.Skip(tt.skip)
			}
			rec, url := newIngestRecorderServer(t)
			called := false
			resolve := func(context.Context) (string, string, error) {
				called = true
				return resolvedProjectID, "cli_ci", nil
			}
			if _, err := newProjectTestScanner(t, url).WithProjectResolver(resolve).Scan(context.Background(), tt.path); err == nil {
				t.Fatal("expected the local check to fail")
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if called || rec.presignCalls != 0 {
				t.Errorf("resolver called = %v, upload requests = %d; want neither", called, rec.presignCalls)
			}
		})
	}
}

// unreadableSkipReason reports why a mode-0 file would still be readable here.
func unreadableSkipReason() string {
	if runtime.GOOS == "windows" {
		return "file modes do not restrict reads on Windows"
	}
	if os.Geteuid() == 0 {
		return "root can read a mode-0 file"
	}
	return ""
}

// A failed lookup or create stops the scan before anything is uploaded, and
// keeps its own error.
func TestScan_ProjectResolverErrorStopsBeforeUpload(t *testing.T) {
	rec, url := newIngestRecorderServer(t)
	errLookup := errors.New("could not look up the project")
	resolve := func(context.Context) (string, string, error) { return "", "", errLookup }

	_, err := newProjectTestScanner(t, url).WithProjectResolver(resolve).Scan(context.Background(), newProjectTestRepo(t))
	if err != errLookup { //nolint:errorlint // the resolver's error must come back unwrapped
		t.Fatalf("err = %v, want the resolver's error unwrapped", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.presignCalls != 0 || rec.scanBody != nil {
		t.Errorf("upload requests = %d, scan body = %q; want no upload", rec.presignCalls, rec.scanBody)
	}
}

func TestScan_APublishedScanFilesItsRunUnderItsBranch(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	clearCIBranchEnv(t)
	rec, url := newIngestRecorderServer(t)
	dir := setupGitRepo(t)
	if err := runGitCmd(t, dir, "checkout", "-b", "feature/login"); err != nil {
		t.Fatalf("checkout: %v", err)
	}

	if _, err := newProjectTestScanner(t, url).WithProject("p_42", "cli_ci").Scan(context.Background(), dir); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	var req model.IngestScanStartRequest
	if err := json.Unmarshal(rec.scanBody, &req); err != nil {
		t.Fatalf("decode /scan body: %v", err)
	}
	if req.Branch != "feature/login" {
		t.Errorf("branch = %q, want feature/login", req.Branch)
	}
}

func TestScan_AScanThatIsNotPublishedSendsNoBranch(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	clearCIBranchEnv(t)
	t.Setenv("CIRCLE_BRANCH", "main")
	rec, url := newIngestRecorderServer(t)

	if _, err := newProjectTestScanner(t, url).Scan(context.Background(), setupGitRepo(t)); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if strings.Contains(string(rec.scanBody), `"branch"`) {
		t.Errorf("a scan without a project must not send a branch; body: %s", rec.scanBody)
	}
}

func TestScan_ReportsWhatTheServerSaidOfTheRun(t *testing.T) {
	for _, tt := range []struct {
		name string
		run  *model.ProjectRun
	}{
		{"recorded", &model.ProjectRun{Recorded: true, ProjectID: "p_42", RunID: "s_1"}},
		{"not recorded", &model.ProjectRun{ProjectID: "p_42", Reason: model.ProjectRunDisabled}},
		{"a server that predates project runs", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
			rec, url := newIngestRecorderServer(t)
			rec.projectRun = tt.run

			var reports []*model.ProjectRun
			scanner := newProjectTestScanner(t, url).WithProject("p_42", "cli_ci").
				WithProjectRunReporter(func(run *model.ProjectRun) { reports = append(reports, run) })
			if _, err := scanner.Scan(context.Background(), newProjectTestRepo(t)); err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(reports) != 1 {
				t.Fatalf("reports = %d, want 1", len(reports))
			}
			if (reports[0] == nil) != (tt.run == nil) || (tt.run != nil && *reports[0] != *tt.run) {
				t.Errorf("reported %+v, want %+v", reports[0], tt.run)
			}
		})
	}
}

func TestScan_AScanThatIsNotPublishedReportsNoRun(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	_, url := newIngestRecorderServer(t)

	reported := false
	scanner := newProjectTestScanner(t, url).
		WithProjectRunReporter(func(*model.ProjectRun) { reported = true })
	if _, err := scanner.Scan(context.Background(), newProjectTestRepo(t)); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if reported {
		t.Error("a scan without a project must report no run")
	}
}

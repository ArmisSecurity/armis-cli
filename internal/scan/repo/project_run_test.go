package repo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const (
	testRecordedProject = "p_66f2a1b2c3d4e5f6a7b8c9d0"
	testRecordedRun     = "s_6730a1b2c3d4e5f6a7b8c9d0"
)

// recordedRun is what /ingest/scan answers for a scan it recorded.
func recordedRun() *model.ProjectRun {
	return &model.ProjectRun{Recorded: true, ProjectID: testRecordedProject, RunID: testRecordedRun}
}

// runServer is a mock API for a published scan: /ingest/scan answers run,
// the AppSec findings route answers appSec in order (the last one repeats),
// and the legacy route answers legacy.
type runServer struct {
	mu          sync.Mutex
	run         *model.ProjectRun
	appSec      []func(http.ResponseWriter)
	legacy      func(http.ResponseWriter)
	appSecCalls int
	legacyCalls int
}

func (s *runServer) counts() (appSec, legacy int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appSecCalls, s.legacyCalls
}

func newRunServer(t *testing.T, srv *runServer) string {
	t.Helper()
	ts := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       testScanID,
				PresignedURL: testhelpers.SchemeFromRequest(r) + "://" + r.Host + "/_s3/upload",
				Fields:       map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/"):
			testutil.AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan"):
			srv.mu.Lock()
			run := srv.run
			srv.mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID: testScanID, ScanStatus: "INITIATED", ProjectRun: run,
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{ScanID: testScanID, ScanStatus: "COMPLETED"}},
			})
		case r.URL.Path == "/api/v1/appsec/projects/"+testRecordedProject+"/scans/"+testRecordedRun+"/findings":
			srv.mu.Lock()
			i := srv.appSecCalls
			if i >= len(srv.appSec) {
				i = len(srv.appSec) - 1
			}
			srv.appSecCalls++
			answer := srv.appSec[i]
			srv.mu.Unlock()
			answer(w)
		case r.URL.Path == "/api/v1/appsec/projects/"+testRecordedProject+"/scan-filters":
			w.WriteHeader(http.StatusNotFound)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
			srv.mu.Lock()
			srv.legacyCalls++
			legacy := srv.legacy
			srv.mu.Unlock()
			if legacy == nil {
				t.Errorf("unexpected legacy read")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			legacy(w)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/results"):
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return ts.URL
}

// appSecPage answers one page: the fixture's rows (or none), with empty
// state reason when not "".
func appSecPage(t *testing.T, rows []model.RunFinding, reason string, truncated bool) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		page := map[string]any{
			"data":        rows,
			"pagination":  map[string]any{"page": 1, "page_size": 100, "total_items": len(rows), "total_pages": 1},
			"counts":      map[string]any{"total": len(rows) + 40_000, "matching": len(rows), "suppressed": 2},
			"truncated":   truncated,
			"empty_state": nil,
		}
		if reason != "" {
			page["empty_state"] = map[string]any{"reason": reason}
			page["counts"] = nil
		}
		testutil.JSONResponse(t, w, http.StatusOK, page)
	}
}

func appSecStatus(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// legacyFindings answers the legacy read with one SAST finding.
func legacyFindings(t *testing.T) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		file, line := "legacy.go", 3
		testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
			Data: model.NormalizedResultsData{ScanResults: []model.ScanResultData{{
				ScanID: testScanID,
				Findings: []model.NormalizedFinding{{
					NormalizedRemediation: model.NormalizedRemediation{
						Description: "A legacy finding.", ToolSeverity: "HIGH", FindingCategory: "CODE_VULNERABILITY",
					},
					NormalizedTask: model.NormalizedTask{FindingID: "legacy-1", ExtraData: model.ExtraData{
						CodeLocation: model.CodeLocation{FileName: &file, StartLine: &line},
					}},
				}},
			}}},
		})
	}
}

// scanRecorded runs a published scan of a fresh repository against srv.
func scanRecorded(t *testing.T, srv *runServer, timeout time.Duration, repo string) (*model.ScanResult, error) {
	t.Helper()
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	url := newRunServer(t, srv)
	scanner := newProjectTestScanner(t, url).WithProject(testRecordedProject, "cli_ci").
		WithFetchRetryInterval(time.Millisecond)
	scanner.timeout = timeout
	if repo == "" {
		repo = newProjectTestRepo(t)
	}
	return scanner.Scan(context.Background(), repo)
}

func TestScan_ARecordedRunIsReadFromAppSec(t *testing.T) {
	rows := runFixture(t)
	srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){appSecPage(t, rows, "", false)}}

	result, err := scanRecorded(t, srv, time.Minute, "")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if appSec, legacy := srv.counts(); appSec != 1 || legacy != 0 {
		t.Errorf("AppSec reads %d, legacy reads %d", appSec, legacy)
	}
	if len(result.Findings) != len(rows) {
		t.Fatalf("findings = %d, want %d", len(result.Findings), len(rows))
	}
	// Two of the fixture's rows are suppressed by the project's filters: out of
	// the totals and --fail-on.
	if result.Summary.Suppressed != 2 || result.Summary.Total != len(rows)-2 {
		t.Errorf("summary = %+v", result.Summary)
	}
	if result.Truncated != nil {
		t.Errorf("truncated = %+v", result.Truncated)
	}
	if output.FailingCount(result, []string{"CRITICAL"}) != 1 {
		t.Errorf("failing CRITICAL = %d, want 1: the secret, not the suppressed SCA finding",
			output.FailingCount(result, []string{"CRITICAL"}))
	}
}

func TestScan_ARecordedRunNotFinishedIsReadAgain(t *testing.T) {
	srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){
		appSecPage(t, nil, "not_finished", false),
		appSecPage(t, nil, "not_finished", false),
		appSecPage(t, runFixture(t), "", false),
	}}

	result, err := scanRecorded(t, srv, time.Minute, "")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if appSec, _ := srv.counts(); appSec != 3 || len(result.Findings) != len(runFixture(t)) {
		t.Errorf("AppSec reads %d, findings %d", appSec, len(result.Findings))
	}
}

func TestScan_ARunStillNotRecordedAtTheTimeoutIsIncomplete(t *testing.T) {
	srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){appSecPage(t, nil, "not_finished", false)}}

	_, err := scanRecorded(t, srv, 60*time.Millisecond, "")
	var incomplete *output.ErrResultsIncomplete
	if !errors.As(err, &incomplete) {
		t.Errorf("err = %v, want ErrResultsIncomplete", err)
	}
}

func TestScan_ARecordedRunsEmptyStates(t *testing.T) {
	for _, tt := range []struct {
		name         string
		appSec       func(http.ResponseWriter)
		wantFindings int
		wantLegacy   int
		wantErr      bool
	}{
		{name: "no_findings is a clean run", appSec: appSecPage(t, nil, "no_findings", false)},
		{name: "run_failed is incomplete", appSec: appSecPage(t, nil, "run_failed", false), wantErr: true},
		{name: "not_recorded reads the legacy way", appSec: appSecPage(t, nil, "not_recorded", false), wantFindings: 1, wantLegacy: 1},
		{name: "a reason the CLI doesn't know reads the legacy way", appSec: appSecPage(t, nil, "kept_elsewhere", false), wantFindings: 1, wantLegacy: 1},
		{name: "a server without the route reads the legacy way", appSec: appSecStatus(http.StatusNotFound, `{"detail":"Not Found"}`), wantFindings: 1, wantLegacy: 1},
		{name: "a server refusing the parameters reads the legacy way", appSec: appSecStatus(http.StatusUnprocessableEntity, `{"detail":[{"loc":["query","expand"],"msg":"bad"}]}`), wantFindings: 1, wantLegacy: 1},
		{name: "rows without their detail read the legacy way", appSec: appSecPage(t, []model.RunFinding{{FindingID: "f_1", Type: "sast", Severity: "high"}}, "", false), wantFindings: 1, wantLegacy: 1},
		{name: "a read failing after its retries is incomplete", appSec: appSecStatus(http.StatusBadGateway, `{"detail":"bad gateway"}`), wantErr: true},
		{name: "a 403 is incomplete, not a legacy read", appSec: appSecStatus(http.StatusForbidden, `{"detail":"no","error":"insufficient_role","context":{}}`), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){tt.appSec}, legacy: legacyFindings(t)}
			result, err := scanRecorded(t, srv, time.Minute, "")
			if tt.wantErr {
				var incomplete *output.ErrResultsIncomplete
				if !errors.As(err, &incomplete) {
					t.Errorf("err = %v, want ErrResultsIncomplete", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if _, legacy := srv.counts(); legacy != tt.wantLegacy || len(result.Findings) != tt.wantFindings {
				t.Errorf("legacy reads %d, findings %d", legacy, len(result.Findings))
			}
		})
	}
}

func TestScan_TheLegacyReadsRefusalIsIncomplete(t *testing.T) {
	refusal := `{"detail":{"code":"project_run_findings","message":"This scan is a run of an AppSec project",` +
		`"context":{"project_id":"` + testRecordedProject + `","run_id":"` + testRecordedRun + `"}}}`
	srv := &runServer{
		run:    recordedRun(),
		appSec: []func(http.ResponseWriter){appSecPage(t, nil, "not_recorded", false)},
		legacy: appSecStatus(http.StatusConflict, refusal),
	}

	_, err := scanRecorded(t, srv, time.Minute, "")
	var incomplete *output.ErrResultsIncomplete
	if !errors.As(err, &incomplete) {
		t.Errorf("err = %v, want ErrResultsIncomplete", err)
	}
	if _, legacy := srv.counts(); legacy != 1 {
		t.Errorf("legacy reads %d, want one: a 409 is not retried", legacy)
	}
}

func TestScan_ATruncatedRunSaysWhatItKept(t *testing.T) {
	rows := runFixture(t)
	srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){appSecPage(t, rows, "", true)}}

	result, err := scanRecorded(t, srv, time.Minute, "")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	want := model.ResultsTruncation{Kept: len(rows), Total: len(rows) + 40_000 + 2, LeastSevereKept: model.SeverityLow}
	if result.Truncated == nil || *result.Truncated != want {
		t.Errorf("truncated = %+v, want %+v", result.Truncated, want)
	}
}

func TestScan_RunsThatAreNotRecordedReadTheLegacyWay(t *testing.T) {
	for _, tt := range []struct {
		name string
		run  *model.ProjectRun
	}{
		{"not recorded", &model.ProjectRun{ProjectID: testRecordedProject, Reason: model.ProjectRunDisabled}},
		{"a server that predates project runs", nil},
		{"a run id of another shape", &model.ProjectRun{Recorded: true, ProjectID: testRecordedProject, RunID: "s_1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := &runServer{run: tt.run, legacy: legacyFindings(t)}
			result, err := scanRecorded(t, srv, time.Minute, "")
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if appSec, legacy := srv.counts(); appSec != 0 || legacy != 1 || len(result.Findings) != 1 {
				t.Errorf("AppSec reads %d, legacy reads %d, findings %d", appSec, legacy, len(result.Findings))
			}
		})
	}
}

func TestScan_AnAsyncRecordedRunReadsNoFindings(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	srv := &runServer{run: recordedRun()}
	url := newRunServer(t, srv)
	scanner := newProjectTestScanner(t, url).WithProject(testRecordedProject, "cli_ci").WithAsync()

	result, err := scanner.Scan(context.Background(), newProjectTestRepo(t))
	if err != nil || result.Status != StatusAccepted {
		t.Fatalf("Scan = %+v, %v", result, err)
	}
	if appSec, legacy := srv.counts(); appSec != 0 || legacy != 0 {
		t.Errorf("AppSec reads %d, legacy reads %d", appSec, legacy)
	}
}

func TestScan_TheRootArmisignoreStillAppliesToARecordedRun(t *testing.T) {
	repo := newProjectTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".armisignore"), []byte("severity:LOW\n"), 0o600); err != nil {
		t.Fatalf("write .armisignore: %v", err)
	}
	srv := &runServer{run: recordedRun(), appSec: []func(http.ResponseWriter){appSecPage(t, runFixture(t), "", false)}}

	result, err := scanRecorded(t, srv, time.Minute, repo)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	sources := map[string]int{}
	for _, f := range result.Findings {
		if f.Suppressed {
			sources[f.SuppressionInfo.Source]++
		}
	}
	// The license finding is LOW: the root .armisignore suppresses it.
	want := map[string]int{"project": 1, "tenant": 1, "armisignore": 1}
	got, _ := json.Marshal(sources)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) || result.Summary.Suppressed != 3 {
		t.Errorf("suppressed by %s (total %d), want %s", got, result.Summary.Suppressed, wantJSON)
	}
}

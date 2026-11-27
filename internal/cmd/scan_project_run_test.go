package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// testRunID is the run /ingest/scan says it recorded the scan as.
const testRunID = "s_6730a1b2c3d4e5f6a7b8c9d0"

// recordedAsRun answers a scan that names its project as recorded.
func recordedAsRun(req model.IngestScanStartRequest) *model.ProjectRun {
	return &model.ProjectRun{Recorded: true, ProjectID: req.ProjectID, RunID: testRunID}
}

// runRow is one row of a run's findings, with its detail.
func runRow(id, typ, severity string, suppression map[string]any) map[string]any {
	return map[string]any{
		"finding_id": id, "title": strings.ToUpper(severity[:1]) + severity[1:] + " " + typ + " finding",
		"type": typ, "severity": severity, "suppression": suppression,
		"location": map[string]any{"path": "src/app.ts", "line": 7},
		"detail": map[string]any{
			"description": "A " + typ + " finding.",
			"location":    map[string]any{"path": "src/app.ts", "start_line": 7, "end_line": 8},
			"identifiers": map[string]any{"cves": []string{}, "cwes": []string{"CWE-79"}, "owasp": []string{}},
			"references":  []string{},
		},
	}
}

// runRows are a CRITICAL finding the project's threshold suppressed, and a
// HIGH one it didn't.
func runRows() []map[string]any {
	return []map[string]any{
		runRow("f_critical", "sca", "critical", map[string]any{"source": "project", "directive": "severity_threshold", "value": "HIGH"}),
		runRow("f_high", "sast", "high", nil),
	}
}

// runPage answers the run's findings route with rows. A truncated run counts
// 60,000 more findings than it kept, and 1 suppressed; any other counts
// exactly its rows.
func runPage(rows []map[string]any, truncated bool) func(*http.Request) (int, any) {
	return func(*http.Request) (int, any) {
		suppressed := 0
		for _, row := range rows {
			if suppression, _ := row["suppression"].(map[string]any); suppression != nil {
				suppressed++
			}
		}
		counts := map[string]any{"total": len(rows) - suppressed, "matching": len(rows), "suppressed": suppressed}
		if truncated {
			counts = map[string]any{"total": len(rows) + 60_000, "matching": len(rows), "suppressed": 1}
		}
		return http.StatusOK, map[string]any{
			"data":        rows,
			"pagination":  map[string]any{"page": 1, "page_size": 100, "total_items": len(rows), "total_pages": 1},
			"counts":      counts,
			"truncated":   truncated,
			"empty_state": nil,
		}
	}
}

// publishRecordedScan sets a CI scan published to testProjectName, which the
// mock records as a run whose findings route serves runFindings.
func publishRecordedScan(t *testing.T, runFindings func(*http.Request) (int, any), cfg testutil.MockAPIConfig) *projectScanEnv {
	t.Helper()
	cfg.ProjectRun = recordedAsRun
	cfg.RunFindings = runFindings
	env := setupProjectScan(t, cfg)
	t.Setenv("CI", "true")
	projectName = testProjectName
	return env
}

// AC 26, 27: a recorded run's findings come from AppSec, and the findings the
// project's filters suppressed are out of --fail-on and marked in JSON.
func TestProjectScan_ARecordedRunGatesOnTheFindingsArmisKept(t *testing.T) {
	env := publishRecordedScan(t, runPage(runRows(), false), testutil.MockAPIConfig{})
	failOn = []string{"CRITICAL"}

	stdout, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v (the only CRITICAL finding is suppressed)", err)
	}
	if reqs := env.rec.Matching(http.MethodGet, "/ingest/normalized-results"); len(reqs) != 0 {
		t.Errorf("a recorded run was read the legacy way: %d requests", len(reqs))
	}
	reads := env.rec.Matching(http.MethodGet, "/scans/"+testRunID+"/findings")
	if len(reads) != 1 || reads[0].Query.Get("suppressed") != "include" || reads[0].Query.Get("expand") != "detail" {
		t.Fatalf("AppSec reads = %+v", reads)
	}

	var result model.ScanResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode JSON output: %v\n%s", err, stdout)
	}
	if result.Summary.Suppressed != 1 || result.Summary.Total != 1 {
		t.Errorf("summary = %+v", result.Summary)
	}
	for _, f := range result.Findings {
		if f.ID == "f_critical" && (!f.Suppressed || f.SuppressionInfo == nil || f.SuppressionInfo.Source != "project") {
			t.Errorf("the suppressed finding isn't marked: %+v", f)
		}
	}
}

func TestProjectScan_ARecordedRunFailsOnAnUnsuppressedFinding(t *testing.T) {
	publishRecordedScan(t, runPage(runRows(), false), testutil.MockAPIConfig{})
	failOn = []string{"HIGH"}

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	var exceeded *output.ErrFindingsExceeded
	if !errors.As(err, &exceeded) {
		t.Errorf("err = %v, want ErrFindingsExceeded", err)
	}
}

// AC 27: --show-suppressed shows the server's suppressions with their source,
// and the summary groups them.
func TestProjectScan_ShowSuppressedShowsTheServersFilter(t *testing.T) {
	publishRecordedScan(t, runPage(runRows(), false), testutil.MockAPIConfig{})
	keep(t, &showSuppressed)
	format, showSuppressed = "human", true

	stdout, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	flat := strings.Join(strings.Fields(stdout), " ")
	for _, want := range []string{
		"[SUPPRESSED by Armis scan filters] severity_threshold:HIGH -- Armis project scan filter",
		"Armis scan filters suppressed 1 finding (1 below the project's HIGH threshold)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
}

// AC 28 and the default the PR flags: a truncated run exits 2 when a --fail-on
// level could be among the findings the history dropped.
func TestProjectScan_ATruncatedRunExits2OnlyWhenFailOnIsOpen(t *testing.T) {
	high := []map[string]any{runRow("f_high", "sast", "high", nil)}
	// A kept finding the project's filters suppressed fails nothing, so only
	// the findings Armis dropped could still match --fail-on.
	suppressedHigh := []map[string]any{runRow("f_high", "sast", "high",
		map[string]any{"source": "project", "directive": "severity", "value": "HIGH"})}
	for _, tt := range []struct {
		rows      []map[string]any
		failOn    []string
		truncated bool
		want      string
	}{
		{high, []string{"CRITICAL"}, true, ""}, // above the least severe kept: decided
		{suppressedHigh, []string{"LOW"}, true, "truncated"},
		{suppressedHigh, []string{"CRITICAL", "LOW"}, true, "truncated"}, // a list counts from its lowest level
		{high, []string{"HIGH"}, true, "exceeded"},
		{high, []string{"LOW"}, false, "exceeded"}, // LOW and up: the HIGH finding fails it
		{high, []string{"CRITICAL"}, false, ""},
	} {
		t.Run(strings.Join(tt.failOn, ",")+map[bool]string{true: " truncated", false: ""}[tt.truncated], func(t *testing.T) {
			publishRecordedScan(t, runPage(tt.rows, tt.truncated), testutil.MockAPIConfig{})
			failOn = tt.failOn

			_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
			var truncated *output.ErrResultsTruncated
			var exceeded *output.ErrFindingsExceeded
			switch tt.want {
			case "":
				if err != nil {
					t.Errorf("err = %v, want none", err)
				}
			case "truncated":
				// The open levels: those --fail-on gates on, up to the least
				// severe finding kept (HIGH).
				if !errors.As(err, &truncated) || strings.Join(truncated.Levels, ",") != "LOW,MEDIUM,HIGH" {
					t.Errorf("err = %v, want ErrResultsTruncated for LOW,MEDIUM,HIGH", err)
				}
			case "exceeded":
				if !errors.As(err, &exceeded) {
					t.Errorf("err = %v, want ErrFindingsExceeded", err)
				}
			}
			if tt.truncated && !strings.Contains(stderr, "Armis kept the 1 most severe findings of 60002") {
				t.Errorf("no truncation warning:\n%s", stderr)
			}
		})
	}
}

// A run whose history the server doesn't keep is read the legacy way.
func TestProjectScan_ANotRecordedRunReadsTheLegacyWay(t *testing.T) {
	notRecorded := func(*http.Request) (int, any) {
		return http.StatusOK, map[string]any{
			"data": []any{}, "pagination": map[string]any{"page": 1, "page_size": 100, "total_items": 0, "total_pages": 1},
			"counts": nil, "truncated": false, "empty_state": map[string]any{"reason": "not_recorded"},
		}
	}
	env := publishRecordedScan(t, notRecorded, testutil.MockAPIConfig{Findings: []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("legacy-1", "HIGH", "sql_injection", nil, []string{"CWE-89"}),
	}})
	failOn = []string{"HIGH"}

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	var exceeded *output.ErrFindingsExceeded
	if !errors.As(err, &exceeded) {
		t.Errorf("err = %v, want the legacy finding to fail --fail-on HIGH", err)
	}
	if reqs := env.rec.Matching(http.MethodGet, "/ingest/normalized-results"); len(reqs) == 0 {
		t.Error("the run was not read the legacy way")
	}
}

// --debug prints the project's scan filters; an older server without the
// route skips it silently.
func TestProjectScan_DebugPrintsTheScanFilters(t *testing.T) {
	for _, withRoute := range []bool{true, false} {
		t.Run(map[bool]string{true: "a server with the route", false: "an older server"}[withRoute], func(t *testing.T) {
			cfg := testutil.MockAPIConfig{}
			if withRoute {
				cfg.ScanFilters = func(*http.Request) (int, any) {
					return http.StatusOK, map[string]any{"armisignore": "severity:LOW\ncwe:79\n"}
				}
			}
			publishRecordedScan(t, runPage(runRows(), false), cfg)
			debug = true

			_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			printed := strings.Contains(stderr, "=== DEBUG: Armis scan filters of project") && strings.Contains(stderr, "cwe:79")
			if printed != withRoute {
				t.Errorf("printed the scan filters: %v, want %v\n%s", printed, withRoute, stderr)
			}
		})
	}
}

// The commands that read no findings don't start to: `bom repo` (which names
// no project, so it's never a run) and `scan status`, even against a server
// that records project scans as runs and serves their findings.
func TestProjectScan_BOMAndStatusReadNoFindings(t *testing.T) {
	failingRead := func(r *http.Request) (int, any) {
		t.Errorf("a run's findings were read: %s", r.URL.Path)
		return http.StatusInternalServerError, map[string]any{}
	}

	t.Run("bom repo", func(t *testing.T) {
		var rec scanRecorder
		setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, rec.hook(testutil.MockAPIConfig{
			ProjectRun:  recordedAsRun,
			RunFindings: failingRead,
			BOMContent:  map[string]string{"bom_results": `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`},
		})))
		t.Setenv("CI", "true")
		bomOnlyOutput = t.TempDir()

		if _, _, err := runBOM(t, bomRepoCmd, createTestRepo(t)); err != nil {
			t.Fatalf("bom repo: %v", err)
		}
		if rec.called("/findings") || rec.called("/normalized-results") {
			t.Error("bom repo read findings")
		}
	})

	t.Run("scan status", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{ScanID: r.URL.Query().Get("scan_id"), ScanStatus: "COMPLETED"}},
			})
		})
		cleanup := setupStatusEnv(t, server.URL)
		defer cleanup()

		if _, err := runStatus(t, []string{"scan-123"}); err != nil {
			t.Fatalf("scan status: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		for _, path := range paths {
			if !strings.Contains(path, "/api/v1/ingest/status") {
				t.Errorf("scan status called %s", path)
			}
		}
	})
}

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/project"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	projectsPathPart = "/api/v1/appsec/projects"
	ingestScanPart   = "/api/v1/ingest/scan"
	// testProjectName is the --project most tests publish to.
	testProjectName = "checkout-service"
	// firstMockProjectID is the id the mock API gives the first project it creates.
	firstMockProjectID = "p_mock1"
)

// projectScanEnv is a mock API plus the CLI state a project-scan test runs in.
type projectScanEnv struct {
	rec *testutil.RequestRecorder
	url string
}

// setupProjectScan points the scan commands at a recording mock API on a
// simulated developer machine (every CI variable cleared), with Basic auth so
// authenticating makes no request of its own. All touched globals and flag
// states are restored afterwards.
func setupProjectScan(t *testing.T, cfg testutil.MockAPIConfig) *projectScanEnv {
	t.Helper()
	rec := &testutil.RequestRecorder{}
	cfg.Recorder = rec
	serverURL := testutil.GetMockServerURLWithConfig(t, cfg)

	for _, p := range []*string{&token, &tenantID, &clientID, &clientSecret, &format, &colorFlag, &themeFlag,
		&outputFile, &changedRef, &projectName} {
		keep(t, p)
	}
	for _, p := range []*bool{&noUpdateCheck, &noProgress, &reportScan, &syncScan, &asyncScan, &debug,
		&generateSBOM, &generateVEX} {
		keep(t, p)
	}
	keep(t, &pollInterval)
	keep(t, &failOn)
	keep(t, &includeFiles)
	keep(t, &exitCode)
	t.Cleanup(func() {
		cli.InitColors(cli.ColorModeAuto)
		output.SyncColors()
	})

	t.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	for _, k := range progress.CIEnvVars() {
		t.Setenv(k, "")
	}

	token, tenantID, clientID, clientSecret = testToken, testTenantID, "", ""
	format, colorFlag, themeFlag, outputFile = agentFormatJSON, testColorNever, themeAuto, ""
	changedRef, projectName = "", ""
	noUpdateCheck, noProgress = true, true
	reportScan, syncScan, asyncScan, debug, generateSBOM, generateVEX = false, false, false, false, false, false
	pollInterval = 5 * time.Millisecond
	failOn, includeFiles, exitCode = []string{"CRITICAL"}, nil, 1
	cli.InitColors(cli.ColorModeNever)
	output.SyncColors()

	// Start from a clean command line: other tests in this package can leave
	// a flag marked as set, which would change what these commands do.
	for _, c := range []*cobra.Command{rootCmd, scanCmd, scanRepoCmd} {
		clearFlagChanges(t, c.Flags())
		clearFlagChanges(t, c.PersistentFlags())
	}

	return &projectScanEnv{rec: rec, url: serverURL}
}

// keep restores *p to its current value when the test ends.
func keep[T any](t *testing.T, p *T) {
	t.Helper()
	old := *p
	t.Cleanup(func() { *p = old })
}

// clearFlagChanges marks every flag in fs as not set, restoring the previous
// marks when the test ends.
func clearFlagChanges(t *testing.T, fs *pflag.FlagSet) {
	t.Helper()
	var changed []*pflag.Flag
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			changed = append(changed, f)
			f.Changed = false
		}
	})
	t.Cleanup(func() {
		for _, f := range changed {
			f.Changed = true
		}
	})
}

// markFlag marks a flag as set on the command line, as cobra would, and resets
// it afterwards so the state does not leak into other tests.
func markFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	f := cmd.Flag(name)
	if f == nil {
		t.Fatalf("no --%s flag on %s", name, cmd.Name())
	}
	old := f.Value.String()
	if err := f.Value.Set(value); err != nil {
		t.Fatalf("set --%s: %v", name, err)
	}
	f.Changed = true
	t.Cleanup(func() {
		_ = f.Value.Set(old)
		f.Changed = false
	})
}

// runScan runs fn (a RunE call), capturing stdout and stderr.
func runScan(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	stderr = testutil.CaptureStderr(t, func() {
		stdout = captureStdout(t, func() { err = fn() })
	})
	return stdout, stderr, err
}

func newScanDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

// scanBody decodes the single /ingest/scan request of the run.
func (e *projectScanEnv) scanBody(t *testing.T) (model.IngestScanStartRequest, string) {
	t.Helper()
	reqs := e.rec.Matching(http.MethodPost, ingestScanPart)
	if len(reqs) != 1 {
		t.Fatalf("/ingest/scan requests = %d, want 1", len(reqs))
	}
	var body model.IngestScanStartRequest
	if err := json.Unmarshal(reqs[0].Body, &body); err != nil {
		t.Fatalf("decode /ingest/scan body: %v", err)
	}
	return body, string(reqs[0].Body)
}

// assertNotPublished checks that the run never reached the projects API and
// that its scan request carried nothing project-related.
func (e *projectScanEnv) assertNotPublished(t *testing.T) {
	t.Helper()
	if reqs := e.rec.Matching("", projectsPathPart); len(reqs) != 0 {
		t.Errorf("expected no projects API calls, got %d: %+v", len(reqs), reqs)
	}
	_, raw := e.scanBody(t)
	for _, key := range []string{"project_id", "trigger"} {
		if strings.Contains(raw, key) {
			t.Errorf("/ingest/scan must not carry %s for an unpublished scan: %s", key, raw)
		}
	}
}

// AC: `armis-cli scan .` without --project never creates a project, whether
// or not it runs in CI, with --sync or --async.
func TestProjectScan_WithoutProjectIsNeverPublished(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ci    bool
		async bool
	}{
		{"local", false, false},
		{"CI", true, false},
		{"CI async", true, true},
		{"local async", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := setupProjectScan(t, testutil.MockAPIConfig{})
			if tt.ci {
				t.Setenv("GITHUB_ACTIONS", "true")
			}
			asyncScan = tt.async

			_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			env.assertNotPublished(t)
		})
	}
}

// AC: a local scan with no --report and no CI variables never reaches the
// projects backend, even with --project.
func TestProjectScan_LocalProjectScanStaysLocal(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectName = testProjectName

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	env.assertNotPublished(t)
	for _, want := range []string{"--project checkout-service", "not published", "--report"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

// AC: the first CI scan with a new --project name creates the project
// (a ci_cd project, which the API tags source "cli") and records the run.
func TestProjectScan_CICreatesProjectOnFirstRun(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("GITHUB_ACTIONS", "true")
	projectName = testProjectName

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	creates := env.rec.Matching(http.MethodPost, projectsPathPart)
	if len(creates) != 1 {
		t.Fatalf("create calls = %d, want 1", len(creates))
	}
	if got := string(creates[0].Body); got != `{"name":"checkout-service","project_type":"ci_cd"}` {
		t.Errorf("create body = %s", got)
	}
	if creates[0].Query.Get("tenant_id") != testTenantID {
		t.Errorf("create tenant_id = %q", creates[0].Query.Get("tenant_id"))
	}

	body, _ := env.scanBody(t)
	if body.ProjectID != firstMockProjectID || body.Trigger != project.TriggerCLICI {
		t.Errorf("/ingest/scan project_id/trigger = %q/%q, want p_mock1/cli_ci", body.ProjectID, body.Trigger)
	}
	for _, want := range []string{"Created project", testProjectName, "CI detected (GITHUB_ACTIONS)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}

	// The project is resolved before the upload, so a new project exists
	// before its first run is triggered.
	reqs := env.rec.Requests()
	createIdx, presignIdx := -1, -1
	for i, r := range reqs {
		if r.Method == http.MethodPost && strings.Contains(r.Path, projectsPathPart) && createIdx < 0 {
			createIdx = i
		}
		if strings.Contains(r.Path, "/presigned-url") && presignIdx < 0 {
			presignIdx = i
		}
	}
	if createIdx < 0 || presignIdx < 0 || createIdx > presignIdx {
		t.Errorf("project must be created before the upload starts (create #%d, presign #%d)", createIdx, presignIdx)
	}
}

// AC: re-running with the same name appends a run to the existing project and
// never creates a duplicate.
func TestProjectScan_RerunAppendsToTheSameProject(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("CI", "true")
	projectName = testProjectName
	dir := newScanDir(t)

	for run := 1; run <= 2; run++ {
		if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) }); err != nil {
			t.Fatalf("run %d failed: %v", run, err)
		}
	}

	if creates := env.rec.Matching(http.MethodPost, projectsPathPart); len(creates) != 1 {
		t.Errorf("create calls over two runs = %d, want exactly 1", len(creates))
	}
	scans := env.rec.Matching(http.MethodPost, ingestScanPart)
	if len(scans) != 2 {
		t.Fatalf("scan requests = %d, want 2", len(scans))
	}
	for i, s := range scans {
		var body model.IngestScanStartRequest
		_ = json.Unmarshal(s.Body, &body)
		if body.ProjectID != firstMockProjectID {
			t.Errorf("run %d project_id = %q, want the same project p_mock1", i+1, body.ProjectID)
		}
	}
}

func TestProjectScan_ExistingProjectIsReused(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{Projects: []model.Project{
		{ProjectID: "p_legacy", Name: "checkout-service-legacy", Status: model.ProjectStatusActive},
		{ProjectID: "p_existing", Name: testProjectName, Status: model.ProjectStatusActive},
	}})
	t.Setenv("GITLAB_CI", "true")
	projectName = testProjectName

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if creates := env.rec.Matching(http.MethodPost, projectsPathPart); len(creates) != 0 {
		t.Errorf("an existing project must not be re-created; create calls = %d", len(creates))
	}
	lookups := env.rec.Matching(http.MethodGet, projectsPathPart)
	if len(lookups) != 1 {
		t.Fatalf("lookups = %d, want 1", len(lookups))
	}
	if q := lookups[0].Query; q.Get("q") != testProjectName || strings.Join(q["status"], ",") != "active,paused,archived" {
		t.Errorf("lookup query = %v", q)
	}
	if body, _ := env.scanBody(t); body.ProjectID != "p_existing" {
		t.Errorf("project_id = %q, want p_existing", body.ProjectID)
	}
	if !strings.Contains(stderr, "Publishing to project") {
		t.Errorf("stderr should announce the existing project:\n%s", stderr)
	}
}

// --report publishes a developer-machine scan, stamped cli_dev.
func TestProjectScan_ReportPublishesALocalScan(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectName = testProjectName
	reportScan = true

	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) }); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	body, _ := env.scanBody(t)
	if body.ProjectID == "" || body.Trigger != project.TriggerCLIDev {
		t.Errorf("project_id/trigger = %q/%q, want a project and cli_dev", body.ProjectID, body.Trigger)
	}
}

// AC: a folder that is not a git repository still creates/updates a project,
// without implying a git integration: no repository binding, no git hints.
func TestProjectScan_NonGitFolder(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("CI", "true")
	projectName = "plain-folder"
	dir := newScanDir(t) // no .git
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal("test folder must not be a git repository")
	}

	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) }); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	creates := env.rec.Matching(http.MethodPost, projectsPathPart)
	if len(creates) != 1 || strings.Contains(string(creates[0].Body), "repository") || strings.Contains(string(creates[0].Body), "provider") {
		t.Fatalf("expected one unbound ci_cd create, got %+v", creates)
	}
	body, raw := env.scanBody(t)
	if body.ProjectID == "" {
		t.Error("the scan should be published to the project")
	}
	for _, key := range []string{"repo_name", "git_sha", "origin_sha"} {
		if strings.Contains(raw, key) {
			t.Errorf("a non-git folder must not send %s: %s", key, raw)
		}
	}
}

// AC: an invalid --project name is rejected with the broken rule and a valid
// example, and the scan does not run: no request at all is made.
func TestProjectScan_InvalidNameFailsBeforeAnything(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		rule  project.Rule
	}{
		{"too long", strings.Repeat("a", 65), project.RuleTooLong},
		{"bad characters", "my service!", project.RuleCharset},
		{"flag swallowed as value", "--sync", project.RuleBoundary},
		{"reserved word", "undefined", project.RuleReserved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := setupProjectScan(t, testutil.MockAPIConfig{})
			t.Setenv("CI", "true")
			projectName = tt.input

			_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
			var nameErr *project.NameError
			if !errors.As(err, &nameErr) || !nameErr.Broken(tt.rule) {
				t.Fatalf("err = %v, want a NameError breaking %q", err, tt.rule)
			}
			if !strings.Contains(err.Error(), "Example of a valid name: --project ") {
				t.Errorf("error should show a valid example: %v", err)
			}
			if reqs := env.rec.Requests(); len(reqs) != 0 {
				t.Errorf("the scan must not run: %d requests made", len(reqs))
			}
		})
	}

	t.Run("empty value", func(t *testing.T) {
		env := setupProjectScan(t, testutil.MockAPIConfig{})
		markFlag(t, scanRepoCmd, "project", "") // --project "" (an unset variable)

		_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
		var nameErr *project.NameError
		if !errors.As(err, &nameErr) || !nameErr.Broken(project.RuleEmpty) {
			t.Fatalf("err = %v, want an empty-name error", err)
		}
		if reqs := env.rec.Requests(); len(reqs) != 0 {
			t.Errorf("the scan must not run: %d requests made", len(reqs))
		}
	})
}

// AC: --sync exits non-zero when the scan crosses its --fail-on threshold.
func TestProjectScan_SyncGatesOnFailOn(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{Findings: []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("f1", "HIGH", "sql_injection", nil, []string{"CWE-89"}),
	}})
	t.Setenv("CI", "true")
	projectName = testProjectName
	syncScan = true
	failOn = []string{"HIGH"}

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	var exceeded *output.ErrFindingsExceeded
	if !errors.As(err, &exceeded) || exceeded.ExitCode != 1 {
		t.Fatalf("err = %v, want ErrFindingsExceeded with exit code 1", err)
	}
	if len(env.rec.Matching(http.MethodGet, "/ingest/status")) == 0 {
		t.Error("--sync must wait for the scan")
	}
}

// AC: --async exits 0 once the scan is accepted, even when the findings would
// cross --fail-on, and writes a JSON record of the accepted scan.
func TestProjectScan_AsyncExitsZeroOnceAccepted(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{Findings: []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("f1", "CRITICAL", "sql_injection", nil, []string{"CWE-89"}),
	}})
	t.Setenv("CI", "true")
	projectName = testProjectName
	asyncScan = true
	failOn = []string{"HIGH"}
	markFlag(t, scanRepoCmd, "fail-on", "HIGH")

	stdout, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("--async must exit 0 once accepted, got %v", err)
	}
	if n := len(env.rec.Matching(http.MethodGet, "/ingest/status")) + len(env.rec.Matching(http.MethodGet, "/normalized-results")); n != 0 {
		t.Errorf("--async must not wait for results: %d status/results requests", n)
	}
	if body, _ := env.scanBody(t); body.ProjectID != firstMockProjectID {
		t.Errorf("the async scan should still be published, project_id = %q", body.ProjectID)
	}

	var record asyncScanRecord
	if err := json.Unmarshal([]byte(stdout), &record); err != nil {
		t.Fatalf("stdout is not the JSON record: %v\n%s", err, stdout)
	}
	if record.ScanID != "test-scan-001" || record.Status != "accepted" || record.Project == nil ||
		record.Project.ProjectID != firstMockProjectID || !record.Project.Created || record.Project.Trigger != project.TriggerCLICI {
		t.Errorf("record = %+v (project %+v)", record, record.Project)
	}
	for _, want := range []string{"--fail-on is not evaluated with --async", "armis-cli scan status test-scan-001"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

// An async SARIF run writes nothing: an empty SARIF upload would close every
// open code-scanning alert.
func TestProjectScan_AsyncSARIFWritesNoFile(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})
	asyncScan = true
	outputFile = filepath.Join(t.TempDir(), "results.sarif")

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if _, statErr := os.Stat(outputFile); !os.IsNotExist(statErr) {
		t.Errorf("an async SARIF run must not create %s", outputFile)
	}
	if !strings.Contains(stderr, "--format sarif writes no results with --async") {
		t.Errorf("stderr should explain the missing output:\n%s", stderr)
	}
}

func TestProjectScan_ReportWithoutProject(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	reportScan = true

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err == nil || !strings.Contains(err.Error(), "--report publishes the scan to a project, so it needs --project") {
		t.Fatalf("err = %v", err)
	}
	if reqs := env.rec.Requests(); len(reqs) != 0 {
		t.Errorf("no request should be made: %d", len(reqs))
	}
}

func TestProjectScan_SyncAndAsyncConflict(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})
	syncScan, asyncScan = true, true
	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err == nil || !strings.Contains(err.Error(), "--sync and --async cannot be used together") {
		t.Fatalf("err = %v", err)
	}
}

// A partial scan would under-report the project's findings, so publishing one
// is refused before anything runs.
func TestProjectScan_PartialScanIsNotPublished(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("CI", "true")
	projectName = testProjectName
	includeFiles = []string{"main.go"}

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err == nil || !strings.Contains(err.Error(), "cannot be published") {
		t.Fatalf("err = %v", err)
	}
	if reqs := env.rec.Requests(); len(reqs) != 0 {
		t.Errorf("no request should be made: %d", len(reqs))
	}
}

// A partial scan without publishing (no --project) is unaffected.
func TestProjectScan_PartialLocalScanStillRuns(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("CI", "true")
	includeFiles = []string{"main.go"}

	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) }); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	env.assertNotPublished(t)
}

func TestProjectScan_CaseOnlyMatchIsRefused(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{Projects: []model.Project{
		{ProjectID: "p_1", Name: "Checkout-Service", Status: model.ProjectStatusActive},
	}})
	t.Setenv("CI", "true")
	projectName = testProjectName

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	var caseErr *project.CaseMismatchError
	if !errors.As(err, &caseErr) {
		t.Fatalf("err = %v, want CaseMismatchError", err)
	}
	if n := len(env.rec.Matching(http.MethodPost, projectsPathPart)) + len(env.rec.Matching("", "/ingest/")); n != 0 {
		t.Errorf("nothing should be created or uploaded: %d requests", n)
	}
}

func TestProjectScan_ProjectsDisabledFailsBeforeUpload(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{ProjectsDisabled: true})
	t.Setenv("CI", "true")
	projectName = testProjectName

	_, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if !errors.Is(err, project.ErrProjectsUnavailable) {
		t.Fatalf("err = %v, want ErrProjectsUnavailable", err)
	}
	if reqs := env.rec.Matching("", "/ingest/"); len(reqs) != 0 {
		t.Errorf("nothing should be uploaded: %d ingest requests", len(reqs))
	}
}

func TestProjectScan_ArchivedProjectWarns(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{Projects: []model.Project{
		{ProjectID: "p_old", Name: testProjectName, Status: model.ProjectStatusArchived},
	}})
	t.Setenv("CI", "true")
	projectName = testProjectName

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(stderr, "is archived") {
		t.Errorf("stderr should warn about the archived project:\n%s", stderr)
	}
	// A project that will not record the run is "found", not "published to".
	if !strings.Contains(stderr, "Found project") || strings.Contains(stderr, "Publishing to project") {
		t.Errorf("stderr should announce the archived project as found:\n%s", stderr)
	}
	if creates := env.rec.Matching(http.MethodPost, projectsPathPart); len(creates) != 0 {
		t.Error("an archived project holds its name and must not be re-created")
	}
	if body, _ := env.scanBody(t); body.ProjectID != "p_old" {
		t.Errorf("project_id = %q, want p_old", body.ProjectID)
	}
}

// `armis-cli scan <path>` is `armis-cli scan repo <path>`.
func TestScanShorthand(t *testing.T) {
	t.Run("scans the path like scan repo", func(t *testing.T) {
		env := setupProjectScan(t, testutil.MockAPIConfig{})
		t.Setenv("CI", "true")
		projectName = testProjectName

		if _, _, err := runScan(t, func() error { return scanCmd.RunE(scanCmd, []string{newScanDir(t)}) }); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if body, _ := env.scanBody(t); body.ProjectID != firstMockProjectID || body.Trigger != project.TriggerCLICI {
			t.Errorf("project_id/trigger = %q/%q", body.ProjectID, body.Trigger)
		}
	})

	t.Run("bare scan prints help", func(t *testing.T) {
		env := setupProjectScan(t, testutil.MockAPIConfig{})
		// Pin scanCmd's own writer: cobra falls back to a parent's writer,
		// which another test may have redirected.
		var help bytes.Buffer
		scanCmd.SetOut(&help)
		t.Cleanup(func() { scanCmd.SetOut(nil) })

		if err := scanCmd.RunE(scanCmd, nil); err != nil {
			t.Fatalf("bare `scan` should print help, got %v", err)
		}
		if !strings.Contains(help.String(), "armis-cli scan [path]") {
			t.Errorf("expected the scan help, got:\n%s", help.String())
		}
		if reqs := env.rec.Requests(); len(reqs) != 0 {
			t.Errorf("bare `scan` must not scan: %d requests", len(reqs))
		}
	})

	t.Run("flags without a path fail instead of passing silently", func(t *testing.T) {
		setupProjectScan(t, testutil.MockAPIConfig{})
		markFlag(t, scanCmd, "project", testProjectName)
		err := scanCmd.RunE(scanCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "missing scan target") {
			t.Fatalf("err = %v, want a missing-target error", err)
		}
	})

	t.Run("mistyped subcommand gets a suggestion", func(t *testing.T) {
		setupProjectScan(t, testutil.MockAPIConfig{})
		err := scanCmd.RunE(scanCmd, []string{"rpo"})
		if err == nil || !strings.Contains(err.Error(), "did you mean 'armis-cli scan repo'") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("image reference gets a hint", func(t *testing.T) {
		setupProjectScan(t, testutil.MockAPIConfig{})
		err := scanCmd.RunE(scanCmd, []string{"nginx:1.27"})
		if err == nil || !strings.Contains(err.Error(), "armis-cli scan image nginx:1.27") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("shares the repo-scan flags", func(t *testing.T) {
		for _, name := range []string{"project", "report", "sync", "async", "changed", "include-files", "show-suppressed"} {
			if scanCmd.Flags().Lookup(name) == nil {
				t.Errorf("scan is missing --%s", name)
			}
			if scanRepoCmd.Flags().Lookup(name) == nil {
				t.Errorf("scan repo is missing --%s", name)
			}
		}
		// The new flags are repo-only; scan image does not take them.
		for _, name := range []string{"project", "report", "async"} {
			if scanImageCmd.Flags().Lookup(name) != nil {
				t.Errorf("scan image should not have --%s", name)
			}
		}
	})
}

// TestProjectScan_CLIRejectsSyncWithAsync runs through cobra itself, where the
// flags are declared mutually exclusive.
func TestProjectScan_CLIRejectsSyncWithAsync(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})
	t.Cleanup(func() {
		for _, c := range []*cobra.Command{scanCmd, scanRepoCmd} {
			for _, n := range []string{"sync", "async"} {
				if f := c.Flags().Lookup(n); f != nil {
					_ = f.Value.Set("false")
					f.Changed = false
				}
			}
		}
		rootCmd.SetArgs(nil)
	})
	rootCmd.SetArgs([]string{"scan", "repo", newScanDir(t), "--sync", "--async"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "[async sync]") {
		t.Fatalf("err = %v, want cobra's mutually-exclusive flag error", err)
	}
}

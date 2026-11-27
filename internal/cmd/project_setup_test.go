package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/project"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestQuestionsFor_SkipsWhatTheArmisignoreAnswers(t *testing.T) {
	all := questionsFor(repo.IgnoreSummary{})
	if all != (setupQuestions{Severity: true, Paths: true, Categories: true, CWEs: true}) || len(all.skipped()) != 0 {
		t.Errorf("no .armisignore: %+v, skipped %q", all, all.skipped())
	}
	some := questionsFor(repo.IgnoreSummary{RootFile: true, Severities: true, Paths: true})
	if some.Severity || some.Paths || !some.Categories || !some.CWEs {
		t.Errorf("severity and path lines: %+v", some)
	}
	if got := strings.Join(some.skipped(), ", "); got != "minimum severity and severity, path excludes" {
		t.Errorf("skipped = %q", got)
	}
}

func TestSetupAnswers_ToSetup(t *testing.T) {
	a := setupAnswers{
		MinSeverity:  "medium",
		PathExcludes: "node_modules/, dist/",
		Severities:   []string{"critical"},
		Categories:   []string{"license"},
		CWEs:         "CWE-89, 79",
		Labels:       "Team-A, pci",
	}
	got, err := a.toSetup(setupQuestions{Severity: true, Paths: true, Categories: true, CWEs: true})
	if err != nil {
		t.Fatalf("toSetup: %v", err)
	}
	want := project.Filters{
		MinSeverity: "MEDIUM", PathExcludes: []string{"node_modules/", "dist/"},
		Severities: []string{"CRITICAL"}, Categories: []string{"license"}, CWEs: []int{79, 89},
	}
	if !slices.Equal(got.Labels, []string{"team-a", "pci"}) || got.Filters.MinSeverity != want.MinSeverity ||
		!slices.Equal(got.Filters.PathExcludes, want.PathExcludes) || !slices.Equal(got.Filters.Severities, want.Severities) ||
		!slices.Equal(got.Filters.Categories, want.Categories) || !slices.Equal(got.Filters.CWEs, want.CWEs) {
		t.Errorf("toSetup = %+v", got)
	}

	// The questions the .armisignore answered keep nothing, whatever the form held.
	got, err = a.toSetup(setupQuestions{Categories: true})
	if err != nil {
		t.Fatalf("only categories asked: %v", err)
	}
	if got.Filters.MinSeverity != "" || got.Filters.PathExcludes != nil || got.Filters.CWEs != nil || len(got.Filters.Categories) != 1 {
		t.Errorf("only categories asked: %+v", got.Filters)
	}

	if _, err := (setupAnswers{CWEs: "nope"}).toSetup(setupQuestions{CWEs: true}); err == nil {
		t.Error("an invalid CWE should fail")
	}
}

// repoArmisignore is the .armisignore of the tests' made-up folder /repo as
// the summary names it, with this OS's path separator.
var repoArmisignore = filepath.Join("/repo", ".armisignore")

func TestPrintSetupSummary(t *testing.T) {
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	setup := &project.Setup{Labels: []string{"pci"}, Filters: project.Filters{PathExcludes: []string{"dist/"}}}

	var buf bytes.Buffer
	printSetupSummary(&buf, "payments-api", setup, repo.IgnoreSummary{Root: "/repo"}, now)
	out := buf.String()
	for _, want := range []string{"payments-api, a CLI / CI-CD project", "Labels   pci", "Creates " + repoArmisignore + ":",
		"# armis-cli project setup: payments-api, 2026-11-26", "dist/"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	printSetupSummary(&buf, "p", setup, repo.IgnoreSummary{Root: "/repo", RootFile: true}, now)
	if !strings.Contains(buf.String(), "Adds to "+repoArmisignore+" (appended; your lines are kept):") {
		t.Errorf("an existing file: %s", buf.String())
	}

	buf.Reset()
	printSetupSummary(&buf, "p", &project.Setup{}, repo.IgnoreSummary{Root: "/repo"}, now)
	if !strings.Contains(buf.String(), "No filters to add") || !strings.Contains(buf.String(), "Labels   (none)") {
		t.Errorf("nothing to add: %s", buf.String())
	}
}

func TestSetupAllowed(t *testing.T) {
	keep(t, &noInput)
	keep(t, &isInteractive)
	dev := project.Decision{Publish: true, Trigger: project.TriggerCLIDev}
	ci := project.Decision{Publish: true, Trigger: project.TriggerCLICI}

	for _, tt := range []struct {
		name        string
		decision    project.Decision
		interactive bool
		noInputFlag bool
		env         string
		want        bool
	}{
		{"a developer's terminal", dev, true, false, "", true},
		{"CI, even with a terminal", ci, true, false, "", false},
		{"no terminal", dev, false, false, "", false},
		{"--no-input", dev, true, true, "", false},
		{"ARMIS_NO_INPUT=1", dev, true, false, "1", false},
		{"ARMIS_NO_INPUT=true", dev, true, false, "true", false},
		{"ARMIS_NO_INPUT=0 asks", dev, true, false, "0", true},
		{"ARMIS_NO_INPUT=off asks", dev, true, false, "off", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ARMIS_NO_INPUT", tt.env)
			noInput = tt.noInputFlag
			isInteractive = func() bool { return tt.interactive }
			if got := setupAllowed(tt.decision); got != tt.want {
				t.Errorf("setupAllowed = %v, want %v", got, tt.want)
			}
		})
	}
}

// setupForm makes the setup's questions answer setup, recording what they got.
func setupForm(t *testing.T, setup *project.Setup, err error) *[]repo.IgnoreSummary {
	t.Helper()
	var seen []repo.IgnoreSummary
	isInteractive = func() bool { return true }
	runSetupForm = func(_ context.Context, name string, ignore repo.IgnoreSummary, _ []string) (*project.Setup, error) {
		if name != testProjectName {
			t.Errorf("setup asked for %q, want %q", name, testProjectName)
		}
		seen = append(seen, ignore)
		return setup, err
	}
	return &seen
}

func TestProjectScan_FirstRunSetsUpTheProject(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectName, reportScan = testProjectName, true
	seen := setupForm(t, &project.Setup{
		Labels:  []string{"team-a"},
		Filters: project.Filters{PathExcludes: []string{"secret/"}, CWEs: []int{79}},
	}, nil)

	dir := newScanDir(t)
	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].Root != dir || (*seen)[0].RootFile {
		t.Fatalf("the setup saw %+v, want the folder once, without an .armisignore", *seen)
	}

	creates := env.rec.Matching(http.MethodPost, projectsPathPart)
	if len(creates) != 1 || string(creates[0].Body) != `{"name":"checkout-service","project_type":"ci_cd","tags":["team-a"]}` {
		t.Fatalf("creates = %+v", creates)
	}
	written, err := os.ReadFile(filepath.Join(dir, ".armisignore")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read .armisignore: %v", err)
	}
	for _, want := range []string{"# armis-cli project setup: checkout-service,", "secret/", "cwe:79", "# end armis-cli project setup"} {
		if !strings.Contains(string(written), want) {
			t.Errorf(".armisignore missing %q:\n%s", want, written)
		}
	}
	for _, want := range []string{"Created project", "with labels team-a", "lines to " + filepath.Join(dir, ".armisignore"),
		"commit it, so CI scans apply the same filters"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if body, _ := env.scanBody(t); body.ProjectID != firstMockProjectID {
		t.Errorf("/ingest/scan project_id = %q", body.ProjectID)
	}
}

func TestProjectScan_UseDefaultsCreatesAsBefore(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectName, reportScan = testProjectName, true
	setupForm(t, &project.Setup{}, nil)

	dir := newScanDir(t)
	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) }); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	creates := env.rec.Matching(http.MethodPost, projectsPathPart)
	if len(creates) != 1 || string(creates[0].Body) != `{"name":"checkout-service","project_type":"ci_cd"}` {
		t.Errorf("creates = %+v", creates)
	}
	if _, err := os.Stat(filepath.Join(dir, ".armisignore")); !os.IsNotExist(err) {
		t.Errorf("defaults must write no .armisignore: %v", err)
	}
}

func TestProjectScan_ACancelledSetupStopsEverything(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectName, reportScan = testProjectName, true
	setupForm(t, nil, project.ErrSetupCancelled)

	dir := newScanDir(t)
	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) })
	if !errors.Is(err, ErrScanCancelled) {
		t.Fatalf("err = %v, want ErrScanCancelled (exit 130)", err)
	}
	if !strings.Contains(stderr, "Project setup cancelled: nothing was created or uploaded.") {
		t.Errorf("stderr:\n%s", stderr)
	}
	if n := len(env.rec.Matching(http.MethodPost, projectsPathPart)); n != 0 {
		t.Errorf("create calls = %d, want 0", n)
	}
	if n := len(env.rec.Matching("", "/presigned-url")); n != 0 {
		t.Errorf("an upload started: %d presigned-url calls", n)
	}
	if _, err := os.Stat(filepath.Join(dir, ".armisignore")); !os.IsNotExist(err) {
		t.Errorf("a cancel must write nothing: %v", err)
	}
}

func TestProjectScan_NoInputNeverAsks(t *testing.T) {
	for _, viaEnv := range []bool{false, true} {
		t.Run(map[bool]string{false: "--no-input", true: "ARMIS_NO_INPUT"}[viaEnv], func(t *testing.T) {
			env := setupProjectScan(t, testutil.MockAPIConfig{})
			projectName, reportScan = testProjectName, true
			projectLabels = []string{"PCI"}
			isInteractive = func() bool { return true } // the form seam still fails the test if it runs
			if viaEnv {
				t.Setenv("ARMIS_NO_INPUT", "1")
			} else {
				noInput = true
			}
			if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) }); err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			creates := env.rec.Matching(http.MethodPost, projectsPathPart)
			if len(creates) != 1 || string(creates[0].Body) != `{"name":"checkout-service","project_type":"ci_cd","tags":["pci"]}` {
				t.Errorf("creates = %+v", creates)
			}
		})
	}
}

func TestProjectScan_CICreatesWithItsLabels(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	t.Setenv("GITHUB_ACTIONS", "true")
	projectName = testProjectName
	projectLabels = []string{"team-a,team-b", "Team-A"}
	isInteractive = func() bool { return true } // CI never asks, terminal or not

	_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	creates := env.rec.Matching(http.MethodPost, projectsPathPart)
	if len(creates) != 1 || string(creates[0].Body) != `{"name":"checkout-service","project_type":"ci_cd","tags":["team-a","team-b"]}` {
		t.Errorf("creates = %+v", creates)
	}
	if !strings.Contains(stderr, "with labels team-a, team-b") {
		t.Errorf("stderr:\n%s", stderr)
	}
}

func TestProjectScan_AnExistingProjectKeepsItsLabels(t *testing.T) {
	source := "cli"
	existing := model.Project{ProjectID: "p_existing", Name: testProjectName, ProjectType: model.ProjectTypeCICD,
		Status: model.ProjectStatusActive, Source: &source, Tags: []string{"old"}}

	for _, tt := range []struct {
		labels []string
		warn   bool
	}{{[]string{"new"}, true}, {[]string{"OLD"}, false}} {
		env := setupProjectScan(t, testutil.MockAPIConfig{Projects: []model.Project{existing}})
		t.Setenv("GITHUB_ACTIONS", "true")
		projectName, projectLabels = testProjectName, tt.labels

		_, stderr, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) })
		if err != nil {
			t.Fatalf("labels %q: scan failed: %v", tt.labels, err)
		}
		if n := len(env.rec.Matching(http.MethodPost, projectsPathPart)); n != 0 {
			t.Errorf("labels %q: create calls = %d", tt.labels, n)
		}
		warned := strings.Contains(stderr, "its labels (old) were not changed to new")
		if warned != tt.warn {
			t.Errorf("labels %q: warned = %v, want %v:\n%s", tt.labels, warned, tt.warn, stderr)
		}
	}
}

func TestProjectScan_SetupSeesAndExtendsAnExistingArmisignore(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})
	projectName, reportScan = testProjectName, true
	seen := setupForm(t, &project.Setup{Filters: project.Filters{Categories: []string{"license"}}}, nil)

	dir := newScanDir(t)
	if err := os.WriteFile(filepath.Join(dir, ".armisignore"), []byte("vendor/\nseverity:LOW\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{dir}) }); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := (*seen)[0]; !got.RootFile || !got.Paths || !got.Severities || got.Categories || got.CWEs {
		t.Errorf("the setup saw %+v", got)
	}
	written, _ := os.ReadFile(filepath.Join(dir, ".armisignore")) //nolint:gosec // test path
	if !strings.HasPrefix(string(written), "vendor/\nseverity:LOW\n\n# armis-cli project setup:") ||
		!strings.Contains(string(written), "category:license") {
		t.Errorf(".armisignore =\n%s", written)
	}
}

func TestProjectLabelFlag_IsCheckedBeforeAnything(t *testing.T) {
	env := setupProjectScan(t, testutil.MockAPIConfig{})
	projectLabels = []string{"pci"}
	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) }); err == nil ||
		!strings.Contains(err.Error(), "--project-label labels the project a scan creates, so it needs --project") {
		t.Errorf("without --project: err = %v", err)
	}

	projectName, projectLabels = testProjectName, []string{strings.Repeat("a", project.MaxLabelLength+1)}
	if _, _, err := runScan(t, func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{newScanDir(t)}) }); err == nil ||
		!strings.Contains(err.Error(), "invalid --project-label") {
		t.Errorf("a long label: err = %v", err)
	}
	if n := len(env.rec.Requests()); n != 0 {
		t.Errorf("requests before the flags were checked: %d", n)
	}
}

// lineReader hands out one line per Read, as a terminal does. Each of huh's
// accessible prompts reads through a bufio.Scanner of its own, which would
// buffer every later answer away from a reader that gives more.
type lineReader struct{ pending []string }

func (r *lineReader) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.pending[0])
	if n == len(r.pending[0]) {
		r.pending = r.pending[1:]
	} else {
		r.pending[0] = r.pending[0][n:]
	}
	return n, nil
}

// askWith runs the real setup form in huh's accessible mode (the tests' colors
// are off), feeding it lines, and returns what it decided and printed.
func askWith(t *testing.T, ignore repo.IgnoreSummary, flagLabels []string, lines ...string) (*project.Setup, string, error) {
	t.Helper()
	keep(t, &setupIn)
	keep(t, &setupOut)
	var out bytes.Buffer
	pending := make([]string, len(lines))
	for i, line := range lines {
		pending[i] = line + "\n"
	}
	setupIn = &lineReader{pending: pending}
	setupOut = &out
	setup, err := askProjectSetup(t.Context(), testProjectName, ignore, flagLabels)
	return setup, out.String(), err
}

// idleTerminal is a terminal no one types on: Read waits until it is closed,
// then reports EOF. reading is closed at the first Read.
type idleTerminal struct {
	once            sync.Once
	reading, closed chan struct{}
}

func (r *idleTerminal) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.reading) })
	<-r.closed
	return 0, io.EOF
}

// In accessible mode Ctrl-C is a SIGINT, which the scan's signal context
// takes: a question waiting on its line must give up when the context ends.
func TestAskProjectSetup_AnEndedContextStopsAWaitingQuestion(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{}) // colors off: accessible mode
	keep(t, &setupIn)
	keep(t, &setupOut)
	terminal := &idleTerminal{reading: make(chan struct{}), closed: make(chan struct{})}
	setupIn, setupOut = terminal, io.Discard
	// The abandoned question reads EOF, takes its default and ends.
	t.Cleanup(func() { close(terminal.closed); accessibleForms.Wait() })

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := askProjectSetup(ctx, testProjectName, repo.IgnoreSummary{Root: "/repo"}, nil)
		errc <- err
	}()
	<-terminal.reading // the first question waits on its line
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, project.ErrSetupCancelled) {
			t.Errorf("err = %v, want ErrSetupCancelled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the setup still waits on its question after the context ended")
	}

	// A context that has already ended asks nothing.
	if _, err := askProjectSetup(ctx, testProjectName, repo.IgnoreSummary{Root: "/repo"}, nil); !errors.Is(err, project.ErrSetupCancelled) {
		t.Errorf("an ended context: err = %v, want ErrSetupCancelled", err)
	}
}

func TestAskProjectSetup_TheQuestionsOneByOne(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{}) // colors off: accessible mode
	setup, out, err := askWith(t, repo.IgnoreSummary{Root: "/repo"}, nil,
		"1",              // Set up now
		"",               // Minimum severity: keep Medium
		"#bad",           // Path excludes: refused, asked again
		"secret/, dist/", //   then accepted
		"1", "0",         // Suppress by severity: Critical, done
		"5", "0", // Suppress by category: License, done
		"CWE-79",      // Suppress by CWE ID
		"Team-A, pci", // Project labels
		"1",           // Create the project
	)
	if err != nil {
		t.Fatalf("ask: %v\n%s", err, out)
	}
	want := project.Filters{MinSeverity: "MEDIUM", PathExcludes: []string{"secret/", "dist/"},
		Severities: []string{"CRITICAL"}, Categories: []string{"license"}, CWEs: []int{79}}
	if !slices.Equal(setup.Labels, []string{"team-a", "pci"}) || setup.Filters.MinSeverity != want.MinSeverity ||
		!slices.Equal(setup.Filters.PathExcludes, want.PathExcludes) || !slices.Equal(setup.Filters.Severities, want.Severities) ||
		!slices.Equal(setup.Filters.Categories, want.Categories) || !slices.Equal(setup.Filters.CWEs, want.CWEs) {
		t.Errorf("setup = %+v", setup)
	}
	for _, q := range []string{`Project "checkout-service" doesn't exist in this tenant yet. Set it up now?`, "Minimum severity",
		"Path excludes (optional)", "starts with #", "Suppress by severity (optional)", "Suppress by scanner category (optional)",
		"Suppress by CWE ID (optional)", "Project labels (optional)", "Creates " + repoArmisignore + ":", "Create the project?"} {
		if !strings.Contains(out, q) {
			t.Errorf("the form never showed %q:\n%s", q, out)
		}
	}
}

func TestAskProjectSetup_DefaultsCancelAndEdit(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})

	setup, _, err := askWith(t, repo.IgnoreSummary{Root: "/repo"}, []string{"from-flag"}, "2") // Use defaults
	if err != nil || !setup.Filters.Empty() || !slices.Equal(setup.Labels, []string{"from-flag"}) {
		t.Errorf("Use defaults = %+v, %v", setup, err)
	}

	if _, _, err := askWith(t, repo.IgnoreSummary{Root: "/repo"}, nil, "3"); !errors.Is(err, project.ErrSetupCancelled) { // Cancel
		t.Errorf("Cancel = %v", err)
	}

	// Edit goes round again with the answers kept, then Create; Cancel at the summary cancels.
	setup, _, err = askWith(t, repo.IgnoreSummary{Root: "/repo"}, nil,
		"1", "", "", "0", "0", "", "first", "2",
		"", "", "0", "0", "", "second", "1")
	if err != nil || !slices.Equal(setup.Labels, []string{"second"}) {
		t.Errorf("Edit = %+v, %v", setup, err)
	}
	if _, _, err := askWith(t, repo.IgnoreSummary{Root: "/repo"}, nil, "1", "", "", "0", "0", "", "", "3"); !errors.Is(err, project.ErrSetupCancelled) {
		t.Errorf("Cancel at the summary = %v", err)
	}
}

func TestAskProjectSetup_SkipsWhatTheArmisignoreAnswers(t *testing.T) {
	setupProjectScan(t, testutil.MockAPIConfig{})
	ignore := repo.IgnoreSummary{Root: "/repo", RootFile: true, Severities: true, Paths: true}
	// Only categories, CWEs and labels are asked.
	setup, out, err := askWith(t, ignore, nil, "1", "2", "0", "89", "", "1")
	if err != nil {
		t.Fatalf("ask: %v\n%s", err, out)
	}
	if setup.Filters.MinSeverity != "" || setup.Filters.PathExcludes != nil ||
		!slices.Equal(setup.Filters.Categories, []string{"secrets"}) || !slices.Equal(setup.Filters.CWEs, []int{89}) {
		t.Errorf("setup = %+v", setup.Filters)
	}
	if !strings.Contains(out, "Using .armisignore for: minimum severity and severity, path excludes") ||
		strings.Contains(out, "Minimum severity") || strings.Contains(out, "Path excludes (optional)") ||
		!strings.Contains(out, "Adds to "+repoArmisignore+" (appended; your lines are kept):") {
		t.Errorf("out:\n%s", out)
	}
}

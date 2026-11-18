package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/spf13/cobra"
)

// oldServerBody is the 422 a server that predates BOM-only scans gives for
// scan_type "bom": a request validation error, not the detail.code shape.
const oldServerBody = `{"detail":[{"type":"enum","loc":["body","scan_type"],"msg":"Input should be 'full' or 'custom'","input":"bom"}]}`

// setupBOMRunEnv points the bom commands at serverURL, as setupScanRunEnv
// does for scan, and restores every global the bom commands read.
func setupBOMRunEnv(t *testing.T, serverURL string) {
	t.Helper()
	setupScanRunEnv(t, serverURL)
	origTypes, origFormat, origOutput := bomOnlyTypes, bomOnlyFormat, bomOnlyOutput
	origFiles, origTests, origTarball, origPull := includeFiles, includeTests, tarballPath, pullPolicy
	origScanTimeout, origUploadTimeout := scanTimeout, uploadTimeout
	t.Cleanup(func() {
		bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = origTypes, origFormat, origOutput
		includeFiles, includeTests, tarballPath, pullPolicy = origFiles, origTests, origTarball, origPull
		scanTimeout, uploadTimeout = origScanTimeout, origUploadTimeout
	})
	bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = defaultBOMOnlyTypes(), scan.BOMFormatCycloneDX17, ""
	includeFiles, includeTests, tarballPath, pullPolicy = nil, false, "", defaultPullPolicy
	scanTimeout, uploadTimeout = defaultScanTimeout, defaultUploadTimeout
}

// runBOM runs c's RunE with args, as the RunE tests of scan do, and returns
// stdout, stderr and the error. The caller sets the normalized flag values.
func runBOM(t *testing.T, c *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	stderr = testutil.CaptureStderr(t, func() {
		stdout = captureStdout(t, func() { err = c.RunE(c, args) })
	})
	return stdout, stderr, err
}

// mainExitCode is the exit code cmd/armis-cli/main.go gives for err.
func mainExitCode(err error) int {
	var findingsErr *output.ErrFindingsExceeded
	var incompleteErr *output.ErrResultsIncomplete
	var bomErr *output.ErrBOMIncomplete
	switch {
	case err == nil:
		return 0
	case errors.As(err, &findingsErr):
		return findingsErr.ExitCode
	case errors.As(err, &incompleteErr), errors.As(err, &bomErr):
		return 2
	case errors.Is(err, ErrScanCancelled):
		return ExitCodeCancelled
	}
	return 1
}

// scanRecorder records the /scan bodies and the paths a mock server sees.
type scanRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
	paths  []string
}

func (r *scanRecorder) hook(config testutil.MockAPIConfig) testutil.MockAPIConfig {
	config.OnScanRequest = func(body []byte) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.bodies = append(r.bodies, body)
	}
	config.OnRequest = func(req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.paths = append(r.paths, req.URL.Path)
	}
	return config
}

// body returns the one /scan body as a map, so tests see the keys on the wire.
func (r *scanRecorder) body(t *testing.T) map[string]any {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) != 1 {
		t.Fatalf("got %d /scan requests, want 1", len(r.bodies))
	}
	var got map[string]any
	if err := json.Unmarshal(r.bodies[0], &got); err != nil {
		t.Fatalf("decode /scan body %s: %v", r.bodies[0], err)
	}
	return got
}

// called reports whether any request path contained part.
func (r *scanRecorder) called(part string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.paths {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}

// writeDockerSaveTar writes a tarball with a docker save manifest.json that
// lists tags, and returns its path.
func writeDockerSaveTar(t *testing.T, name string, tags ...string) string {
	t.Helper()
	manifest, err := json.Marshal([]map[string]any{{"Config": "config.json", "RepoTags": tags, "Layers": []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest)), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// resetBOMFlags undoes what Execute parsed for the bom commands.
func resetBOMFlags(t *testing.T) {
	t.Helper()
	for _, name := range []string{"type", "format", "output", "no-progress", "scan-timeout", "upload-timeout", "poll-interval"} {
		resetParsedFlag(t, bomCmd.PersistentFlags(), name)
	}
	for _, name := range []string{"include-files", "include-tests"} {
		resetParsedFlag(t, bomRepoCmd.Flags(), name)
	}
	for _, name := range []string{"tarball", "pull"} {
		resetParsedFlag(t, bomImageCmd.Flags(), name)
	}
}

// TestBOMCommandFlagErrorsStopBeforeUpload runs the real command line: every
// rejected input exits 1 before auth, so the API server sees no request.
func TestBOMCommandFlagErrorsStopBeforeUpload(t *testing.T) {
	var requests atomic.Int32
	server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	setupBOMRunEnv(t, server.URL)
	t.Setenv("ARMIS_API_TOKEN", testToken)
	t.Setenv("ARMIS_TENANT_ID", testTenantID)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	repoDir := t.TempDir()
	tarball := filepath.Join(t.TempDir(), "image.tar")
	testhelpers.WriteMinimalTar(t, tarball)

	rows := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"--type=", []string{"bom", "repo", repoDir, "--type="}, "--type requires a value: one of [sbom aibom cbom all]"},
		{"only empty items", []string{"bom", "repo", repoDir, "--type", ","}, "--type requires a value"},
		{"unknown type", []string{"bom", "repo", repoDir, "--type", "aibom,xbom"}, `invalid --type value "xbom"`},
		{"unknown format", []string{"bom", "repo", repoDir, "--format", "xml"}, `invalid --format value "xml"`},
		{"the default type with spdx", []string{"bom", "repo", repoDir, "--format", "spdx"},
			"--format spdx is not available for --type all (the default): the Combined BOM has no SPDX form"},
		{"a typed all with spdx", []string{"bom", "repo", repoDir, "--type", "all", "--format", "spdx"},
			"--format spdx is not available for --type all: the Combined BOM has no SPDX form"},
		{"aibom with spdx-2.3", []string{"bom", "repo", repoDir, "--type", "aibom", "--format", "spdx-2.3"},
			"--format spdx-2.3 is not available for --type aibom: the AI-BOM's SPDX form is spdx-3.0.1"},
		{"cbom with SPDX-3.0.1 on an image", []string{"bom", "image", "--tarball", tarball, "--type", "cbom", "--format", "SPDX-3.0.1"},
			"the CBOM has no SPDX form"},
		{"stdout with two types", []string{"bom", "repo", repoDir, "--type", "cbom", "--type", "aibom", "--output", "-"},
			"--output - takes one BOM type, got 2: aibom,cbom"},
		{"output is a file", []string{"bom", "repo", repoDir, "--output", tarball}, "not a directory"},
		{"output with ..", []string{"bom", "repo", repoDir, "--output", "../boms"}, "path traversal detected"},
		{"output names a new .json file", []string{"bom", "repo", repoDir, "--output", filepath.Join(repoDir, "sbom.JSON")},
			"--output takes a directory, not a file name; use --output - to write the BOM to stdout, or name a directory"},
		{"output names a new .json file for two types", []string{"bom", "repo", repoDir, "--type", "sbom,cbom", "--output", filepath.Join(repoDir, "boms.json")},
			"--output takes a directory, not a file name; name a directory for the 2 BOM files"},
		{"scan timeout 0", []string{"bom", "repo", repoDir, "--scan-timeout", "0"}, "invalid --scan-timeout value 0"},
		{"upload timeout over 2 hours", []string{"bom", "image", "--tarball", tarball, "--upload-timeout", "121"}, "must not exceed 120 minutes"},
		{"repo path missing", []string{"bom", "repo", filepath.Join(repoDir, "none")}, "path does not exist"},
		{"repo path is a file", []string{"bom", "repo", tarball}, "path is not a directory"},
		{"--include-files outside the repo", []string{"bom", "repo", repoDir, "--include-files", "../x.go"}, "invalid --include-files"},
		{"image without a target", []string{"bom", "image"}, "missing target: specify an image name or use --tarball"},
		{"bad --pull", []string{"bom", "image", "app:1", "--pull", "sometimes"}, `invalid --pull value "sometimes"`},
		{"tarball missing", []string{"bom", "image", "--tarball", tarball + ".none"}, "tarball does not exist"},
		{"no --fail-on on bom", []string{"bom", "repo", repoDir, "--fail-on", "HIGH"}, "unknown flag: --fail-on"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			// A slice flag appends after its first Set in this process, so
			// start each row from the flag defaults.
			resetBOMFlags(t)
			t.Cleanup(func() { resetBOMFlags(t) })
			rootCmd.SetArgs(row.args)
			err := Execute()
			if err == nil || !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, row.wantErr)
			}
			if code := mainExitCode(err); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("server saw %d requests, want none before the error", n)
			}
		})
	}
}

// TestBOMDefaultOutputDirStopsBeforeUpload: a default .armis that is a
// symlink, as a scanned repository can commit, stops bom before any request.
func TestBOMDefaultOutputDirStopsBeforeUpload(t *testing.T) {
	var requests atomic.Int32
	server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	setupBOMRunEnv(t, server.URL)
	t.Setenv("ARMIS_API_TOKEN", testToken)
	t.Setenv("ARMIS_TENANT_ID", testTenantID)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	repoDir := t.TempDir()
	t.Chdir(t.TempDir())
	outside := t.TempDir()
	if err := os.Symlink(outside, ".armis"); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	rows := []struct {
		name    string
		args    []string
		wantErr string // "" passes the check
	}{
		{"default output", []string{"bom", "repo", repoDir}, "invalid Combined BOM output path: .armis is not a plain directory"},
		{"default output, cbom", []string{"bom", "repo", repoDir, "--type", "cbom"}, "invalid CBOM output path: .armis is not a plain directory"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			// A slice flag appends after its first Set in this process, so
			// start each row from the flag defaults.
			resetBOMFlags(t)
			t.Cleanup(func() { resetBOMFlags(t) })
			rootCmd.SetArgs(row.args)
			err := Execute()
			if err == nil || !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, row.wantErr)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("server saw %d requests, want none", n)
			}
		})
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("wrote through the link: %v", entries)
	}
}

// TestBOMCommandLine runs the real command line against the mock API: the
// default type is all, the request is a BOM-only scan, no findings are
// fetched, and one file is written.
func TestBOMCommandLine(t *testing.T) {
	const allDoc = `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`
	var rec scanRecorder
	setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, rec.hook(testutil.MockAPIConfig{
		BOMContent: map[string]string{"bom_results": allDoc},
	})))
	t.Setenv("ARMIS_API_TOKEN", testToken)
	t.Setenv("ARMIS_TENANT_ID", testTenantID)
	t.Cleanup(func() {
		resetBOMFlags(t)
		rootCmd.SetArgs(nil)
	})
	repoDir := createTestRepo(t)
	dir := t.TempDir()
	// A process starts with the flag's own default, nil; the command applies all.
	resetBOMFlags(t)

	rootCmd.SetArgs([]string{"bom", "repo", repoDir, "--output", dir, "--no-progress", "--poll-interval", "10ms"})
	var err error
	var stdout string
	stderr := testutil.CaptureStderr(t, func() { stdout = captureStdout(t, func() { err = Execute() }) })
	if err != nil {
		t.Fatalf("bom repo: %v\nstderr: %s", err, stderr)
	}
	got := rec.body(t)
	if got["scan_type"] != "bom" {
		t.Errorf("scan_type = %v, want bom", got["scan_type"])
	}
	if types, _ := got["bom_types"].([]any); len(types) != 1 || types[0] != "all" {
		t.Errorf("bom_types = %v, want [all] by default", got["bom_types"])
	}
	if rec.called("/normalized-results") {
		t.Error("a BOM-only scan fetched findings")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing outside --output -", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.Base(repoDir)+"-bom-all.json")); err != nil {
		t.Errorf("expected the combined BOM file: %v", err)
	}
	if !strings.Contains(stderr, "Combined BOM saved to:") {
		t.Errorf("stderr = %q, want the saved line", stderr)
	}
}

// TestBOMRepoRunE_RequestBody checks the /scan body of bom repo: scan_type
// bom, the types and the format as typed, nothing a security scan alone
// sends, and the git hints of a full upload of a checkout, as scan repo sends
// them.
func TestBOMRepoRunE_RequestBody(t *testing.T) {
	rows := []struct {
		name       string
		types      []string
		format     string
		files      []string
		gitRepo    bool
		wantTypes  []any
		wantFormat string
		wantWarn   string
		wantHints  bool
	}{
		{name: "default", types: []string{"all"}, format: "cyclonedx-1.7", wantTypes: []any{"all"}, wantFormat: "cyclonedx-1.7"},
		{name: "two types, cyclonedx-1.6", types: []string{"aibom", "cbom"}, format: "cyclonedx-1.6",
			wantTypes: []any{"aibom", "cbom"}, wantFormat: "cyclonedx-1.6"},
		{name: "the spdx alias as typed", types: []string{"sbom"}, format: "spdx", wantTypes: []any{"sbom"}, wantFormat: "spdx"},
		{name: "--include-files warns", types: []string{"all"}, format: "cyclonedx-1.7", files: []string{"main.go"},
			wantTypes: []any{"all"}, wantFormat: "cyclonedx-1.7", wantWarn: "BOMs cover only the uploaded files"},
		{name: "a git checkout sends its git hints", types: []string{"all"}, format: "cyclonedx-1.7", gitRepo: true,
			wantTypes: []any{"all"}, wantFormat: "cyclonedx-1.7", wantHints: true},
		{name: "a git checkout with --include-files sends none", types: []string{"all"}, format: "cyclonedx-1.7", gitRepo: true,
			files: []string{"main.go"}, wantTypes: []any{"all"}, wantFormat: "cyclonedx-1.7", wantWarn: "BOMs cover only the uploaded files"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var rec scanRecorder
			doc := `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, rec.hook(testutil.MockAPIConfig{
				BOMContent: map[string]string{"bom_results": doc, "aibom_cdx16_results": doc, "cbom_cdx16_results": doc,
					"bom_sbom_spdx23_results": `{"spdxVersion":"SPDX-2.3","packages":[{"name":"p"}]}`},
			})))
			repoDir := createTestRepo(t)
			if row.gitRepo {
				initGitCheckout(t, repoDir)
			}
			bomOnlyTypes, bomOnlyFormat, bomOnlyOutput, includeFiles = row.types, row.format, t.TempDir(), row.files
			_, stderr, err := runBOM(t, bomRepoCmd, repoDir)
			if err != nil {
				t.Fatalf("bom repo: %v", err)
			}
			got := rec.body(t)
			if got["scan_type"] != "bom" {
				t.Errorf("scan_type = %v, want bom", got["scan_type"])
			}
			if !reflect.DeepEqual(got["bom_types"], row.wantTypes) {
				t.Errorf("bom_types = %v, want %v", got["bom_types"], row.wantTypes)
			}
			if got["bom_format"] != row.wantFormat {
				t.Errorf("bom_format = %v, want %s", got["bom_format"], row.wantFormat)
			}
			if got["sbom_generate"] != false || got["vex_generate"] != false {
				t.Errorf("sbom_generate = %v, vex_generate = %v, want false", got["sbom_generate"], got["vex_generate"])
			}
			for _, key := range []string{"custom_scans", "sbom_format", "image_ref"} {
				if v, ok := got[key]; ok {
					t.Errorf("%s = %v, want it omitted", key, v)
				}
			}
			if row.wantHints {
				hints := repo.DetectGitHints(repoDir)
				if got["repo_name"] != "example/app" || got["git_sha"] != hints.GitSHA {
					t.Errorf("repo_name = %v, git_sha = %v; want example/app and %s", got["repo_name"], got["git_sha"], hints.GitSHA)
				}
			} else {
				for _, key := range []string{"repo_name", "git_sha", "origin_sha"} {
					if v, ok := got[key]; ok {
						t.Errorf("%s = %v, want it omitted", key, v)
					}
				}
			}
			if rec.called("/normalized-results") {
				t.Error("a BOM-only scan fetched findings")
			}
			if row.wantWarn != "" && !strings.Contains(stderr, row.wantWarn) {
				t.Errorf("stderr = %q, want %q", stderr, row.wantWarn)
			}
			if row.wantWarn == "" && strings.Contains(stderr, "BOMs cover only") {
				t.Errorf("stderr = %q, want no partial-upload warning", stderr)
			}
		})
	}
}

// initGitCheckout makes dir a clean git checkout with an origin remote, from
// which scan repo would send git hints.
func initGitCheckout(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "test@example.com"}, {"config", "user.name", "Test User"},
		{"remote", "add", "origin", "https://github.com/example/app.git"}, {"add", "."}, {"commit", "-q", "-m", "init"},
	} {
		if err := runTestGitCmd(dir, args...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	if hints := repo.DetectGitHints(dir); hints.RepoName == "" || hints.GitSHA == "" {
		t.Fatalf("the checkout gives no git hints (%+v), so the test proves nothing", hints)
	}
}

// TestBOMImageRunE_RequestBody checks bom image --tarball: image_ref from the
// manifest tag, as scan image --bom sends it, and the file name.
func TestBOMImageRunE_RequestBody(t *testing.T) {
	const cbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	rows := []struct {
		name      string
		tags      []string
		wantRef   any // nil: image_ref omitted
		withImage bool
	}{
		{name: "the manifest tag", tags: []string{"myorg/app:2.0"}, wantRef: "myorg/app:2.0"},
		{name: "no tag sends no image_ref"},
		{name: "--tarball wins over an image name", tags: []string{"myorg/app:2.0"}, wantRef: "myorg/app:2.0", withImage: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var rec scanRecorder
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, rec.hook(testutil.MockAPIConfig{
				BOMContent: map[string]string{"cbom_results": cbomDoc},
			})))
			tarballPath = writeDockerSaveTar(t, "app.tar", row.tags...)
			dir := t.TempDir()
			bomOnlyTypes, bomOnlyOutput = []string{"cbom"}, dir
			var args []string
			if row.withImage {
				args = []string{"other:1"}
			}
			_, stderr, err := runBOM(t, bomImageCmd, args...)
			if err != nil {
				t.Fatalf("bom image: %v", err)
			}
			got := rec.body(t)
			if got["scan_type"] != "bom" {
				t.Errorf("scan_type = %v, want bom", got["scan_type"])
			}
			if got["image_ref"] != row.wantRef {
				t.Errorf("image_ref = %v, want %v", got["image_ref"], row.wantRef)
			}
			if rec.called("/normalized-results") {
				t.Error("a BOM-only scan fetched findings")
			}
			if _, err := os.Stat(filepath.Join(dir, "app-bom-cbom.json")); err != nil {
				t.Errorf("expected app-bom-cbom.json: %v", err)
			}
			if row.withImage && !strings.Contains(stderr, "using tarball (image name ignored)") {
				t.Errorf("stderr = %q, want the tarball warning", stderr)
			}
		})
	}
}

// TestBOMRunE_ServerRefusals covers the /scan answers that end a bom command
// with exit 1: an old server's enum error, read as a plain message, and the
// new server's refusal codes, printed in the scan --bom form.
func TestBOMRunE_ServerRefusals(t *testing.T) {
	refusal := func(code, msg string) string {
		return `{"detail":{"code":"` + code + `","message":"` + msg + `"}}`
	}
	const oldPrefix = "this Armis server does not support BOM-only scans yet; run: "
	rows := []struct {
		name    string
		image   bool
		types   []string
		format  string
		output  string
		files   []string
		tests   bool
		body    string
		wantErr string // <repo> and <tarball> stand for the target as typed
		wantOld bool
	}{
		{name: "old server, repo", body: oldServerBody,
			wantErr: oldPrefix + "armis-cli scan repo <repo> --bom all", wantOld: true},
		{name: "old server, repo, types, format and output", types: []string{"aibom", "cbom"}, format: "cyclonedx-1.6",
			output: "./my boms", body: oldServerBody,
			wantErr: oldPrefix + "armis-cli scan repo <repo> --bom aibom,cbom --bom-format cyclonedx-1.6 --bom-output './my boms'", wantOld: true},
		{name: "old server, repo, upload flags", files: []string{"main.go"}, tests: true, body: oldServerBody,
			wantErr: oldPrefix + "armis-cli scan repo <repo> --include-files main.go --include-tests --bom all", wantOld: true},
		{name: "old server, image tarball", image: true, types: []string{"sbom"}, format: "spdx", body: oldServerBody,
			wantErr: oldPrefix + "armis-cli scan image --tarball <tarball> --bom sbom --bom-format spdx", wantOld: true},
		{name: "a validation error on another field", body: `{"detail":[{"loc":["body","bom_format"],"msg":"bad"}]}`,
			wantErr: "/scan returned 422 Unprocessable Entity"},
		{name: "bom_types_required", body: refusal("bom_types_required", "bom_types is required"),
			wantErr: "the server refused the BOM request (--type all --format cyclonedx-1.7): bom_types is required (bom_types_required)"},
		{name: "custom_scans_not_allowed", body: refusal("custom_scans_not_allowed", "custom_scans is not allowed"),
			wantErr: "the server refused the BOM request (--type all --format cyclonedx-1.7): custom_scans is not allowed (custom_scans_not_allowed)"},
		{name: "sbom_vex_not_allowed", body: refusal("sbom_vex_not_allowed", "SBOM and VEX are not built"),
			wantErr: "the server refused the BOM request (--type all --format cyclonedx-1.7): SBOM and VEX are not built (sbom_vex_not_allowed)"},
		{name: "artifact_type_not_supported", image: true, body: refusal("artifact_type_not_supported", "not for this artifact"),
			wantErr: "the server refused the BOM request (--type all --format cyclonedx-1.7): not for this artifact (artifact_type_not_supported)"},
		{name: "export_format_unavailable", types: []string{"sbom"}, format: "spdx-3.0.1", body: refusal("export_format_unavailable", "not offered"),
			wantErr: "the server refused the BOM request (--type sbom --format spdx-3.0.1): not offered (export_format_unavailable)"},
		{name: "bom_generation_disabled, repo", body: refusal("bom_generation_disabled", "BOM generation is not enabled for this tenant."),
			wantErr: "the server refused the BOM request (--type all --format cyclonedx-1.7): BOM generation is not enabled for this tenant. (bom_generation_disabled)"},
		{name: "bom_generation_disabled, image", image: true, types: []string{"sbom", "cbom"}, format: "cyclonedx-1.7",
			body:    refusal("bom_generation_disabled", "BOM generation is not enabled for this tenant."),
			wantErr: "the server refused the BOM request (--type sbom,cbom --format cyclonedx-1.7): BOM generation is not enabled for this tenant. (bom_generation_disabled)"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var rec scanRecorder
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, rec.hook(testutil.MockAPIConfig{
				ScanStatus: http.StatusUnprocessableEntity, ScanBody: row.body,
			})))
			if row.types != nil {
				bomOnlyTypes, bomOnlyFormat = row.types, row.format
			}
			bomOnlyOutput, includeFiles, includeTests = row.output, row.files, row.tests
			var err error
			want := row.wantErr
			if row.image {
				tarballPath = writeDockerSaveTar(t, "app.tar")
				want = strings.ReplaceAll(want, "<tarball>", shellArg(tarballPath, "<file>"))
				_, _, err = runBOM(t, bomImageCmd)
			} else {
				repoDir := createTestRepo(t)
				want = strings.ReplaceAll(want, "<repo>", shellArg(repoDir, "<path>"))
				_, _, err = runBOM(t, bomRepoCmd, repoDir)
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want it to contain %q", err, want)
			}
			if row.wantOld && err.Error() != want {
				t.Errorf("error = %q, want exactly %q", err, want)
			}
			if errors.Is(err, api.ErrBOMScanUnsupported) != row.wantOld {
				t.Errorf("errors.Is(err, ErrBOMScanUnsupported) = %v, want %v", !row.wantOld, row.wantOld)
			}
			if code := mainExitCode(err); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if rec.called("/status") || rec.called("/results") || rec.called("/_bom/") {
				t.Error("polled, fetched results or downloaded after /scan refused")
			}
		})
	}
}

// TestBOMRepoRunE_Files covers the outputs: the default .armis, a typed
// directory, SPDX and CycloneDX 1.6 keys, stdout, types not offered (exit 2
// when nothing is written) and an empty BOM.
func TestBOMRepoRunE_Files(t *testing.T) {
	const allDoc = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":"a"}]}`
	const aibomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"m"}]}`
	const cbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	const spdxDoc = `{"spdxVersion":"SPDX-2.3","packages":[{"name":"p"}]}`
	const cdx16Doc = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"m"}]}`
	rows := []struct {
		name      string
		docs      map[string]string
		types     []string
		format    string
		output    string // "default" for .armis in the working directory
		wantFiles map[string]string
		wantOut   string
		wantErr   []string // stderr lines
		wantNoErr []string
		wantCode  int
	}{
		{name: "the default .armis", docs: map[string]string{"bom_results": allDoc}, types: []string{"all"}, output: "default",
			wantFiles: map[string]string{"-bom-all.json": allDoc}, wantErr: []string{"Combined BOM saved to:", ".armis"}},
		{name: "two types into a directory", docs: map[string]string{"aibom_results": aibomDoc, "cbom_results": cbomDoc},
			types: []string{"aibom", "cbom"}, wantFiles: map[string]string{"-bom-aibom.json": aibomDoc, "-bom-cbom.json": cbomDoc},
			wantErr: []string{"AI-BOM saved to:", "CBOM saved to:"}},
		{name: "spdx gives the SPDX 2.3 SBOM", docs: map[string]string{"bom_sbom_spdx23_results": spdxDoc}, types: []string{"sbom"},
			format: "spdx", wantFiles: map[string]string{"-bom-sbom.spdx.json": spdxDoc}},
		{name: "cyclonedx-1.6 reads the _cdx16_ key", docs: map[string]string{"aibom_results": aibomDoc, "aibom_cdx16_results": cdx16Doc},
			types: []string{"aibom"}, format: "cyclonedx-1.6", wantFiles: map[string]string{"-bom-aibom.json": cdx16Doc}},
		{name: "stdout gets only the document", docs: map[string]string{"cbom_results": cbomDoc}, types: []string{"cbom"}, output: "-",
			wantOut: cbomDoc, wantErr: []string{"CBOM written to stdout"}, wantNoErr: []string{"saved to:"}},
		{name: "a tenant without BOMs: every type warns and exit 2", types: []string{"aibom", "cbom"},
			wantErr:   []string{"AI-BOM was requested but not available in results", "CBOM was requested but not available in results"},
			wantNoErr: []string{"saved to:"}, wantCode: 2},
		{name: "one type written, one not offered: exit 0", docs: map[string]string{"cbom_results": cbomDoc},
			types: []string{"aibom", "cbom"}, wantFiles: map[string]string{"-bom-cbom.json": cbomDoc},
			wantErr: []string{"AI-BOM was requested but not available in results", "CBOM saved to:"}},
		{name: "stdout with nothing to write: exit 2 and no output", types: []string{"cbom"}, output: "-",
			wantErr: []string{"CBOM was requested but not available in results"}, wantNoErr: []string{"written to stdout"}, wantCode: 2},
		{name: "an empty BOM is written and named", docs: map[string]string{"cbom_results": `{"bomFormat":"CycloneDX","components":[]}`},
			types: []string{"cbom"}, wantFiles: map[string]string{"-bom-cbom.json": `{"bomFormat":"CycloneDX","components":[]}`},
			wantErr: []string{"No crypto components found in <repo>"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{BOMContent: row.docs}))
			t.Chdir(t.TempDir())
			repoDir := createTestRepo(t)
			dir := t.TempDir()
			switch row.output {
			case "default":
				dir = scan.DefaultBOMDir
				bomOnlyOutput = ""
			case "-":
				bomOnlyOutput = scan.BOMOutputStdout
			default:
				bomOnlyOutput = dir
			}
			bomOnlyTypes = row.types
			if row.format != "" {
				bomOnlyFormat = row.format
			}
			stdout, stderr, err := runBOM(t, bomRepoCmd, repoDir)
			if code := mainExitCode(err); code != row.wantCode {
				t.Fatalf("exit code = %d (%v), want %d", code, err, row.wantCode)
			}
			if stdout != row.wantOut {
				t.Errorf("stdout = %q, want %q", stdout, row.wantOut)
			}
			for suffix, doc := range row.wantFiles {
				path := filepath.Join(dir, filepath.Base(repoDir)+suffix)
				data, err := os.ReadFile(path) //nolint:gosec // test path
				if err != nil {
					t.Fatalf("expected %s: %v", path, err)
				}
				if !bytes.Equal(data, scan.IndentJSON([]byte(doc))) {
					t.Errorf("%s = %s, want the stored document pretty-printed", path, data)
				}
				if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Errorf("%s mode = %v, want 0600", path, info.Mode().Perm())
				}
			}
			if len(row.wantFiles) == 0 && row.output != "-" {
				if entries, _ := os.ReadDir(dir); len(entries) != 0 {
					t.Errorf("wrote %v, want no files", entries)
				}
			}
			if row.output == "-" {
				if _, err := os.Stat(scan.DefaultBOMDir); err == nil {
					t.Error("stdout mode created .armis")
				}
			}
			for _, w := range row.wantErr {
				w = strings.ReplaceAll(w, "<repo>", repoDir)
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr = %q, want %q", stderr, w)
				}
			}
			for _, w := range row.wantNoErr {
				if strings.Contains(stderr, w) {
					t.Errorf("stderr = %q, want no %q", stderr, w)
				}
			}
			if strings.Contains(stderr, "Retrieving results") || strings.Contains(stderr, "SCAN SUMMARY") {
				t.Errorf("stderr = %q, want no findings report", stderr)
			}
		})
	}
}

// TestBOMRepoRunE_ExitCodes: 0 when at least one BOM is written, 2 when none
// is or a built BOM cannot be downloaded, findings or not.
func TestBOMRepoRunE_ExitCodes(t *testing.T) {
	critical := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("f-1", "CRITICAL", "sql_injection", nil, []string{"CWE-89"}),
	}
	const doc = `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`
	rows := []struct {
		name       string
		config     testutil.MockAPIConfig
		types      []string
		wantCode   int
		wantLabels []string
		wantMsg    string
	}{
		{name: "written", config: testutil.MockAPIConfig{BOMContent: map[string]string{"bom_results": doc}}, types: []string{"all"}, wantCode: 0},
		{name: "one of two written", config: testutil.MockAPIConfig{BOMContent: map[string]string{"cbom_results": doc}},
			types: []string{"sbom", "cbom"}, wantCode: 0},
		{name: "none offered", config: testutil.MockAPIConfig{}, types: []string{"sbom", "cbom"}, wantCode: 2, wantLabels: []string{"SBOM", "CBOM"},
			wantMsg: "scan completed but no BOM was written: SBOM, CBOM not available (scan ID: test-scan-001)"},
		{name: "not supported in the summary", config: testutil.MockAPIConfig{BOMSummary: map[string]interface{}{
			"types": map[string]interface{}{"aibom": map[string]interface{}{"status": "not_supported"}}}},
			types: []string{"aibom"}, wantCode: 2, wantLabels: []string{"AI-BOM"}},
		{name: "findings on the server do not count", config: testutil.MockAPIConfig{Findings: critical,
			BOMContent: map[string]string{"bom_results": doc}}, types: []string{"all"}, wantCode: 0},
		{name: "a download fails", config: testutil.MockAPIConfig{BOMContent: map[string]string{"aibom_results": doc, "cbom_results": doc},
			BOMDownloadStatus: http.StatusNotFound}, types: []string{"aibom", "cbom"}, wantCode: 2, wantLabels: []string{"AI-BOM", "CBOM"}},
		{name: "not valid JSON", config: testutil.MockAPIConfig{BOMContent: map[string]string{"cbom_results": "{not json"}},
			types: []string{"cbom"}, wantCode: 2, wantLabels: []string{"CBOM"}},
		{name: "the scan fails on the server", config: testutil.MockAPIConfig{FinalStatus: "FAILED", LastError: "boom"},
			types: []string{"all"}, wantCode: 1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, row.config))
			bomOnlyTypes, bomOnlyOutput = row.types, t.TempDir()
			_, _, err := runBOM(t, bomRepoCmd, createTestRepo(t))
			if code := mainExitCode(err); code != row.wantCode {
				t.Fatalf("exit code = %d (%v), want %d", code, err, row.wantCode)
			}
			if row.wantLabels != nil {
				var bomErr *output.ErrBOMIncomplete
				if !errors.As(err, &bomErr) || !reflect.DeepEqual(bomErr.Labels, row.wantLabels) {
					t.Errorf("error = %v, want ErrBOMIncomplete for %v", err, row.wantLabels)
				}
			}
			if row.wantMsg != "" && (err == nil || err.Error() != row.wantMsg) {
				t.Errorf("error = %v, want %q", err, row.wantMsg)
			}
		})
	}
}

// TestBOMRepoScan_CancelDuringDownload: Ctrl+C during a BOM download of a
// BOM-only scan exits 130, not 2.
func TestBOMRepoScan_CancelDuringDownload(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		BOMContent: map[string]string{"bom_results": `{"components":[]}`},
		OnBOMDownload: func(r *http.Request) {
			cancel()
			<-r.Context().Done() // hold the answer until the client gives up
		},
	})
	client, err := api.NewClient(serverURL, testutil.NewTestAuthProvider("test-token"), false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	scanner := repo.NewScanner(client, true, testTenantID, 0, false, time.Minute, false).
		WithPollInterval(10 * time.Millisecond).
		WithSBOMVEXOptions(&scan.SBOMVEXOptions{BOM: &scan.BOMOptions{
			Types: []string{scan.BOMTypeAll}, Format: scan.BOMFormatCycloneDX17, Output: t.TempDir(), Only: true,
		}})

	var result *model.ScanResult
	_ = testutil.CaptureStderr(t, func() { result, err = scanner.Scan(ctx, createTestRepo(t)) })
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan = %v, %v; want a cancelled scan", result, err)
	}
	_ = testutil.CaptureStderr(t, func() { err = bomScanError("repo", ".", nil)(ctx, err) })
	if code := mainExitCode(err); code != ExitCodeCancelled {
		t.Errorf("exit code = %d (%v), want %d", code, err, ExitCodeCancelled)
	}
}

// TestBOMHelp renders the help of bom, bom repo and bom image: the tenant
// requirement, the default type, the flags with their defaults, examples in
// the $ armis-cli style, and none of the findings flags of scan.
func TestBOMHelp(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	output.SyncColors()
	for _, c := range []*cobra.Command{bomCmd, bomRepoCmd, bomImageCmd} {
		t.Run(c.Name(), func(t *testing.T) {
			var buf bytes.Buffer
			c.SetOut(&buf)
			t.Cleanup(func() { c.SetOut(nil) })
			c.HelpFunc()(c, nil)
			help := buf.String()
			for _, want := range []string{
				"BOM generation must be enabled for your tenant", "refuses the request (bom_generation_disabled) and the command exits 1.",
				"Exit codes: 0 when at least one BOM was written and none failed to download;",
				"2 when no BOM was written or a built BOM could not be downloaded; 1 on errors;",
				"quoted to paste into sh, bash or zsh, or into PowerShell on Windows;\ncmd.exe is not supported.",
				"Without --type, the combined BOM is built: one file with every type.",
				"--type strings", "(default: all)", "sbom, aibom, cbom, all",
				"--format string", `(default "cyclonedx-1.7")`,
				"--output string", "or - to write one BOM to stdout (default: .armis)",
				"--scan-timeout int", "--upload-timeout int", "--no-progress",
				"  $ armis-cli bom ",
			} {
				if !strings.Contains(help, want) {
					t.Errorf("help is missing %q:\n%s", want, help)
				}
			}
			for _, unwanted := range []string{"--fail-on", "--min-severity", "--group-by", "--sbom", "--bom-format", "--page-limit", "--poll-interval"} {
				if strings.Contains(help, unwanted) {
					t.Errorf("help shows %s:\n%s", unwanted, help)
				}
			}
			// Each paragraph of Long ends before a blank line, not run on.
			if !strings.Contains(help, "with every type.\n\nBOM generation must be enabled") ||
				!strings.Contains(help, "the command exits 1.\n\nExit codes:") {
				t.Errorf("help runs paragraphs together:\n%s", help)
			}
			for _, line := range strings.Split(c.Example, "\n") {
				if !strings.HasPrefix(line, "  $ armis-cli bom ") {
					t.Errorf("example %q is not in the $ armis-cli style", line)
				}
			}
		})
	}
	if f := bomRepoCmd.Flags().Lookup("include-files"); f == nil {
		t.Error("bom repo has no --include-files")
	}
	if f := bomRepoCmd.Flags().Lookup("include-tests"); f == nil {
		t.Error("bom repo has no --include-tests")
	}
	for _, name := range []string{"tarball", "pull"} {
		if f := bomImageCmd.Flags().Lookup(name); f == nil {
			t.Errorf("bom image has no --%s", name)
		}
	}
}

// TestTypedBOMDirRefusesLinkedFile: in a directory from --bom-output or
// bom --output, a link committed at a BOM's file name is refused, its target
// is left alone, and the command exits 2.
func TestTypedBOMDirRefusesLinkedFile(t *testing.T) {
	const doc = `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`
	rows := []struct {
		name string
		run  func(t *testing.T, repoDir, dir string) error
	}{
		{"scan repo --bom-output", func(t *testing.T, repoDir, dir string) error {
			bomTypes, bomOutput = []string{scan.BOMTypeSBOM}, dir
			_, _, err := runRepoScanIn(t, repoDir)
			return err
		}},
		{"bom repo --output", func(t *testing.T, repoDir, dir string) error {
			bomOnlyTypes, bomOnlyOutput = []string{scan.BOMTypeSBOM}, dir
			_, _, err := runBOM(t, bomRepoCmd, repoDir)
			return err
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
				BOMContent: map[string]string{"bom_sbom_results": doc},
			}))
			repoDir := createTestRepo(t)
			dir := t.TempDir()
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
				t.Fatalf("write victim: %v", err)
			}
			if err := os.Symlink(victim, filepath.Join(dir, filepath.Base(repoDir)+"-bom-sbom.json")); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}
			err := row.run(t, repoDir, dir)
			if code := mainExitCode(err); code != 2 {
				t.Errorf("exit code = %d (%v), want 2", code, err)
			}
			if got, _ := os.ReadFile(victim); string(got) != "keep" { //nolint:gosec // test path
				t.Errorf("link target = %q, want it untouched", got)
			}
		})
	}
}

// TestFailedToolsWarning: scan repo --bom and bom repo share the warning for
// a BOM written while a BOM tool failed, and both still exit 0.
func TestFailedToolsWarning(t *testing.T) {
	const doc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	const want = "Warning: BOM tools failed on the server: opengrep_bom; CBOM may be incomplete"
	rows := []struct {
		name string
		run  func(t *testing.T, repoDir, dir string) (string, error)
	}{
		{"scan repo --bom", func(t *testing.T, repoDir, dir string) (string, error) {
			bomTypes, bomOutput = []string{scan.BOMTypeCBOM}, dir
			_, stderr, err := runRepoScanIn(t, repoDir)
			return stderr, err
		}},
		{"bom repo", func(t *testing.T, repoDir, dir string) (string, error) {
			bomOnlyTypes, bomOnlyOutput = []string{scan.BOMTypeCBOM}, dir
			_, stderr, err := runBOM(t, bomRepoCmd, repoDir)
			return stderr, err
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
				BOMContent: map[string]string{"cbom_results": doc},
				BOMSummary: map[string]interface{}{
					"types":        map[string]interface{}{"cbom": map[string]interface{}{"status": "generated"}},
					"failed_tools": []string{"opengrep_bom"},
				},
			}))
			stderr, err := row.run(t, createTestRepo(t), t.TempDir())
			if code := mainExitCode(err); code != 0 {
				t.Errorf("exit code = %d (%v), want 0", code, err)
			}
			if strings.Count(stderr, want) != 1 {
				t.Errorf("stderr = %q, want %q once", stderr, want)
			}
		})
	}
}

package repo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// setupClonedRepo builds an upstream repo with one commit and clones it, so the
// clone has a real "origin" remote, origin/HEAD symbolic ref, and remote-tracking
// branches — mirroring a normal CI checkout. Returns the clone path.
func setupClonedRepo(t *testing.T) string {
	t.Helper()
	upstream := setupGitRepo(t)

	cloneParent := t.TempDir()
	clonePath := filepath.Join(cloneParent, "clone")
	if err := runGitCmd(t, cloneParent, "clone", upstream, clonePath); err != nil {
		t.Fatalf("Failed to clone repo: %v", err)
	}
	// Commits aren't made in the clone by these tests, but configure identity
	// anyway so any future commit-based assertions don't fail on missing config.
	if err := runGitCmd(t, clonePath, "config", "user.email", "test@example.com"); err != nil {
		t.Fatalf("Failed to configure git: %v", err)
	}
	if err := runGitCmd(t, clonePath, "config", "user.name", "Test User"); err != nil {
		t.Fatalf("Failed to configure git: %v", err)
	}
	return clonePath
}

func TestDetectGitHints_CleanRootWithRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)

	hints := DetectGitHints(clonePath)

	if hints.RepoName == "" {
		t.Error("expected repo_name to be populated from origin remote")
	}
	if hints.GitSHA == "" {
		t.Error("expected git_sha to be populated for a clean checkout")
	}
	if hints.OriginSHA == "" {
		t.Error("expected origin_sha to resolve via merge-base with the default branch")
	}
	// In a fresh clone HEAD == origin/<default>, so the merge-base is HEAD.
	if hints.GitSHA != hints.OriginSHA {
		t.Errorf("expected git_sha == origin_sha in a fresh clone, got git_sha=%q origin_sha=%q",
			hints.GitSHA, hints.OriginSHA)
	}
}

func TestDetectGitHints_DirtyTreeOmitsGitSHA(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)

	// Make the working tree dirty with an untracked file.
	if err := os.WriteFile(filepath.Join(clonePath, "dirty.txt"), []byte("uncommitted"), 0600); err != nil {
		t.Fatalf("Failed to write untracked file: %v", err)
	}

	hints := DetectGitHints(clonePath)

	if hints.GitSHA != "" {
		t.Errorf("expected git_sha to be omitted for a dirty tree, got %q", hints.GitSHA)
	}
	// repo_name and origin_sha are resolve-only keys and remain valid.
	if hints.RepoName == "" {
		t.Error("expected repo_name to remain populated for a dirty tree")
	}
	if hints.OriginSHA == "" {
		t.Error("expected origin_sha to remain populated for a dirty tree")
	}
}

func TestDetectGitHints_StagedChangeOmitsGitSHA(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)

	staged := filepath.Join(clonePath, "staged.txt")
	if err := os.WriteFile(staged, []byte("staged content"), 0600); err != nil {
		t.Fatalf("Failed to write staged file: %v", err)
	}
	if err := runGitCmd(t, clonePath, "add", "staged.txt"); err != nil {
		t.Fatalf("Failed to stage file: %v", err)
	}

	hints := DetectGitHints(clonePath)
	if hints.GitSHA != "" {
		t.Errorf("expected git_sha to be omitted with a staged change, got %q", hints.GitSHA)
	}
}

func TestDetectGitHints_NoRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// setupGitRepo has a commit but no origin remote.
	repoDir := setupGitRepo(t)

	hints := DetectGitHints(repoDir)

	if hints.GitSHA == "" {
		t.Error("expected git_sha to be populated (clean repo, HEAD exists)")
	}
	if hints.RepoName != "" {
		t.Errorf("expected repo_name to be empty with no origin remote, got %q", hints.RepoName)
	}
	if hints.OriginSHA != "" {
		t.Errorf("expected origin_sha to be empty with no origin remote, got %q", hints.OriginSHA)
	}
}

func TestDetectGitHints_SubdirTargetOmitsAll(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)
	subdir := filepath.Join(clonePath, "sub")
	if err := os.MkdirAll(subdir, 0750); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	hints := DetectGitHints(subdir)

	if hints != (GitHints{}) {
		t.Errorf("expected no hints when target is a subdirectory, got %+v", hints)
	}
}

func TestDetectGitHints_NonGitDirOmitsAll(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	plainDir := t.TempDir()

	hints := DetectGitHints(plainDir)
	if hints != (GitHints{}) {
		t.Errorf("expected no hints for a non-git directory, got %+v", hints)
	}
}

// scanBodyCapturingServer stands up the full ingest flow and records the last
// /scan request body so tests can assert what the scanner forwarded.
func scanBodyCapturingServer(t *testing.T, lastScanBody *[]byte, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			scheme := testhelpers.SchemeFromRequest(r)
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       testScanID,
				ArtifactType: "repo",
				TenantID:     "tenant-456",
				PresignedURL: scheme + "://" + r.Host + "/_s3/upload",
				Fields: map[string]string{
					"key":             "ingest/tenant-456/" + testScanID + "/repo.tar.gz",
					"policy":          "test-policy",
					"x-amz-signature": "test-sig",
				},
				MaxUploadBytes: 2 << 30,
				ExpiresIn:      1800,
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/"):
			testutil.AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan"):
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			mu.Lock()
			*lastScanBody = body
			mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID: testScanID, ScanStatus: "INITIATED", ArtifactType: "repo",
				TenantID: "tenant-456", Filename: "repo", Message: "ok",
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{ScanID: testScanID, ScanStatus: "completed"}},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
			testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{TenantID: "tenant-456"},
			})
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newGitHintsTestClient(t *testing.T, baseURL string) *api.Client {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	c, err := api.NewClient(baseURL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute,
		api.WithHTTPClient(httpClient), api.WithUploadHTTPClient(uploadClient), api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return c
}

// TestScan_ForwardsGitHints verifies the full glue: a clean-root scan with
// WithGitHints enabled forwards detected hints onto the /scan body.
func TestScan_ForwardsGitHints(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)

	var lastScanBody []byte
	var mu sync.Mutex
	server := scanBodyCapturingServer(t, &lastScanBody, &mu)
	apiClient := newGitHintsTestClient(t, server.URL)

	scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).
		WithPollInterval(10 * time.Millisecond).
		WithGitHints()

	if _, err := scanner.Scan(context.Background(), clonePath); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	mu.Lock()
	body := lastScanBody
	mu.Unlock()

	var req model.IngestScanStartRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to unmarshal /scan body: %v", err)
	}
	if req.RepoName == "" {
		t.Error("expected repo_name to be forwarded to /scan")
	}
	if req.GitSHA == "" {
		t.Error("expected git_sha to be forwarded to /scan")
	}
	if req.OriginSHA == "" {
		t.Error("expected origin_sha to be forwarded to /scan")
	}
}

// TestScan_OmitsGitHintsWhenDisabled verifies that without WithGitHints
// (the --changed / --include-files / non-root path), no hints are sent.
func TestScan_OmitsGitHintsWhenDisabled(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	clonePath := setupClonedRepo(t)

	var lastScanBody []byte
	var mu sync.Mutex
	server := scanBodyCapturingServer(t, &lastScanBody, &mu)
	apiClient := newGitHintsTestClient(t, server.URL)

	// No WithGitHints call — detection stays disabled.
	scanner := NewScanner(apiClient, true, "tenant-456", 100, true, 1*time.Minute, false).
		WithPollInterval(10 * time.Millisecond)

	if _, err := scanner.Scan(context.Background(), clonePath); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	mu.Lock()
	body := lastScanBody
	mu.Unlock()

	for _, key := range []string{"repo_name", "git_sha", "origin_sha"} {
		if strings.Contains(string(body), key) {
			t.Errorf("expected %s to be omitted when detection disabled, got body: %s", key, body)
		}
	}
}

func TestNormalizeRepoName(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"scp-like github", "git@github.com:org/repo.git", "org/repo"},
		{"scp-like no .git", "git@github.com:org/repo", "org/repo"},
		{"https with .git", "https://github.com/org/repo.git", "org/repo"},
		{"https no .git", "https://github.com/org/repo", "org/repo"},
		{"https with userinfo", "https://user@github.com/org/repo.git", "org/repo"},
		{"ssh with port", "ssh://git@host:22/org/repo.git", "org/repo"},
		{"git protocol", "git://github.com/org/repo.git", "org/repo"},
		{"trailing slash", "https://github.com/org/repo/", "org/repo"},
		{"deeper path reduces to last two", "https://gitlab.com/group/subgroup/repo.git", "subgroup/repo"},
		{"azure devops https", "https://dev.azure.com/org/project/_git/repo", "_git/repo"},
		{"windows local clone path", `C:\Users\runner\src\owner\upstream`, "owner/upstream"},
		{"windows unc-ish path", `\\server\share\owner\repo`, "owner/repo"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"host only no path", "https://github.com", ""},
		{"single segment path", "https://github.com/repo.git", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRepoName(tt.url)
			if got != tt.want {
				t.Errorf("normalizeRepoName(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

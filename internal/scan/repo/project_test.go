package repo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	statusCalls  int
	resultsCalls int
}

func newIngestRecorderServer(t *testing.T) (*ingestRecorder, string) {
	t.Helper()
	rec := &ingestRecorder{}
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
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
			body, _ := io.ReadAll(r.Body)
			rec.mu.Lock()
			rec.scanBody = body
			rec.mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: testScanID, ScanStatus: "INITIATED"})
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
			testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{})
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
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	client, err := api.NewClient(baseURL, testutil.NewTestAuthProvider("token123"), false, time.Minute,
		api.WithHTTPClient(httpClient), api.WithUploadHTTPClient(uploadClient), api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
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

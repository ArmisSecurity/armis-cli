package sbomcpe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/sbomcpe"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// TestIntegration_SbomCpeScanner_EndToEnd runs the full sbom-cpe scan flow
// against a bespoke httptest.Server that impersonates:
//
//  1. POST /api/v1/ingest/presigned-url  → returns presigned S3 POST
//  2. POST /_s3/upload                    → fake S3, accepts multipart upload
//  3. POST /api/v1/ingest/scan            → confirms upload
//  4. GET  /api/v1/ingest/status/…        → status polling (1 poll → COMPLETED)
//  5. GET  /api/v1/ingest/normalized-results → returns 1 normalized finding
//  6. GET  /api/v1/ingest/results         → returns sbom_cpe_results URL
//  7. GET  /_s3/download                  → fake S3 raw JSON download
//
// The test asserts:
//   - The scanner completes without error.
//   - The presigned-url request carries artifact_type=sbom-cpe (contract w/ backend).
//   - The final ScanResult contains the normalized finding.
//   - The raw sbom-cpe JSON dump is written to the requested output path.
//
// This exercises every layer that will run in production except the actual
// backend scan itself.
func TestIntegration_SbomCpeScanner_EndToEnd(t *testing.T) {
	// --- Fixture: real SBOM with a single component ------------------------
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "torizon-mini.cdx.json")
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"metadata": map[string]any{
			"component": map[string]any{"type": "application", "name": "torizon"},
		},
		"components": []map[string]any{
			{
				"type":    "library",
				"name":    "OpenSSL",
				"version": "1.0.2k",
				"cpe":     "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*",
			},
		},
	}
	sbomBytes, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}
	if err := os.WriteFile(sbomPath, sbomBytes, 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	// The raw JSON dump the backend would upload to S3 for the CLI to fetch.
	// Shape mirrors the CpeSbomScanner.scan() output shipped by PPSC-1136.
	rawCpeJSON := []byte(`{
		"packages": [{"file": "torizon-mini.cdx.json", "name": "OpenSSL", "version": "1.0.2k", "cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*", "low_confidence": false}],
		"vulnerabilities": [{"file": "torizon-mini.cdx.json", "vulnerability_id": "CVE-2018-0732", "severity": "HIGH", "package": "OpenSSL", "version": "1.0.2k", "low_confidence": false}],
		"vulnerability_count": 1,
		"package_count": 1
	}`)

	// --- Mock server -------------------------------------------------------
	const (
		wantTenantID = "test-tenant"
		wantScanID   = "sbom-cpe-scan-001"
	)
	var (
		presignedCallCount   atomic.Int32
		s3UploadCallCount    atomic.Int32
		startScanCallCount   atomic.Int32
		statusCallCount      atomic.Int32
		normalizedCallCount  atomic.Int32
		artifactResultsCount atomic.Int32
		rawDownloadCallCount atomic.Int32
		observedArtifactType atomic.Value // string
	)

	finding := model.NormalizedFinding{
		NormalizedTask: model.NormalizedTask{
			FindingID: "finding-cpe-1",
			ExtraData: model.ExtraData{
				CodeLocation: model.CodeLocation{
					FileName: strPtr("torizon-mini.cdx.json"),
				},
			},
		},
		NormalizedRemediation: model.NormalizedRemediation{
			Description:  "Denial of service in OpenSSL 1.0.2k (CVE-2018-0732).",
			ToolSeverity: "HIGH",
			VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
				CVEs: []string{"CVE-2018-0732"},
				CWEs: []string{"CWE-400"},
			},
		},
	}

	server := testutil.NewMockScanServerWithConfig(t, testutil.MockAPIConfig{
		ScanID:             wantScanID,
		Findings:           []model.NormalizedFinding{finding},
		PollsUntilComplete: 1,
	})

	// We can't easily override the shared mock's presigned-url handler to
	// echo back the artifact_type, so we wrap it with a new server that
	// intercepts the endpoints we care about and delegates the rest.
	baseHandler := server.Handler
	handler := http.NewServeMux()

	// The bespoke handlers below cover the URLs whose behaviour differs
	// from the shared mock: we need to (a) inspect the artifact_type on
	// /presigned-url, (b) implement /ingest/results, (c) implement the raw
	// download endpoint. Everything else falls through to the shared mock.
	handler.HandleFunc("/api/v1/ingest/presigned-url", func(w http.ResponseWriter, r *http.Request) {
		presignedCallCount.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req model.PresignedUploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode presigned-url body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		observedArtifactType.Store(req.ArtifactType)
		scheme := testutil.SchemeFromRequest(r)
		s3URL := scheme + "://" + r.Host + "/_s3/upload"
		testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
			ScanID:       wantScanID,
			ArtifactType: req.ArtifactType,
			TenantID:     wantTenantID,
			PresignedURL: s3URL,
			Fields: map[string]string{
				"key":             "ingest/" + wantTenantID + "/" + wantScanID + "/upload.tar.gz",
				"policy":          "test-policy",
				"x-amz-signature": "test-sig",
			},
			MaxUploadBytes: 2 * 1024 * 1024 * 1024,
			ExpiresIn:      1800,
		})
	})

	handler.HandleFunc("/_s3/upload", func(w http.ResponseWriter, r *http.Request) {
		s3UploadCallCount.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024*1024)
		testutil.AssertValidS3Upload(t, r)
		w.WriteHeader(http.StatusNoContent)
	})

	handler.HandleFunc("/api/v1/ingest/scan", func(w http.ResponseWriter, r *http.Request) {
		startScanCallCount.Add(1)
		testutil.AssertHasAuthorization(t, r)
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
			ScanID:       wantScanID,
			ScanStatus:   "INITIATED",
			ArtifactType: "sbom-cpe",
			TenantID:     wantTenantID,
			Filename:     "upload",
			Message:      "Upload confirmed and scan initiated successfully",
		})
	})

	handler.HandleFunc("/api/v1/ingest/status/", func(w http.ResponseWriter, r *http.Request) {
		statusCallCount.Add(1)
		testutil.AssertHasAuthorization(t, r)
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
			Data: []model.IngestStatusData{{
				ScanID:       wantScanID,
				ScanStatus:   "COMPLETED",
				TenantID:     wantTenantID,
				ArtifactType: "sbom-cpe",
				ScanType:     "custom",
			}},
		})
	})

	handler.HandleFunc("/api/v1/ingest/normalized-results", func(w http.ResponseWriter, r *http.Request) {
		normalizedCallCount.Add(1)
		testutil.AssertHasAuthorization(t, r)
		testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
			Data: model.NormalizedResultsData{
				TenantID: wantTenantID,
				ScanResults: []model.ScanResultData{
					{
						ScanID:   wantScanID,
						Findings: []model.NormalizedFinding{finding},
					},
				},
			},
			Pagination: model.Pagination{NextCursor: nil, Limit: 500},
		})
	})

	handler.HandleFunc("/api/v1/ingest/results", func(w http.ResponseWriter, r *http.Request) {
		artifactResultsCount.Add(1)
		testutil.AssertHasAuthorization(t, r)
		scheme := testutil.SchemeFromRequest(r)
		rawURL := scheme + "://" + r.Host + "/_s3/download"
		testutil.JSONResponse(t, w, http.StatusOK, map[string]any{
			"scan_status": "COMPLETED",
			// Key MUST match sbomcpe.ResultKeySBOMCPE (contract with backend).
			"results": map[string]string{
				sbomcpe.ResultKeySBOMCPE: rawURL,
			},
		})
	})

	handler.HandleFunc("/_s3/download", func(w http.ResponseWriter, r *http.Request) {
		rawDownloadCallCount.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rawCpeJSON)
	})

	// Fallback: hand anything unhandled to the shared mock so we still get
	// coverage of any endpoint we forgot.
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		baseHandler.ServeHTTP(w, r)
	})

	testSrv := testutil.NewTestServer(t, handler.ServeHTTP)
	serverURL := testSrv.URL

	// --- Client + scanner --------------------------------------------------
	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 30*time.Second, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}

	rawOut := filepath.Join(tmpDir, "torizon-mini-sbom-cpe.json")
	scanner := sbomcpe.NewScanner(client, true, wantTenantID, 500, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond).
		WithRawOutput(rawOut)

	// --- Run scan ----------------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, sbomPath)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}

	// --- Assertions --------------------------------------------------------
	if got, _ := observedArtifactType.Load().(string); got != "sbom-cpe" {
		t.Errorf("presigned-url received artifact_type=%q, want sbom-cpe", got)
	}
	if presignedCallCount.Load() != 1 {
		t.Errorf("presigned-url call count = %d, want 1", presignedCallCount.Load())
	}
	if s3UploadCallCount.Load() != 1 {
		t.Errorf("S3 upload call count = %d, want 1", s3UploadCallCount.Load())
	}
	if startScanCallCount.Load() != 1 {
		t.Errorf("/ingest/scan call count = %d, want 1", startScanCallCount.Load())
	}
	if statusCallCount.Load() < 1 {
		t.Errorf("/ingest/status call count = %d, want >=1", statusCallCount.Load())
	}
	if normalizedCallCount.Load() != 1 {
		t.Errorf("/normalized-results call count = %d, want 1", normalizedCallCount.Load())
	}
	if artifactResultsCount.Load() != 1 {
		t.Errorf("/ingest/results call count = %d, want 1", artifactResultsCount.Load())
	}
	if rawDownloadCallCount.Load() != 1 {
		t.Errorf("raw-download call count = %d, want 1", rawDownloadCallCount.Load())
	}

	// Result should carry the finding through
	if result.ScanID != wantScanID {
		t.Errorf("ScanID = %q, want %q", result.ScanID, wantScanID)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != "finding-cpe-1" {
		t.Errorf("finding ID = %q, want finding-cpe-1", result.Findings[0].ID)
	}

	// Raw dump should exist on disk
	data, err := os.ReadFile(rawOut) //nolint:gosec // test-only read of a path we just wrote
	if err != nil {
		t.Fatalf("failed to read raw dump: %v", err)
	}
	if !bytes.Contains(data, []byte("CVE-2018-0732")) {
		t.Errorf("raw dump missing expected CVE, got: %s", string(data))
	}
}

// TestIntegration_SbomCpeScanner_TarballInput asserts the scanner accepts a
// pre-built tar.gz verbatim (no re-packing).
func TestIntegration_SbomCpeScanner_TarballInput(t *testing.T) {
	tmpDir := t.TempDir()

	// Build a real tar.gz containing one SBOM entry.
	sbomInside := `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"OpenSSL","version":"1.0.2k","cpe":"cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"}]}`
	tarballPath := filepath.Join(tmpDir, "inventory.tar.gz")
	writeMinimalTarGz(t, tarballPath, "inventory.cdx.json", []byte(sbomInside))

	handler := minimalMockHandler(t)
	testSrv := testutil.NewTestServer(t, handler)
	serverURL := testSrv.URL

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient(serverURL, authProvider, false, 30*time.Second, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	scanner := sbomcpe.NewScanner(client, true, "test-tenant", 500, 60*time.Second, false).
		WithPollInterval(10 * time.Millisecond).
		WithoutRawDownload()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := scanner.Scan(ctx, tarballPath); err != nil {
		t.Fatalf("Scan with prebuilt tarball failed: %v", err)
	}
}

// TestIntegration_SbomCpeScanner_RejectsMissingSbom checks the fail-fast
// behaviour when the input path does not exist.
func TestIntegration_SbomCpeScanner_RejectsMissingSbom(t *testing.T) {
	authProvider := testutil.NewTestAuthProvider("test-token")
	// Base URL doesn't matter; we never reach the network.
	client, err := api.NewClient("http://localhost:1", authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	scanner := sbomcpe.NewScanner(client, true, "test-tenant", 500, 60*time.Second, false)

	_, err = scanner.Scan(context.Background(), "/no/such/file.json")
	if err == nil {
		t.Fatal("expected error for missing input path")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' in error, got: %v", err)
	}
}

// TestIntegration_SbomCpeScanner_RejectsWrongExtension verifies that a
// single file with an unsupported extension is rejected before upload.
func TestIntegration_SbomCpeScanner_RejectsWrongExtension(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "notes.txt")
	if err := os.WriteFile(badPath, []byte("not an sbom"), 0600); err != nil {
		t.Fatal(err)
	}

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient("http://localhost:1", authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	scanner := sbomcpe.NewScanner(client, true, "test-tenant", 500, 60*time.Second, false)

	_, err = scanner.Scan(context.Background(), badPath)
	if err == nil {
		t.Fatal("expected error for wrong extension")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected extension rejection message, got: %v", err)
	}
}

// TestIntegration_SbomCpeScanner_EmptyDirRejected checks that a directory
// with no SBOM-shaped files fails fast (pre-upload) rather than uploading
// an empty tarball.
func TestIntegration_SbomCpeScanner_EmptyDirRejected(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	authProvider := testutil.NewTestAuthProvider("test-token")
	client, err := api.NewClient("http://localhost:1", authProvider, false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	scanner := sbomcpe.NewScanner(client, true, "test-tenant", 500, 60*time.Second, false)

	_, err = scanner.Scan(context.Background(), tmpDir)
	if err == nil {
		t.Fatal("expected error for directory with no SBOMs")
	}
	if !strings.Contains(err.Error(), "no SBOM files") {
		t.Errorf("expected 'no SBOM files' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

// minimalMockHandler returns a handler that satisfies the sbom-cpe flow with
// a single hard-coded scan_id, no findings, and no raw-download endpoint.
// Used by tests that don't need to inspect the request payload.
func minimalMockHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	const (
		wantTenantID = "test-tenant"
		wantScanID   = "tarball-scan-001"
	)
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			scheme := testutil.SchemeFromRequest(r)
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       wantScanID,
				ArtifactType: "sbom-cpe",
				TenantID:     wantTenantID,
				PresignedURL: scheme + "://" + r.Host + "/_s3/upload",
				Fields: map[string]string{
					"key":             "ingest/" + wantTenantID + "/" + wantScanID + "/upload.tar.gz",
					"policy":          "test-policy",
					"x-amz-signature": "test-sig",
				},
				MaxUploadBytes: 2 * 1024 * 1024 * 1024,
				ExpiresIn:      1800,
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/") && r.Method == http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024*1024)
			testutil.AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan") && r.Method == http.MethodPost:
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{
				ScanID: wantScanID, ScanStatus: "INITIATED",
				ArtifactType: "sbom-cpe", TenantID: wantTenantID,
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{
					ScanID: wantScanID, ScanStatus: "COMPLETED",
					TenantID: wantTenantID, ArtifactType: "sbom-cpe",
				}},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
			testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{
					TenantID: wantTenantID,
					ScanResults: []model.ScanResultData{
						{ScanID: wantScanID, Findings: nil},
					},
				},
				Pagination: model.Pagination{Limit: 500},
			})
		default:
			http.NotFound(w, r)
		}
	}
}

// writeMinimalTarGz builds a real tar.gz on disk with one entry, so we can
// exercise the "prebuilt tarball forwarded verbatim" path without depending
// on the driver's own packing.
func writeMinimalTarGz(t *testing.T, path, name string, content []byte) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // test-only write to a t.TempDir path
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck

	// Reusing the driver's own single-file pack lets us skip re-implementing
	// tar/gzip here — the packer is a small, well-tested unit and this
	// integration test doesn't care about its internals.
	src := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatal(err)
	}
	// The driver's packSingleFile is unexported; call it via an exported
	// helper. We add a tiny exported wrapper below.
	if err := sbomcpe.PackForTest(src, f); err != nil {
		t.Fatalf("PackForTest: %v", err)
	}
}

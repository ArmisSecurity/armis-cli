package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestResultKeyConstants(t *testing.T) {
	if ResultKeySBOM != "sbom_results" {
		t.Errorf("ResultKeySBOM = %q, want %q", ResultKeySBOM, "sbom_results")
	}
	// Locked to the backend Project-Moose contract (PPSC-266): SPDX SBOMs are
	// persisted under a distinct ref so they can coexist with the CycloneDX one.
	if ResultKeySBOMSPDX != "sbom_spdx_results" {
		t.Errorf("ResultKeySBOMSPDX = %q, want %q", ResultKeySBOMSPDX, "sbom_spdx_results")
	}
	if ResultKeyVEX != "vex_results" {
		t.Errorf("ResultKeyVEX = %q, want %q", ResultKeyVEX, "vex_results")
	}
	if SBOMFormatCycloneDX != "cyclonedx" {
		t.Errorf("SBOMFormatCycloneDX = %q, want %q", SBOMFormatCycloneDX, "cyclonedx")
	}
	if SBOMFormatSPDX != "spdx" {
		t.Errorf("SBOMFormatSPDX = %q, want %q", SBOMFormatSPDX, "spdx")
	}
}

func TestSBOMVEXOptions(t *testing.T) {
	opts := SBOMVEXOptions{
		GenerateSBOM: true,
		GenerateVEX:  false,
		SBOMOutput:   "custom/sbom.json",
		VEXOutput:    "",
	}

	if !opts.GenerateSBOM {
		t.Error("Expected GenerateSBOM to be true")
	}
	if opts.GenerateVEX {
		t.Error("Expected GenerateVEX to be false")
	}
	if opts.SBOMOutput != "custom/sbom.json" {
		t.Errorf("Expected SBOMOutput to be 'custom/sbom.json', got %s", opts.SBOMOutput)
	}
}

func TestNewSBOMVEXDownloader(t *testing.T) {
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	client, err := api.NewClient("https://api.example.com", testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	opts := &SBOMVEXOptions{
		GenerateSBOM: true,
		GenerateVEX:  true,
	}

	downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)

	if downloader == nil {
		t.Fatal("Expected downloader to be created")
	}
	if downloader.tenantID != "tenant-123" {
		t.Errorf("Expected tenantID 'tenant-123', got %s", downloader.tenantID)
	}
	if downloader.opts != opts {
		t.Error("Expected opts to be set")
	}
}

func TestSBOMVEXDownloader_Download(t *testing.T) {
	t.Run("downloads SBOM when requested", func(t *testing.T) {
		sbomContent := []byte(`{"bomFormat": "CycloneDX"}`)

		// Create temp directory for output
		tmpDir := t.TempDir()
		sbomPath := filepath.Join(tmpDir, "test-sbom.json")

		// We need the server URL before creating the server, so we use a variable
		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				// First call: FetchArtifactScanResults - return server URL as presigned URL
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"sbom_results": serverURL + "/download/sbom",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				// Second call: DownloadFromPresignedURL
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(sbomContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
			GenerateVEX:  false,
			SBOMOutput:   sbomPath,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		_, err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		// Verify SBOM file was created
		data, err := os.ReadFile(sbomPath) //nolint:gosec // test file path from t.TempDir()
		if err != nil {
			t.Fatalf("Failed to read SBOM file: %v", err)
		}
		if !jsonEqual(t, data, sbomContent) {
			t.Errorf("SBOM content mismatch: got %s, want %s", data, sbomContent)
		}
	})

	t.Run("downloads VEX when requested", func(t *testing.T) {
		vexContent := []byte(`{"@context": "vex"}`)

		tmpDir := t.TempDir()
		vexPath := filepath.Join(tmpDir, "test-vex.json")

		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"vex_results": serverURL + "/download/vex",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(vexContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: false,
			GenerateVEX:  true,
			VEXOutput:    vexPath,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		_, err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		data, err := os.ReadFile(vexPath) //nolint:gosec // test file path from t.TempDir()
		if err != nil {
			t.Fatalf("Failed to read VEX file: %v", err)
		}
		if !jsonEqual(t, data, vexContent) {
			t.Errorf("VEX content mismatch: got %s, want %s", data, vexContent)
		}
	})

	t.Run("uses default .armis directory when no path specified", func(t *testing.T) {
		sbomContent := []byte(`{"bomFormat": "CycloneDX"}`)

		// Create temp directory and change to it
		tmpDir := t.TempDir()
		oldDir, _ := os.Getwd()
		if err := os.Chdir(tmpDir); err != nil {
			t.Fatalf("Failed to change directory: %v", err)
		}
		defer func() { _ = os.Chdir(oldDir) }()

		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"sbom_results": serverURL + "/download/sbom",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(sbomContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
			SBOMOutput:   "", // Empty = use default
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		_, err = downloader.Download(context.Background(), "scan-456", "my-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		// Check default path
		expectedPath := filepath.Join(".armis", "my-artifact-sbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected SBOM file at default path %s", expectedPath)
		}
	})

	t.Run("downloads SPDX SBOM from sbom_spdx_results key", func(t *testing.T) {
		spdxContent := []byte(`{"spdxVersion": "SPDX-2.3"}`)

		tmpDir := t.TempDir()
		spdxPath := filepath.Join(tmpDir, "test-sbom.spdx.json")

		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			if callCount == 1 {
				// The backend advertises the SPDX document under its own ref and
				// leaves sbom_results unset. The downloader must read the SPDX key.
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"sbom_spdx_results": serverURL + "/download/spdx",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(spdxContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
			SBOMFormat:   SBOMFormatSPDX,
			SBOMOutput:   spdxPath,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		if _, err := downloader.Download(context.Background(), "scan-456", "test-artifact"); err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		data, err := os.ReadFile(spdxPath) //nolint:gosec // test file path from t.TempDir()
		if err != nil {
			t.Fatalf("Failed to read SPDX file: %v", err)
		}
		if !jsonEqual(t, data, spdxContent) {
			t.Errorf("SPDX content mismatch: got %s, want %s", data, spdxContent)
		}
	})

	t.Run("SPDX uses .spdx.json default filename", func(t *testing.T) {
		spdxContent := []byte(`{"spdxVersion": "SPDX-2.3"}`)

		tmpDir := t.TempDir()
		oldDir, _ := os.Getwd()
		if err := os.Chdir(tmpDir); err != nil {
			t.Fatalf("Failed to change directory: %v", err)
		}
		defer func() { _ = os.Chdir(oldDir) }()

		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			if callCount == 1 {
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"sbom_spdx_results": serverURL + "/download/spdx",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(spdxContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
			SBOMFormat:   SBOMFormatSPDX,
			SBOMOutput:   "", // Empty = use default
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		if _, err := downloader.Download(context.Background(), "scan-456", "my-artifact"); err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		expectedPath := filepath.Join(".armis", "my-artifact-sbom.spdx.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected SPDX file at default path %s", expectedPath)
		}
	})

	t.Run("returns error when artifact results not available", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		_, err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err == nil {
			t.Error("Expected error when results not available")
		}
	})

	t.Run("silently no-ops when results not available and SBOM/VEX not requested", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", nil)
		if _, err := downloader.Download(context.Background(), "scan-456", "test-artifact"); err != nil {
			t.Errorf("expected no error when SBOM/VEX wasn't requested, got: %v", err)
		}
	})

	t.Run("returns error on API failure", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Server error")
		})

		// DisableRetry: this subtest only checks that a persistent 500 surfaces as
		// an error, not retry behavior — without it, the client's default 3-retry
		// exponential backoff (up to 30s MaxElapsedTime) makes this test slow.
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		_, err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err == nil {
			t.Error("Expected error on API failure")
		}
	})

	t.Run("rejects path traversal in artifact name", func(t *testing.T) {
		// DisableRetry: some inputs below (e.g. "../../../etc/passwd") survive
		// filepath.Base unscathed and fall through to a real FetchArtifactScanResults
		// call against this fake, unreachable host — without it, each one burns
		// the client's default 3-retry exponential backoff on the connection failure.
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
		client, err := api.NewClient("https://api.example.com", testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)

		// Test various path traversal attempts
		testCases := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32",
			"",
			".",
			"/",
		}

		for _, tc := range testCases {
			_, err := downloader.Download(context.Background(), "scan-456", tc)
			if err == nil {
				t.Errorf("Expected error for artifact name %q", tc)
			}
		}
	})

	t.Run("validates path traversal in output path", func(t *testing.T) {
		// Path traversal validation in output path is handled by downloadAndSave
		// which prints a warning but doesn't fail the overall Download operation
		// (by design - SBOM/VEX failures are non-fatal)
		sbomContent := []byte(`{"bomFormat": "CycloneDX"}`)

		var serverURL string
		callCount := 0
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			if callCount == 1 {
				response := api.ArtifactScanResultsResponse{
					ScanStatus: "COMPLETED",
					Results: map[string]string{
						"sbom_results": serverURL + "/download/sbom",
					},
				}
				testutil.JSONResponse(t, w, http.StatusOK, response)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(sbomContent)
			}
		})
		serverURL = server.URL

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{
			GenerateSBOM: true,
			SBOMOutput:   "../../../tmp/evil.json", // Path traversal attempt
		}

		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)
		// Download doesn't return error for SBOM/VEX failures (they're warnings)
		// but the path traversal IS detected and the file is NOT written
		_, _ = downloader.Download(context.Background(), "scan-456", "test-artifact")

		// Verify the malicious file was NOT created
		if _, err := os.Stat("../../../tmp/evil.json"); err == nil {
			t.Error("Path traversal should have been blocked - file should not exist")
		}
	})

	t.Run("prints a warning when some SBOM files were not scanned", func(t *testing.T) {
		skipMsg := "Repository too large for AI-based scanning."

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := api.ArtifactScanResultsResponse{
				ScanStatus:       "COMPLETED",
				Results:          map[string]string{},
				SkipReason:       &skipMsg,
				SBOMScanStatus:   "PARTIAL",
				SBOMScanReasons:  []string{"file_limit_exceeded"},
				SBOMSkippedFiles: []api.SkippedSBOMFile{{Path: "z/bom.json", Reason: "file_limit_exceeded"}},
				SBOMSkippedCount: 1,
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// No SBOM/VEX download requested: the warning must still appear, and a
		// scanner-skip message alongside it is not lost.
		downloader := NewSBOMVEXDownloader(client, "tenant-123", nil)

		stderrOut := testutil.CaptureStderr(t, func() {
			if _, err := downloader.Download(context.Background(), "scan-456", "test-artifact"); err != nil {
				t.Fatalf("Download failed: %v", err)
			}
		})

		if !strings.Contains(stderrOut, "SBOM scan incomplete: 1 SBOM file(s) were not scanned") {
			t.Errorf("expected the SBOM warning, got: %q", stderrOut)
		}
		if !strings.Contains(stderrOut, "z/bom.json") {
			t.Errorf("expected the skipped path, got: %q", stderrOut)
		}
		if !strings.Contains(stderrOut, "Scanner skipped:") {
			t.Errorf("expected the scanner-skip warning too, got: %q", stderrOut)
		}
	})

	t.Run("prints skip reason when scanner was skipped", func(t *testing.T) {
		skipMsg := "Repository too large for AI-based scanning (6203 files exceeds the 5000-file limit)."

		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			response := api.ArtifactScanResultsResponse{
				ScanStatus: "SKIPPED",
				Results:    map[string]string{},
				SkipReason: &skipMsg,
			}
			testutil.JSONResponse(t, w, http.StatusOK, response)
		})

		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0, api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		opts := &SBOMVEXOptions{GenerateSBOM: true, GenerateVEX: true}
		downloader := NewSBOMVEXDownloader(client, "tenant-123", opts)

		stderrOut := testutil.CaptureStderr(t, func() {
			if _, err := downloader.Download(context.Background(), "scan-456", "test-artifact"); err != nil {
				t.Fatalf("Download failed: %v", err)
			}
		})

		if !strings.Contains(stderrOut, skipMsg) {
			t.Errorf("expected stderr to contain skip reason %q, got: %q", skipMsg, stderrOut)
		}
		if !strings.Contains(stderrOut, "Scanner skipped:") {
			t.Errorf("expected stderr to contain 'Scanner skipped:' prefix, got: %q", stderrOut)
		}
	})
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("invalid JSON %q: %v", a, err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("invalid JSON %q: %v", b, err)
	}
	return reflect.DeepEqual(av, bv)
}

func TestIndentJSON(t *testing.T) {
	t.Run("pretty-prints minified JSON preserving key order", func(t *testing.T) {
		got := string(IndentJSON([]byte(`{"b":1,"a":[1,2],"c":{"d":null}}`)))
		want := "{\n  \"b\": 1,\n  \"a\": [\n    1,\n    2\n  ],\n  \"c\": {\n    \"d\": null\n  }\n}\n"
		if got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("returns invalid JSON unchanged", func(t *testing.T) {
		in := []byte(`<xml/>`)
		if got := IndentJSON(in); !bytes.Equal(got, in) {
			t.Errorf("got %q, want %q", got, in)
		}
	})
}

// TestSaveArtifactOutputPaths covers the write shared by --sbom, --vex and
// --bom. A path the CLI picked itself under .armis is strict, since a scanned
// repository can commit .armis or a file in it. A path from an output flag is
// written in place, as before.
func TestSaveArtifactOutputPaths(t *testing.T) {
	const doc = `{"bomFormat":"CycloneDX"}`
	d := &SBOMVEXDownloader{}
	save := func(t *testing.T, path string, mode writeMode) error {
		t.Helper()
		var err error
		_ = testutil.CaptureStderr(t, func() { err = d.saveArtifact(path, "SBOM", IndentJSON([]byte(doc)), mode) })
		return err
	}
	defaultPath := filepath.Join(".armis", "repo-sbom.json")

	t.Run("the default .armis as a symlink is refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		outside := t.TempDir()
		if err := os.Symlink(outside, ".armis"); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		err := save(t, defaultPath, writeDefaultDir)
		if err == nil || !strings.Contains(err.Error(), ".armis is not a plain directory") {
			t.Fatalf("error = %v, want the symlinked .armis refused", err)
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Errorf("wrote through the link: %v", entries)
		}
	})

	t.Run("the default .armis as a file is refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(".armis", []byte("keep"), 0600); err != nil {
			t.Fatalf("write .armis: %v", err)
		}
		err := save(t, defaultPath, writeDefaultDir)
		if err == nil || !strings.Contains(err.Error(), ".armis is not a plain directory") {
			t.Fatalf("error = %v, want the non-directory .armis refused", err)
		}
		if got, _ := os.ReadFile(".armis"); string(got) != "keep" {
			t.Errorf(".armis = %q, want it untouched", got)
		}
	})

	t.Run("the default .armis swapped before it is opened is refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.Mkdir(".armis", 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		beforeDefaultDirOpen = func(dir string) {
			if err := os.Rename(dir, dir+"-checked"); err != nil {
				t.Errorf("move the checked directory: %v", err)
			}
			if err := os.Mkdir(dir, 0750); err != nil {
				t.Errorf("make the swapped directory: %v", err)
			}
		}
		t.Cleanup(func() { beforeDefaultDirOpen = nil })
		err := save(t, defaultPath, writeDefaultDir)
		if err == nil || !strings.Contains(err.Error(), ".armis changed while it was opened") {
			t.Fatalf("error = %v, want the swapped .armis refused", err)
		}
		for _, dir := range []string{".armis", ".armis-checked"} {
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("%s holds %v, want nothing written", dir, entries)
			}
		}
	})

	t.Run("a directory as the target in the default .armis is refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.MkdirAll(defaultPath, 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := save(t, defaultPath, writeDefaultDir)
		if err == nil || !strings.Contains(err.Error(), "repo-sbom.json is not a regular file") {
			t.Fatalf("error = %v, want the non-regular target refused", err)
		}
	})

	t.Run("a symlinked target in the default .armis is refused and its target untouched", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.Mkdir(".armis", 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		if err := os.Symlink(victim, defaultPath); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		err := save(t, defaultPath, writeDefaultDir)
		if err == nil || !strings.Contains(err.Error(), "repo-sbom.json is not a regular file") {
			t.Fatalf("error = %v, want the symlinked target refused", err)
		}
		if got, _ := os.ReadFile(victim); string(got) != "keep" { //nolint:gosec // test path from t.TempDir()
			t.Errorf("link target = %q, want it untouched", got)
		}
	})

	t.Run("a 240-byte file name in the default .armis works", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the full path passes MAX_PATH on Windows")
		}
		t.Chdir(t.TempDir())
		path := filepath.Join(".armis", strings.Repeat("n", 235)+".json")
		if err := save(t, path, writeDefaultDir); err != nil {
			t.Fatalf("saveArtifact with a 240-byte name failed: %v", err)
		}
		assertBOMFile(t, path, doc)
	})

	t.Run("an existing 0644 file in the default .armis is replaced with mode 0600", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file modes are not POSIX on Windows")
		}
		t.Chdir(t.TempDir())
		if err := os.Mkdir(".armis", 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(defaultPath, []byte("old"), 0600); err != nil {
			t.Fatalf("write old file: %v", err)
		}
		if err := os.Chmod(defaultPath, 0644); err != nil { //nolint:gosec // test sets a loose mode on purpose
			t.Fatalf("chmod: %v", err)
		}
		if err := save(t, defaultPath, writeDefaultDir); err != nil {
			t.Fatalf("saveArtifact failed: %v", err)
		}
		assertBOMFile(t, defaultPath, doc)
		if entries, _ := os.ReadDir(".armis"); len(entries) != 1 {
			t.Errorf(".armis holds %v, want only the output file", entries)
		}
	})

	// On macOS t.TempDir is under /var, a link to /private/var, as /tmp is.
	t.Run("t.TempDir paths are used, from a flag and as the default", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "repo-sbom.json")
		if err := save(t, path, writeInPlace); err != nil {
			t.Fatalf("saveArtifact with a flag path failed: %v", err)
		}
		assertBOMFile(t, path, doc)

		t.Chdir(t.TempDir())
		if err := save(t, defaultPath, writeDefaultDir); err != nil {
			t.Fatalf("saveArtifact with the default .armis failed: %v", err)
		}
		assertBOMFile(t, defaultPath, doc)
	})

	t.Run("/dev/stdout from a flag is written as before", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no /dev/stdout on Windows")
		}
		if err := save(t, "/dev/stdout", writeInPlace); err != nil {
			t.Fatalf("saveArtifact to /dev/stdout failed: %v", err)
		}
	})

	t.Run("a FIFO from a flag is written in place and stays a FIFO", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "sbom.fifo")
		r := openFIFO(t, fifo)
		if err := save(t, fifo, writeInPlace); err != nil {
			t.Fatalf("saveArtifact to a FIFO failed: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read FIFO: %v", err)
		}
		if !bytes.Equal(got, IndentJSON([]byte(doc))) {
			t.Errorf("FIFO got %q, want the document", got)
		}
		if info, err := os.Lstat(fifo); err != nil || info.Mode()&fs.ModeNamedPipe == 0 {
			t.Errorf("FIFO is now %v (%v), want it left a FIFO", info, err)
		}
	})

	t.Run("a symlinked directory from a flag is used as given", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "out")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		for _, mode := range []writeMode{writeInPlace, writeInTypedDir} {
			if err := save(t, filepath.Join(link, "repo-sbom.json"), mode); err != nil {
				t.Fatalf("saveArtifact (mode %d) failed: %v", mode, err)
			}
			assertBOMFile(t, filepath.Join(target, "repo-sbom.json"), doc)
		}
	})

	t.Run("a symlinked target in a typed directory is refused and its target untouched", func(t *testing.T) {
		dir := t.TempDir()
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		path := filepath.Join(dir, "repo-bom-sbom.json")
		if err := os.Symlink(victim, path); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		err := save(t, path, writeInTypedDir)
		if err == nil || !strings.Contains(err.Error(), "repo-bom-sbom.json is not a regular file") {
			t.Fatalf("error = %v, want the symlinked target refused", err)
		}
		if got, _ := os.ReadFile(victim); string(got) != "keep" { //nolint:gosec // test path from t.TempDir()
			t.Errorf("link target = %q, want it untouched", got)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("link is now %v (%v), want it left a link", info, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%s holds %v, want only the link", dir, entries)
		}
	})

	t.Run("a directory as the target in a typed directory is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "repo-bom-sbom.json")
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := save(t, path, writeInTypedDir)
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("error = %v, want the non-regular target refused", err)
		}
	})

	t.Run("a typed directory that does not exist is created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "repo-bom-sbom.json")
		if err := save(t, path, writeInTypedDir); err != nil {
			t.Fatalf("saveArtifact failed: %v", err)
		}
		assertBOMFile(t, path, doc)
	})

	t.Run("an existing 0644 file in a typed directory is replaced with mode 0600", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file modes are not POSIX on Windows")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "repo-bom-sbom.json")
		if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
			t.Fatalf("write old file: %v", err)
		}
		if err := os.Chmod(path, 0644); err != nil { //nolint:gosec // test sets a loose mode on purpose
			t.Fatalf("chmod: %v", err)
		}
		if err := save(t, path, writeInTypedDir); err != nil {
			t.Fatalf("saveArtifact failed: %v", err)
		}
		assertBOMFile(t, path, doc)
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%s holds %v, want only the output file", dir, entries)
		}
	})

	t.Run("a symlinked target from a flag is written through, as before", func(t *testing.T) {
		victim := filepath.Join(t.TempDir(), "sbom.json")
		link := filepath.Join(t.TempDir(), "link.json")
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		if err := save(t, link, writeInPlace); err != nil {
			t.Fatalf("saveArtifact failed: %v", err)
		}
		assertBOMFile(t, victim, doc)
		if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("link is now %v (%v), want it left a link", info, err)
		}
	})
}

// bomServer is a fake results endpoint plus S3: GET /api/v1/ingest/results
// links every key in docs to /download/<key>?gen=<n> on the same server, which
// serves the document; n counts the results calls.
type bomServer struct {
	docs        map[string]string // results key -> stored document
	summary     *api.BOMSummary
	skipReason  *string
	resultsCode int // non-zero: the results call answers this status
	// refetchCode, when set, is the status of every results call after the
	// first, with refetchBody as the body.
	refetchCode int
	refetchBody string
	// downloadCode, when set, gives the status of the n-th download (from 1)
	// of key; 0 serves the document.
	downloadCode func(key string, n int) int
	badURLKey    string // results key linked to a host that is not S3
	oversizeKey  string // results key whose download is one byte over the cap

	mu            sync.Mutex
	resultsCalls  int
	downloadCalls map[string]int
	downloadGens  map[string][]string // results key -> gen of each download
}

// calls returns the number of results calls and of downloads of key.
func (b *bomServer) calls(key string) (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.resultsCalls, b.downloadCalls[key]
}

func (b *bomServer) start(t *testing.T) *api.Client {
	t.Helper()
	b.downloadCalls = map[string]int{}
	b.downloadGens = map[string][]string{}
	var serverURL string
	server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if strings.Contains(r.URL.Path, "/api/v1/ingest/results") {
			b.resultsCalls++
			if b.resultsCode != 0 {
				w.WriteHeader(b.resultsCode)
				return
			}
			if b.refetchCode != 0 && b.resultsCalls > 1 {
				w.WriteHeader(b.refetchCode)
				_, _ = io.WriteString(w, b.refetchBody)
				return
			}
			results := map[string]string{}
			for key := range b.docs {
				results[key] = serverURL + "/download/" + key + "?gen=" + strconv.Itoa(b.resultsCalls)
			}
			if b.oversizeKey != "" {
				results[b.oversizeKey] = serverURL + "/download/" + b.oversizeKey
			}
			if b.badURLKey != "" {
				results[b.badURLKey] = "https://attacker.example.com/" + b.badURLKey
			}
			testutil.JSONResponse(t, w, http.StatusOK, api.ArtifactScanResultsResponse{
				ScanStatus: "COMPLETED", Results: results, BOMSummary: b.summary, SkipReason: b.skipReason,
			})
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/download/")
		b.downloadCalls[key]++
		b.downloadGens[key] = append(b.downloadGens[key], r.URL.Query().Get("gen"))
		if b.downloadCode != nil {
			if code := b.downloadCode(key, b.downloadCalls[key]); code != 0 {
				w.WriteHeader(code)
				return
			}
		}
		if key == b.oversizeKey {
			// Declare a body one byte over the cap; the client rejects it
			// from Content-Length, so no 100 MB body is sent.
			w.Header().Set("Content-Length", strconv.FormatInt(api.MaxDownloadSize+1, 10))
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, b.docs[key])
	})
	serverURL = server.URL

	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	client, err := api.NewClient(server.URL, testutil.NewTestAuthProvider("token123"), false, 0,
		api.WithHTTPClient(httpClient), api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return client
}

// downloadBOMs runs Download with BOM options and returns the skip reason,
// stderr and the error.
func downloadBOMs(t *testing.T, client *api.Client, opts *SBOMVEXOptions) (skip, stderr string, err error) {
	t.Helper()
	stderr = testutil.CaptureStderr(t, func() {
		skip, err = NewSBOMVEXDownloader(client, "tenant-123", opts).Download(context.Background(), "scan-456", "test-artifact")
	})
	return skip, stderr, err
}

// assertBOMFile checks that path holds doc pretty-printed by IndentJSON, as
// the --sbom and VEX files are, with mode 0600.
func assertBOMFile(t *testing.T, path, doc string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test file path from t.TempDir()
	if err != nil {
		t.Fatalf("expected BOM file %s: %v", path, err)
	}
	if !jsonEqual(t, data, []byte(doc)) {
		t.Errorf("%s content = %s, want %s", path, data, doc)
	}
	if !bytes.Equal(data, IndentJSON([]byte(doc))) {
		t.Errorf("%s is not the stored document pretty-printed:\n%s", path, data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode = %o, want 600", path, perm)
		}
	}
}

// assertBOMFailed checks that err is a *BOMDownloadError for want. wantCause
// is a substring of its Err, set only when the results call failed; empty
// means Err must be nil.
func assertBOMFailed(t *testing.T, err error, want []string, wantCause string) {
	t.Helper()
	var bomErr *BOMDownloadError
	if !errors.As(err, &bomErr) {
		t.Fatalf("error = %v, want a *BOMDownloadError", err)
	}
	if !reflect.DeepEqual(bomErr.Types, want) {
		t.Errorf("failed types = %v, want %v", bomErr.Types, want)
	}
	switch {
	case wantCause == "" && bomErr.Err != nil:
		t.Errorf("Err = %v, want nil for a per-type failure", bomErr.Err)
	case wantCause != "" && (bomErr.Err == nil || !strings.Contains(bomErr.Err.Error(), wantCause)):
		t.Errorf("Err = %v, want it to contain %q", bomErr.Err, wantCause)
	}
}

func TestSBOMVEXDownloader_DownloadBOMs(t *testing.T) {
	const aibomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"machine-learning-model","name":"m"}]}`
	const cbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"cryptographic-asset","name":"AES"}]}`

	t.Run("downloads one file per type, pretty-printed", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"aibom_results": aibomDoc, "cbom_results": cbomDoc}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir, Target: ".",
		}})
		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), aibomDoc)
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-cbom.json"), cbomDoc)
		if !strings.Contains(stderr, "AI-BOM saved to:") || !strings.Contains(stderr, "CBOM saved to:") {
			t.Errorf("stderr = %q, want both saved lines", stderr)
		}
	})

	t.Run("a link committed at the file name in a typed directory is refused", func(t *testing.T) {
		const sbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`
		dir := t.TempDir()
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		if err := os.Symlink(victim, filepath.Join(dir, "test-artifact-bom-sbom.json")); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		srv := &bomServer{docs: map[string]string{"bom_sbom_results": sbomDoc, "cbom_results": cbomDoc}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"sbom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		var bomErr *BOMDownloadError
		if !errors.As(err, &bomErr) || !reflect.DeepEqual(bomErr.Types, []string{"sbom"}) {
			t.Fatalf("error = %v, want the SBOM refused", err)
		}
		if !strings.Contains(stderr, "test-artifact-bom-sbom.json is not a regular file") {
			t.Errorf("stderr = %q, want the refusal", stderr)
		}
		if got, _ := os.ReadFile(victim); string(got) != "keep" { //nolint:gosec // test path from t.TempDir()
			t.Errorf("link target = %q, want it untouched", got)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-cbom.json"), cbomDoc)
	})

	t.Run("a symlinked typed directory is written through", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "boms")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: link,
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(target, "test-artifact-bom-cbom.json"), cbomDoc)
	})

	t.Run("cyclonedx-1.6 reads the _cdx16_ key", func(t *testing.T) {
		const cdx16 = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"m"}]}`
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"aibom_results": aibomDoc, "aibom_cdx16_results": cdx16}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.6", Output: dir,
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), cdx16)
	})

	t.Run("spdx alias gives the SPDX 2.3 SBOM", func(t *testing.T) {
		const spdx = `{"spdxVersion":"SPDX-2.3","packages":[{"name":"p"}]}`
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"bom_sbom_spdx23_results": spdx}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"sbom"}, Format: "spdx", Output: dir,
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-sbom.spdx.json"), spdx)
	})

	t.Run("defaults to the .armis directory", func(t *testing.T) {
		t.Chdir(t.TempDir())
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7",
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(".armis", "test-artifact-bom-cbom.json"), cbomDoc)
	})

	t.Run("--sbom next to --bom sbom writes both files", func(t *testing.T) {
		const sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}`
		const bomSBOMDoc = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":"a"}]}`
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"sbom_results": sbomDoc, "bom_sbom_results": bomSBOMDoc}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{
			GenerateSBOM: true, SBOMOutput: filepath.Join(dir, "sbom.json"),
			BOM: &BOMOptions{Types: []string{"sbom"}, Format: "cyclonedx-1.7", Output: dir},
		}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "sbom.json"), sbomDoc)
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-sbom.json"), bomSBOMDoc)
	})

	t.Run("missing key warns and does not fail", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		if err != nil {
			t.Fatalf("a key not offered must not fail, got: %v", err)
		}
		if !strings.Contains(stderr, "AI-BOM was requested but not available in results") {
			t.Errorf("stderr = %q, want the not-available warning", stderr)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("expected no file, got %v", entries)
		}
	})

	t.Run("too_large warns and does not fail", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{
			docs: map[string]string{"aibom_results": aibomDoc},
			summary: &api.BOMSummary{Types: map[string]api.BOMTypeStatus{
				"aibom": {Status: "generated", Formats: []string{"cyclonedx-1.7"}},
				"cbom":  {Status: "too_large"},
			}},
		}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		if err != nil {
			t.Fatalf("too_large must not fail, got: %v", err)
		}
		if !strings.Contains(stderr, "CBOM was too large to store") {
			t.Errorf("stderr = %q, want the too_large warning", stderr)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), aibomDoc)
	})

	t.Run("a type not offered names a file from an earlier run", func(t *testing.T) {
		dir := t.TempDir()
		old := filepath.Join(dir, "test-artifact-bom-cbom.json")
		if err := os.WriteFile(old, []byte(cbomDoc), 0600); err != nil {
			t.Fatalf("write earlier file: %v", err)
		}
		srv := &bomServer{
			docs: map[string]string{"aibom_results": aibomDoc},
			summary: &api.BOMSummary{Types: map[string]api.BOMTypeStatus{
				"aibom": {Status: "generated", Formats: []string{"cyclonedx-1.7"}},
				"cbom":  {Status: "too_large"},
			}},
		}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		if err != nil {
			t.Fatalf("too_large must not fail, got: %v", err)
		}
		if !strings.Contains(stderr, old+" is from an earlier run, not this scan") {
			t.Errorf("stderr = %q, want the earlier-run warning", stderr)
		}
		if strings.Contains(stderr, "test-artifact-bom-aibom.json is from an earlier run") {
			t.Errorf("stderr = %q names the AI-BOM written this run", stderr)
		}
		if got, _ := os.ReadFile(old); string(got) != cbomDoc { //nolint:gosec // test path from t.TempDir()
			t.Errorf("earlier file = %q, want it left in place", got)
		}
	})

	t.Run("a type not offered without an earlier file names none", func(t *testing.T) {
		srv := &bomServer{docs: map[string]string{}}
		client := srv.start(t)
		_, stderr, _ := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		if strings.Contains(stderr, "earlier run") {
			t.Errorf("stderr = %q, want no earlier-run warning", stderr)
		}
	})

	t.Run("each bom_summary status has its own warning", func(t *testing.T) {
		rows := []struct {
			name    string
			summary *api.BOMSummary
			want    string
		}{
			{"not_supported", &api.BOMSummary{Types: map[string]api.BOMTypeStatus{"aibom": {Status: "not_supported"}}},
				"Warning: AI-BOM is not supported for this scan\n"},
			{"failed with tools", &api.BOMSummary{
				Types:       map[string]api.BOMTypeStatus{"aibom": {Status: "failed"}},
				FailedTools: []string{"tool_a", "tool\x1b[31m_b"},
			}, "Warning: AI-BOM failed on the server (tools that failed in this scan: tool_a, tool[31m_b)\n"},
			{"failed, with a tool of another type", &api.BOMSummary{
				Types:       map[string]api.BOMTypeStatus{"aibom": {Status: "failed"}, "cbom": {Status: "generated"}},
				FailedTools: []string{"crypto_tool"},
			}, "Warning: AI-BOM failed on the server (tools that failed in this scan: crypto_tool)\n"},
			{"failed without tools", &api.BOMSummary{Types: map[string]api.BOMTypeStatus{"aibom": {Status: "failed"}}},
				"Warning: AI-BOM failed on the server\n"},
			{"a type the summary does not list", &api.BOMSummary{Types: map[string]api.BOMTypeStatus{"cbom": {Status: "generated"}}},
				"Warning: AI-BOM was requested but not available in results\n"},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				srv := &bomServer{docs: map[string]string{}, summary: row.summary}
				client := srv.start(t)
				_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
					Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
				}})
				if err != nil {
					t.Fatalf("a %s type must not fail, got: %v", row.name, err)
				}
				if stderr != row.want {
					t.Errorf("stderr = %q, want %q", stderr, row.want)
				}
			})
		}
	})

	t.Run("a format missing from formats warns and does not fail", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{
			docs: map[string]string{"aibom_results": aibomDoc},
			summary: &api.BOMSummary{Types: map[string]api.BOMTypeStatus{
				"aibom": {Status: "generated", Formats: []string{"cyclonedx-1.7"}},
			}},
		}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.6", Output: dir,
		}})
		if err != nil {
			t.Fatalf("a missing format must not fail, got: %v", err)
		}
		if !strings.Contains(stderr, "AI-BOM is not available in cyclonedx-1.6") {
			t.Errorf("stderr = %q, want the format warning", stderr)
		}
	})

	t.Run("an empty BOM is written and named on stderr", func(t *testing.T) {
		const empty = `{"bomFormat":"CycloneDX"}`
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"aibom_results": empty}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: dir, Target: "./my-repo",
		}})
		if err != nil {
			t.Fatalf("an empty BOM must not fail, got: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), empty)
		if !strings.Contains(stderr, "No AI components found in ./my-repo") {
			t.Errorf("stderr = %q, want the empty AI-BOM line", stderr)
		}
	})

	t.Run("an empty SPDX SBOM is named from bom_summary", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{
			docs: map[string]string{"bom_sbom_spdx23_results": spdxRootOnly},
			summary: &api.BOMSummary{Types: map[string]api.BOMTypeStatus{
				"sbom": {Status: "empty", Formats: []string{"cyclonedx-1.7", "spdx-2.3"}},
			}},
		}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"sbom"}, Format: "spdx-2.3", Output: dir, Target: "./my-repo",
		}})
		if err != nil {
			t.Fatalf("an empty BOM must not fail, got: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-sbom.spdx.json"), spdxRootOnly)
		if !strings.Contains(stderr, "No packages found in ./my-repo") {
			t.Errorf("stderr = %q, want the empty SBOM line", stderr)
		}
	})

	t.Run("a download over the size cap fails that type", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc}, oversizeKey: "aibom_results"}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		assertBOMFailed(t, err, []string{"aibom"}, "")
		if _, statErr := os.Stat(filepath.Join(dir, "test-artifact-bom-aibom.json")); statErr == nil {
			t.Error("no file may be written for a download over the cap")
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-cbom.json"), cbomDoc)
	})

	t.Run("invalid JSON fails that type", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"aibom_results": `{"components":[`, "cbom_results": cbomDoc}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		assertBOMFailed(t, err, []string{"aibom"}, "")
		if !strings.Contains(stderr, "AI-BOM is not valid JSON") {
			t.Errorf("stderr = %q, want the invalid JSON warning", stderr)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "test-artifact-bom-aibom.json")); statErr == nil {
			t.Error("no file may be written for invalid JSON")
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-cbom.json"), cbomDoc)
	})

	t.Run("invalid JSON fails that type in stdout mode", func(t *testing.T) {
		var buf bytes.Buffer
		srv := &bomServer{docs: map[string]string{"cbom_results": `<bom/>`}}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: "-", Stdout: &buf,
		}})
		assertBOMFailed(t, err, []string{"cbom"}, "")
		if buf.Len() != 0 {
			t.Errorf("stdout = %q, want nothing", buf.String())
		}
	})

	t.Run("a deeply nested BOM is written unchanged", func(t *testing.T) {
		deep := `{"components":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}`
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"cbom_results": deep}}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "test-artifact-bom-cbom.json")) //nolint:gosec // test path from t.TempDir()
		if err != nil {
			t.Fatalf("read BOM file: %v", err)
		}
		if string(data) != deep {
			t.Errorf("file is %d bytes, want the %d stored bytes unchanged", len(data), len(deep))
		}
	})

	t.Run("a 403 refetches the results and retries once", func(t *testing.T) {
		dir := t.TempDir()
		srv := &bomServer{
			docs: map[string]string{"aibom_results": aibomDoc},
			downloadCode: func(_ string, n int) int {
				if n == 1 {
					return http.StatusForbidden
				}
				return 0
			},
		}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: dir,
		}}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), aibomDoc)
		if results, downloads := srv.calls("aibom_results"); results != 2 || downloads != 2 {
			t.Errorf("results calls = %d, downloads = %d; want 2 and 2", results, downloads)
		}
	})

	t.Run("after a 403 refetch the fresh links serve the other types and --sbom", func(t *testing.T) {
		const sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}`
		dir := t.TempDir()
		srv := &bomServer{
			docs: map[string]string{"aibom_results": aibomDoc, "cbom_results": cbomDoc, "sbom_results": sbomDoc},
			downloadCode: func(key string, n int) int {
				if key == "aibom_results" && n == 1 {
					return http.StatusForbidden
				}
				return 0
			},
		}
		client := srv.start(t)
		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{
			GenerateSBOM: true, SBOMOutput: filepath.Join(dir, "sbom.json"),
			BOM: &BOMOptions{Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir},
		}); err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-cbom.json"), cbomDoc)
		srv.mu.Lock()
		defer srv.mu.Unlock()
		want := map[string][]string{"aibom_results": {"1", "2"}, "cbom_results": {"2"}, "sbom_results": {"2"}}
		if !reflect.DeepEqual(srv.downloadGens, want) {
			t.Errorf("link generations = %v, want %v", srv.downloadGens, want)
		}
		if srv.resultsCalls != 2 {
			t.Errorf("results calls = %d, want 2", srv.resultsCalls)
		}
	})

	t.Run("each type refetches at most once", func(t *testing.T) {
		srv := &bomServer{
			docs:         map[string]string{"aibom_results": aibomDoc, "cbom_results": cbomDoc},
			downloadCode: func(string, int) int { return http.StatusForbidden },
		}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"aibom", "cbom"}, "")
		if results, downloads := srv.calls("cbom_results"); results != 3 || downloads != 2 {
			t.Errorf("results calls = %d, cbom downloads = %d; want 3 and 2", results, downloads)
		}
	})

	t.Run("a second 403 fails that type", func(t *testing.T) {
		srv := &bomServer{
			docs:         map[string]string{"aibom_results": aibomDoc},
			downloadCode: func(string, int) int { return http.StatusForbidden },
		}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"aibom"}, "")
		if results, downloads := srv.calls("aibom_results"); results != 2 || downloads != 2 {
			t.Errorf("results calls = %d, downloads = %d; want 2 and 2", results, downloads)
		}
	})

	t.Run("a failed refetch warns without control characters", func(t *testing.T) {
		srv := &bomServer{
			docs:         map[string]string{"aibom_results": aibomDoc},
			downloadCode: func(string, int) int { return http.StatusForbidden },
			refetchCode:  http.StatusBadRequest,
			refetchBody:  "bad\x1b[2J\x1b]0;title\x07\u009b31m\r\nrequest",
		}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"aibom"}, "")
		if !strings.Contains(stderr, "refetching expired link: fetch results failed with status 400: bad[2J]0;title31m request") {
			t.Errorf("stderr = %q, want the server text without control characters", stderr)
		}
		if strings.ContainsAny(stderr, "\x1b\x07\u009b\r") {
			t.Errorf("stderr = %q holds a control character", stderr)
		}
	})

	t.Run("another error status is not retried", func(t *testing.T) {
		srv := &bomServer{
			docs:         map[string]string{"aibom_results": aibomDoc, "cbom_results": cbomDoc},
			downloadCode: func(key string, _ int) int { return map[string]int{"cbom_results": http.StatusNotFound}[key] },
		}
		client := srv.start(t)
		dir := t.TempDir()
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		assertBOMFailed(t, err, []string{"cbom"}, "")
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), aibomDoc)
		if results, downloads := srv.calls("cbom_results"); results != 1 || downloads != 1 {
			t.Errorf("results calls = %d, cbom downloads = %d; want 1 and 1", results, downloads)
		}
	})

	t.Run("a link to a host that is not S3 fails that type", func(t *testing.T) {
		srv := &bomServer{docs: map[string]string{}, badURLKey: "aibom_results"}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"aibom"}, "")
		if !strings.Contains(stderr, "invalid AI-BOM URL") {
			t.Errorf("stderr = %q, want the URL check warning", stderr)
		}
	})

	t.Run("an invalid artifact name fails every type", func(t *testing.T) {
		srv := &bomServer{docs: map[string]string{"aibom_results": aibomDoc}}
		client := srv.start(t)
		var err error
		_ = testutil.CaptureStderr(t, func() {
			_, err = NewSBOMVEXDownloader(client, "tenant-123", &SBOMVEXOptions{BOM: &BOMOptions{
				Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
			}}).Download(context.Background(), "scan-456", "..")
		})
		assertBOMFailed(t, err, []string{"aibom"}, "invalid artifact name")
		if results, _ := srv.calls("aibom_results"); results != 0 {
			t.Errorf("results calls = %d, want none", results)
		}
	})

	t.Run("results 404 fails every type", func(t *testing.T) {
		srv := &bomServer{resultsCode: http.StatusNotFound}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom", "cbom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"aibom", "cbom"}, "artifact results not available")
	})

	t.Run("a failed results call fails every type", func(t *testing.T) {
		srv := &bomServer{resultsCode: http.StatusBadRequest}
		client := srv.start(t)
		_, _, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: t.TempDir(),
		}})
		assertBOMFailed(t, err, []string{"cbom"}, "failed to fetch artifact results")
	})

	t.Run("a scanner skip does not hide BOMs", func(t *testing.T) {
		skipMsg := "Repository too large for AI-based scanning."
		dir := t.TempDir()
		srv := &bomServer{docs: map[string]string{"aibom_results": aibomDoc}, skipReason: &skipMsg}
		client := srv.start(t)
		skip, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"aibom"}, Format: "cyclonedx-1.7", Output: dir,
		}})
		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		if skip != skipMsg || !strings.Contains(stderr, "Scanner skipped:") {
			t.Errorf("skip = %q, stderr = %q; want the skip reason", skip, stderr)
		}
		assertBOMFile(t, filepath.Join(dir, "test-artifact-bom-aibom.json"), aibomDoc)
	})

	t.Run("a symlinked default .armis is refused, the same path typed is used", func(t *testing.T) {
		const sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}`
		t.Chdir(t.TempDir())
		outside := t.TempDir()
		if err := os.Symlink(outside, ".armis"); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc, "sbom_results": sbomDoc}}
		client := srv.start(t)

		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{
			GenerateSBOM: true,
			BOM:          &BOMOptions{Types: []string{"cbom"}, Format: "cyclonedx-1.7"},
		})
		assertBOMFailed(t, err, []string{"cbom"}, "")
		if !strings.Contains(stderr, "invalid SBOM output path: .armis is not a plain directory") {
			t.Errorf("stderr = %q, want the --sbom default refused", stderr)
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Fatalf("wrote through the default .armis link: %v", entries)
		}

		if _, _, err := downloadBOMs(t, client, &SBOMVEXOptions{
			GenerateSBOM: true, SBOMOutput: filepath.Join(".armis", "sbom.json"),
			BOM: &BOMOptions{Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: ".armis"},
		}); err != nil {
			t.Fatalf("typed output paths must be used as given, got: %v", err)
		}
		assertBOMFile(t, filepath.Join(outside, "test-artifact-bom-cbom.json"), cbomDoc)
		assertBOMFile(t, filepath.Join(outside, "sbom.json"), sbomDoc)
	})

	t.Run("stdout mode writes the fetched bytes once", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var buf bytes.Buffer
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc}}
		client := srv.start(t)
		_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
			Types: []string{"cbom"}, Format: "cyclonedx-1.7", Output: "-", Stdout: &buf,
		}})
		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}
		if buf.String() != cbomDoc {
			t.Errorf("stdout = %q, want the stored bytes %q", buf.String(), cbomDoc)
		}
		if !strings.Contains(stderr, "CBOM written to stdout") {
			t.Errorf("stderr = %q, want the stdout line", stderr)
		}
		if _, statErr := os.Stat(".armis"); statErr == nil {
			t.Error("stdout mode must not create .armis")
		}
	})
}

func TestSBOMVEXOptionsBOMOnly(t *testing.T) {
	rows := []struct {
		name         string
		opts         *SBOMVEXOptions
		wantOnly     bool
		wantScanType string
		wantMessage  string
	}{
		{"no options", nil, false, "", "Scanning for security issues..."},
		{"--sbom only", &SBOMVEXOptions{GenerateSBOM: true}, false, "", "Scanning for security issues..."},
		{"scan --bom", &SBOMVEXOptions{BOM: &BOMOptions{Types: []string{"cbom"}}}, false, "", "Scanning for security issues..."},
		{"bom command", &SBOMVEXOptions{BOM: &BOMOptions{Types: []string{"all"}, Only: true}}, true, "bom", "Building BOMs..."},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := row.opts.BOMOnly(); got != row.wantOnly {
				t.Errorf("BOMOnly() = %v, want %v", got, row.wantOnly)
			}
			if got := row.opts.ScanType(); got != row.wantScanType {
				t.Errorf("ScanType() = %q, want %q", got, row.wantScanType)
			}
			if got := row.opts.WaitMessage(); got != row.wantMessage {
				t.Errorf("WaitMessage() = %q, want %q", got, row.wantMessage)
			}
		})
	}
}

func TestBOMOnlyResult(t *testing.T) {
	const cbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	skip := "a scanner was skipped"
	controlSkip := "a scanner\x1b[2J was\u009b skipped\x07"
	rows := []struct {
		name         string
		srv          *bomServer
		types        []string
		wantFailures []string
		wantSkip     string
		wantFile     bool
	}{
		{name: "built and written", srv: &bomServer{docs: map[string]string{"cbom_results": cbomDoc}}, types: []string{"cbom"}, wantFile: true},
		{name: "one written, one not offered", srv: &bomServer{docs: map[string]string{"cbom_results": cbomDoc}},
			types: []string{"aibom", "cbom"}, wantFile: true},
		{name: "not offered only warns", srv: &bomServer{docs: map[string]string{}}, types: []string{"aibom", "cbom"}},
		{name: "a failed download is a failure", srv: &bomServer{docs: map[string]string{"cbom_results": cbomDoc},
			downloadCode: func(string, int) int { return http.StatusNotFound }}, types: []string{"cbom"}, wantFailures: []string{"cbom"}},
		{name: "results not available fails every type", srv: &bomServer{resultsCode: http.StatusNotFound},
			types: []string{"sbom", "all"}, wantFailures: []string{"sbom", "all"}},
		{name: "the skip reason is kept", srv: &bomServer{docs: map[string]string{"cbom_results": cbomDoc}, skipReason: &skip},
			types: []string{"cbom"}, wantSkip: skip, wantFile: true},
		{name: "the skip reason loses control characters", srv: &bomServer{docs: map[string]string{"cbom_results": cbomDoc}, skipReason: &controlSkip},
			types: []string{"cbom"}, wantSkip: "a scanner[2J was skipped", wantFile: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			client := row.srv.start(t)
			opts := &SBOMVEXOptions{BOM: &BOMOptions{Types: row.types, Format: BOMFormatCycloneDX17, Output: dir, Only: true}}
			var result *model.ScanResult
			var err error
			_ = testutil.CaptureStderr(t, func() {
				result, err = BOMOnlyResult(context.Background(), client, "tenant-123", "scan-456", "app", opts)
			})
			if err != nil {
				t.Fatalf("BOMOnlyResult: %v", err)
			}
			if result.ScanID != "scan-456" || len(result.Findings) != 0 || result.Summary.Total != 0 {
				t.Errorf("result = %+v, want scan-456 with no findings", result)
			}
			if !reflect.DeepEqual(result.BOMFailures, row.wantFailures) {
				t.Errorf("BOMFailures = %v, want %v", result.BOMFailures, row.wantFailures)
			}
			if result.Summary.ScannerSkipReason != row.wantSkip {
				t.Errorf("skip reason = %q, want %q", result.Summary.ScannerSkipReason, row.wantSkip)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "app-bom-cbom.json")); (statErr == nil) != row.wantFile {
				t.Errorf("app-bom-cbom.json exists = %v, want %v", statErr == nil, row.wantFile)
			}
			var wantWritten []string
			if row.wantFile {
				wantWritten = []string{"cbom"}
			}
			if !reflect.DeepEqual(result.BOMWritten, wantWritten) {
				t.Errorf("BOMWritten = %v, want %v", result.BOMWritten, wantWritten)
			}
		})
	}

	t.Run("Ctrl+C during a download returns the context error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv := &bomServer{docs: map[string]string{"cbom_results": cbomDoc},
			downloadCode: func(string, int) int { cancel(); return http.StatusNotFound }}
		client := srv.start(t)
		opts := &SBOMVEXOptions{BOM: &BOMOptions{Types: []string{"cbom"}, Format: BOMFormatCycloneDX17, Output: t.TempDir(), Only: true}}
		var result *model.ScanResult
		var err error
		_ = testutil.CaptureStderr(t, func() {
			result, err = BOMOnlyResult(ctx, client, "tenant-123", "scan-456", "app", opts)
		})
		if result != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("BOMOnlyResult = %v, %v; want a cancelled result", result, err)
		}
	})
}

// TestDownloadBOMsWarnsOnFailedTools: a BOM written while BOM tools failed on
// the server gets one warning after the BOM lines, naming the tools (control
// characters stripped, deduplicated, sorted) and the written types; the
// download still succeeds.
func TestDownloadBOMsWarnsOnFailedTools(t *testing.T) {
	const cbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	const emptyAIBOM = `{"bomFormat":"CycloneDX","components":[]}`
	const prefix = "BOM tools failed on the server: "
	status := func(types map[string]string, tools ...string) *api.BOMSummary {
		s := &api.BOMSummary{Types: map[string]api.BOMTypeStatus{}, FailedTools: tools}
		for t, st := range types {
			s.Types[t] = api.BOMTypeStatus{Status: st}
		}
		return s
	}
	rows := []struct {
		name     string
		docs     map[string]string
		summary  *api.BOMSummary
		types    []string
		want     string // the whole warning line; "" for none
		wantAlso string
	}{
		{name: "generated with a failed tool", docs: map[string]string{"cbom_results": cbomDoc},
			summary: status(map[string]string{"cbom": api.BOMStatusGenerated}, "opengrep_bom"), types: []string{"cbom"},
			want: prefix + "opengrep_bom; CBOM may be incomplete"},
		{name: "empty with failed tools, deduplicated and sorted", docs: map[string]string{"aibom_results": emptyAIBOM},
			summary: status(map[string]string{"aibom": api.BOMStatusEmpty}, "zz_tool", "a_tool\x1b[2J", "zz_tool", " "), types: []string{"aibom"},
			want: prefix + "a_tool[2J, zz_tool; AI-BOM may be incomplete", wantAlso: "No AI components found"},
		{name: "a failed type only: its own warning, no extra line",
			summary: status(map[string]string{"cbom": api.BOMStatusFailed}, "opengrep_bom"), types: []string{"cbom"},
			wantAlso: "CBOM failed on the server (tools that failed in this scan: opengrep_bom)"},
		{name: "a failed type beside a written one names the written one", docs: map[string]string{"cbom_results": cbomDoc},
			summary: status(map[string]string{"aibom": api.BOMStatusFailed, "cbom": api.BOMStatusGenerated}, "opengrep_bom"),
			types:   []string{"aibom", "cbom"}, want: prefix + "opengrep_bom; CBOM may be incomplete"},
		{name: "no failed tools", docs: map[string]string{"cbom_results": cbomDoc},
			summary: status(map[string]string{"cbom": api.BOMStatusGenerated}), types: []string{"cbom"}},
		{name: "no summary", docs: map[string]string{"cbom_results": cbomDoc}, types: []string{"cbom"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			srv := &bomServer{docs: row.docs, summary: row.summary}
			if srv.docs == nil {
				srv.docs = map[string]string{}
			}
			client := srv.start(t)
			_, stderr, err := downloadBOMs(t, client, &SBOMVEXOptions{BOM: &BOMOptions{
				Types: row.types, Format: BOMFormatCycloneDX17, Output: t.TempDir(), Target: ".",
			}})
			if err != nil {
				t.Fatalf("Download = %v, want no failure", err)
			}
			wantCount := 0
			if row.want != "" {
				wantCount = 1
			}
			if n := strings.Count(stderr, prefix); n != wantCount {
				t.Errorf("stderr has %d failed-tools warnings, want %d:\n%s", n, wantCount, stderr)
			}
			if row.want != "" {
				if !strings.Contains(stderr, "Warning: "+row.want+"\n") {
					t.Errorf("stderr = %q, want the line %q", stderr, row.want)
				}
				if saved := strings.LastIndex(stderr, "saved to:"); saved > strings.Index(stderr, prefix) {
					t.Errorf("the warning comes before a BOM line:\n%s", stderr)
				}
			}
			if row.wantAlso != "" && !strings.Contains(stderr, row.wantAlso) {
				t.Errorf("stderr = %q, want %q", stderr, row.wantAlso)
			}
			if strings.ContainsAny(stderr, "\x1b") {
				t.Errorf("stderr holds a control character: %q", stderr)
			}
		})
	}
}

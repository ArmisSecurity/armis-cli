package scan

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestResultKeyConstants(t *testing.T) {
	if ResultKeySBOM != "sbom_results" {
		t.Errorf("ResultKeySBOM = %q, want %q", ResultKeySBOM, "sbom_results")
	}
	if ResultKeyVEX != "vex_results" {
		t.Errorf("ResultKeyVEX = %q, want %q", ResultKeyVEX, "vex_results")
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
		err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		// Verify SBOM file was created
		data, err := os.ReadFile(sbomPath) //nolint:gosec // test file path from t.TempDir()
		if err != nil {
			t.Fatalf("Failed to read SBOM file: %v", err)
		}
		if string(data) != string(sbomContent) {
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
		err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		data, err := os.ReadFile(vexPath) //nolint:gosec // test file path from t.TempDir()
		if err != nil {
			t.Fatalf("Failed to read VEX file: %v", err)
		}
		if string(data) != string(vexContent) {
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
		err = downloader.Download(context.Background(), "scan-456", "my-artifact")

		if err != nil {
			t.Fatalf("Download failed: %v", err)
		}

		// Check default path
		expectedPath := filepath.Join(".armis", "my-artifact-sbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected SBOM file at default path %s", expectedPath)
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
		err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err == nil {
			t.Error("Expected error when results not available")
		}
	})

	t.Run("returns error on API failure", func(t *testing.T) {
		server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			testutil.ErrorResponse(w, http.StatusInternalServerError, "Server error")
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
		err = downloader.Download(context.Background(), "scan-456", "test-artifact")

		if err == nil {
			t.Error("Expected error on API failure")
		}
	})

	t.Run("rejects path traversal in artifact name", func(t *testing.T) {
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
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
			err := downloader.Download(context.Background(), "scan-456", tc)
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
		_ = downloader.Download(context.Background(), "scan-456", "test-artifact")

		// Verify the malicious file was NOT created
		if _, err := os.Stat("../../../tmp/evil.json"); err == nil {
			t.Error("Path traversal should have been blocked - file should not exist")
		}
	})
}

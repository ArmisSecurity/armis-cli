package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const testVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/vex-abc",
  "author": "Armis AppSec",
  "version": 1,
  "statements": [
    {"vulnerability": {"name": "GHSA-1"}, "products": [{"@id": "pkg:pypi/requests@2.19.0"}], "status": "affected"},
    {"vulnerability": {"name": "GHSA-2"}, "products": [{"@id": "pkg:pypi/flask@1.0"}], "status": "affected"}
  ]
}`

// newSBOMClient wires an API client at the mock server with local URLs allowed
// (the mock serves both the API and the fake presigned VEX download).
func newSBOMClient(t *testing.T, serverURL string) *api.Client {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	client, err := api.NewClient(serverURL, testutil.NewTestAuthProvider("token123"), false, time.Minute,
		api.WithHTTPClient(httpClient), api.WithUploadHTTPClient(uploadClient), api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return client
}

func newScanner(t *testing.T, serverURL string) *Scanner {
	t.Helper()
	return NewScanner(newSBOMClient(t, serverURL), true, "test-tenant", 500, time.Minute, false).
		WithPollInterval(10 * time.Millisecond).
		WithFetchRetryInterval(10 * time.Millisecond)
}

func TestScan_SingleSBOMFile_WithVEX(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		ScanID:     "sbom-scan-1",
		VEXContent: testVEX,
	})

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	vexOut := filepath.Join(tmpDir, "out-vex.json")

	scanner := newScanner(t, serverURL).WithVEXOutput(vexOut)

	result, err := scanner.Scan(context.Background(), sbomPath)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.ScanID != "sbom-scan-1" {
		t.Errorf("ScanID = %q, want sbom-scan-1", result.ScanID)
	}

	// VEX file must exist when --vex-output is requested.
	if _, err := os.Stat(vexOut); err != nil {
		t.Errorf("VEX not written to %s: %v", vexOut, err)
	}
}

func TestScan_Directory_NoVEX(t *testing.T) {
	// Without --vex-output the scan still runs but doesn't request VEX from
	// the backend and doesn't produce a VEX file locally.
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		ScanID: "sbom-scan-dir",
	})

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "a.json"), []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write a.json: %v", err)
	}
	sub := filepath.Join(srcDir, "nested")
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.xml"), []byte(`<bom/>`), 0600); err != nil {
		t.Fatalf("write b.xml: %v", err)
	}

	scanner := newScanner(t, serverURL)
	_, err := scanner.Scan(context.Background(), srcDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}

func TestScan_NonExistentPath(t *testing.T) {
	client := newSBOMClient(t, "https://localhost")
	scanner := NewScanner(client, true, "test-tenant", 500, time.Minute, false).
		WithPollInterval(10 * time.Millisecond)

	_, err := scanner.Scan(context.Background(), "/no/such/sbom.json")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestArtifactName(t *testing.T) {
	cases := map[string]string{
		"sbom.json":           "sbom",
		"/tmp/project.tar.gz": "project",
		"bundle.tgz":          "bundle",
		"image.tar":           "image",
		"/a/b/sboms":          "sboms",
		"cyclonedx.bom.xml":   "cyclonedx.bom",
	}
	for in, want := range cases {
		if got := artifactName(in); got != want {
			t.Errorf("artifactName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCountVEXStatements(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(tmp, []byte(testVEX), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	n, ok := countVEXStatements(tmp)
	if !ok {
		t.Fatal("expected ok")
	}
	if n != 2 {
		t.Errorf("statements = %d, want 2", n)
	}

	if _, ok := countVEXStatements(filepath.Join(t.TempDir(), "missing.json")); ok {
		t.Error("expected ok=false for missing file")
	}
}

// TestResultKeySBOMCPE_MatchesBackendContract locks the CLI-side raw-findings
// slot name to the backend's persist_results_task output. If either side
// renames the key, this test breaks in CI before the CLI silently drops the
// download.
func TestResultKeySBOMCPE_MatchesBackendContract(t *testing.T) {
	if ResultKeySBOMCPE != "sbom_cpe_results" {
		t.Errorf("ResultKeySBOMCPE = %q; backend contract expects %q",
			ResultKeySBOMCPE, "sbom_cpe_results")
	}
}

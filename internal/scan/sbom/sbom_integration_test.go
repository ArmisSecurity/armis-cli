package sbom_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	sbompkg "github.com/ArmisSecurity/armis-cli/internal/scan/sbom"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// These integration tests exercise the unified `scan sbom` driver against a
// bespoke httptest.Server that impersonates the backend on both routing
// paths:
//
//   - artifact_type=sbom + CPE-shaped SBOM →
//       results_refs = {sbom_cpe_results, vex_results?}
//   - artifact_type=sbom + purl-shaped SBOM →
//       results_refs = {sbom_results,     vex_results?}
//
// The CLI is intentionally oblivious to which scanner ran; the mock proves
// it downloads the raw JSON from whichever key the backend advertises and
// only fetches VEX when the caller opted in.

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const (
	testTenantID = "test-tenant"
	testScanID   = "unified-sbom-scan-001"
)

var (
	rawCPEJSON  = []byte(`{"packages":[{"name":"openssl","version":"1.0.2k","cpe":"cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"}],"vulnerabilities":[{"vulnerability_id":"CVE-2018-0732","severity":"HIGH","package":"openssl","version":"1.0.2k"}],"vulnerability_count":1,"package_count":1}`)
	rawPurlJSON = []byte(`{"Results":[{"Target":"purl.cdx.json","Vulnerabilities":[{"VulnerabilityID":"GHSA-1234","PkgName":"requests","InstalledVersion":"2.19.0","Severity":"HIGH"}]}]}`)
	vexDoc      = []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://openvex.dev/docs/vex-abc","author":"Armis AppSec","version":1,"statements":[{"vulnerability":{"name":"CVE-2018-0732"},"products":[{"@id":"pkg:pypi/requests@2.19.0"}],"status":"affected"}]}`)
)

func writeSBOM(t *testing.T, path string, components []map[string]any) {
	t.Helper()
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"components":  components,
	}
	body, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
}

// buildScanner wires an API client at serverURL and returns a Scanner with
// short poll/retry intervals so the tests stay fast.
func buildScanner(t *testing.T, serverURL string) *sbompkg.Scanner {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
	uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
	client, err := api.NewClient(serverURL,
		testutil.NewTestAuthProvider("test-token"),
		false, time.Minute,
		api.WithHTTPClient(httpClient),
		api.WithUploadHTTPClient(uploadClient),
		api.WithAllowLocalURLs(true),
	)
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	return sbompkg.NewScanner(client, true, testTenantID, 500, 30*time.Second, false).
		WithPollInterval(10 * time.Millisecond).
		WithFetchRetryInterval(10 * time.Millisecond)
}

// buildFinding constructs a NormalizedFinding shaped as the CLI expects.
// Uses the same shape as the sbomcpe test suite that used to live here.
func buildFinding(id, cve, pkg string) model.NormalizedFinding {
	fileName := "sbom.cdx.json"
	return model.NormalizedFinding{
		NormalizedTask: model.NormalizedTask{
			FindingID: id,
			ExtraData: model.ExtraData{
				CodeLocation: model.CodeLocation{FileName: &fileName},
			},
		},
		NormalizedRemediation: model.NormalizedRemediation{
			Description:  "Denial of service in " + pkg + " (" + cve + ").",
			ToolSeverity: "HIGH",
			VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
				CVEs: []string{cve},
				CWEs: []string{"CWE-400"},
			},
		},
	}
}

// serverConfig describes what the mock backend advertises for a scan.
type serverConfig struct {
	name           string
	rawKey         string // "sbom_cpe_results" or "sbom_results"
	rawBody        []byte
	includeVEX     bool // if true, advertise vex_results too
	scanIDOverride string
	findings       []model.NormalizedFinding
}

// buildMockServer wraps the shared MockScanServer with a handler that
// (a) records the artifact_type sent to /presigned-url and (b) advertises
// the correct results_refs keys so the driver picks up the right raw JSON.
// Returns (server URL, artifact-type observer, raw-download observer).
func buildMockServer(t *testing.T, cfg serverConfig) (
	url string,
	observedArtifactType *atomic.Value,
	rawDownloadCount *atomic.Int32,
) {
	t.Helper()
	if cfg.scanIDOverride == "" {
		cfg.scanIDOverride = testScanID
	}
	observedArtifactType = &atomic.Value{}
	rawDownloadCount = &atomic.Int32{}

	// The shared mock handles /presigned-url, /_s3/upload, /ingest/scan,
	// /ingest/status/…, /ingest/normalized-results, /_vex/.
	base := testutil.NewMockScanServerWithConfig(t, testutil.MockAPIConfig{
		ScanID:             cfg.scanIDOverride,
		Findings:           cfg.findings,
		PollsUntilComplete: 1,
	})
	baseHandler := base.Handler
	mux := http.NewServeMux()

	// Override /presigned-url to record the artifact_type on the way in.
	mux.HandleFunc("/api/v1/ingest/presigned-url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req model.PresignedUploadRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		observedArtifactType.Store(req.ArtifactType)
		scheme := testutil.SchemeFromRequest(r)
		testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
			ScanID:       cfg.scanIDOverride,
			ArtifactType: req.ArtifactType,
			TenantID:     testTenantID,
			PresignedURL: scheme + "://" + r.Host + "/_s3/upload",
			Fields: map[string]string{
				"key":             "ingest/" + testTenantID + "/" + cfg.scanIDOverride + "/upload.tar.gz",
				"policy":          "test-policy",
				"x-amz-signature": "test-sig",
			},
			MaxUploadBytes: 2 * 1024 * 1024 * 1024,
			ExpiresIn:      1800,
		})
	})

	// Override /ingest/results to advertise the results_refs keys the CLI
	// bifurcates on.
	mux.HandleFunc("/api/v1/ingest/results", func(w http.ResponseWriter, r *http.Request) {
		scheme := testutil.SchemeFromRequest(r)
		host := r.Host
		results := map[string]string{
			"all_results": scheme + "://" + host + "/_download/all",
		}
		if cfg.rawKey != "" {
			results[cfg.rawKey] = scheme + "://" + host + "/_download/raw"
		}
		if cfg.includeVEX {
			results["vex_results"] = scheme + "://" + host + "/_download/vex"
		}
		testutil.JSONResponse(t, w, http.StatusOK, map[string]any{
			"scan_status": "COMPLETED",
			"results":     results,
		})
	})

	// Fake presigned-URL download endpoints — CLI's raw-findings + VEX pull.
	mux.HandleFunc("/_download/raw", func(w http.ResponseWriter, r *http.Request) {
		rawDownloadCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(cfg.rawBody)
	})
	mux.HandleFunc("/_download/vex", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vexDoc)
	})
	mux.HandleFunc("/_download/all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	// Everything else delegates to the shared mock (S3 upload, /ingest/scan,
	// status polls, normalized-results).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		baseHandler.ServeHTTP(w, r)
	})

	testSrv := testutil.NewTestServer(t, mux.ServeHTTP)
	return testSrv.URL, observedArtifactType, rawDownloadCount
}

// ---------------------------------------------------------------------------
// Bifurcation matrix
// ---------------------------------------------------------------------------

// TestIntegration_CPE_NoVEX runs the driver against a mock backend that
// advertises sbom_cpe_results (CPE path). The CLI should:
//   - send artifact_type=sbom
//   - fetch normalized findings
//   - download the raw JSON from the sbom_cpe_results URL
//   - not request or write a VEX doc
func TestIntegration_CPE_NoVEX(t *testing.T) {
	tmpDir := t.TempDir()
	// The driver's default VEX path is .armis/<artifact>-vex.json relative to
	// the process cwd. Anchor cwd to tmpDir so the "no VEX written" assertion
	// checks the same location the driver would actually write to.
	t.Chdir(tmpDir)

	sbomPath := filepath.Join(tmpDir, "torizon.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "openssl", "version": "1.0.2k",
		"cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*",
	}})

	serverURL, artifactType, rawHits := buildMockServer(t, serverConfig{
		name:     "cpe",
		rawKey:   sbompkg.ResultKeySBOMCPE,
		rawBody:  rawCPEJSON,
		findings: []model.NormalizedFinding{buildFinding("f-cpe-1", "CVE-2018-0732", "openssl")},
	})

	rawOut := filepath.Join(tmpDir, "raw.json")
	scanner := buildScanner(t, serverURL).WithRawOutput(rawOut)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := scanner.Scan(ctx, sbomPath)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Contract with backend: always sbom regardless of shape.
	if got, _ := artifactType.Load().(string); got != "sbom" {
		t.Errorf("artifact_type sent = %q, want sbom", got)
	}

	if len(result.Findings) != 1 || result.Findings[0].ID != "f-cpe-1" {
		t.Errorf("got %d findings, want 1 with id=f-cpe-1", len(result.Findings))
	}
	if rawHits.Load() != 1 {
		t.Errorf("raw download called %d times, want 1", rawHits.Load())
	}
	data, err := os.ReadFile(rawOut) //nolint:gosec // sandboxed path
	if err != nil {
		t.Fatalf("read raw dump: %v", err)
	}
	if !bytes.Contains(data, []byte("CVE-2018-0732")) {
		t.Errorf("raw dump missing expected CVE; got: %s", string(data))
	}
	// No VEX was requested and none should have been written to the default
	// path (now anchored under tmpDir via t.Chdir above).
	vexPath := filepath.Join(tmpDir, ".armis", "torizon-vex.json")
	if _, err := os.Stat(vexPath); err == nil {
		t.Errorf("VEX file unexpectedly written to %s", vexPath)
	}
}

// TestIntegration_Purl_NoVEX mirrors CPE_NoVEX but the backend advertises
// sbom_results (purl path). The CLI must fall back to that key.
func TestIntegration_Purl_NoVEX(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "purl.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "requests", "version": "2.19.0",
		"purl": "pkg:pypi/requests@2.19.0",
	}})

	serverURL, artifactType, rawHits := buildMockServer(t, serverConfig{
		name:     "purl",
		rawKey:   scan.ResultKeySBOM,
		rawBody:  rawPurlJSON,
		findings: []model.NormalizedFinding{buildFinding("f-purl-1", "GHSA-1234", "requests")},
	})

	rawOut := filepath.Join(tmpDir, "raw.json")
	scanner := buildScanner(t, serverURL).WithRawOutput(rawOut)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := scanner.Scan(ctx, sbomPath)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got, _ := artifactType.Load().(string); got != "sbom" {
		t.Errorf("artifact_type sent = %q, want sbom", got)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "f-purl-1" {
		t.Errorf("got %d findings, want 1 with id=f-purl-1", len(result.Findings))
	}
	if rawHits.Load() != 1 {
		t.Errorf("raw download called %d times, want 1", rawHits.Load())
	}
	data, err := os.ReadFile(rawOut) //nolint:gosec // sandboxed path
	if err != nil {
		t.Fatalf("read raw dump: %v", err)
	}
	if !bytes.Contains(data, []byte("GHSA-1234")) {
		t.Errorf("raw dump missing expected id; got: %s", string(data))
	}
}

// TestIntegration_CPE_WithVEX asserts --vex-output triggers VEX download on
// top of the findings + raw JSON.
func TestIntegration_CPE_WithVEX(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "torizon.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "openssl", "version": "1.0.2k",
		"cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*",
	}})

	serverURL, _, _ := buildMockServer(t, serverConfig{
		name:       "cpe+vex",
		rawKey:     sbompkg.ResultKeySBOMCPE,
		rawBody:    rawCPEJSON,
		includeVEX: true,
		findings:   []model.NormalizedFinding{buildFinding("f-cpe-vex", "CVE-2018-0732", "openssl")},
	})

	vexOut := filepath.Join(tmpDir, "out.vex.json")
	rawOut := filepath.Join(tmpDir, "raw.json")
	scanner := buildScanner(t, serverURL).WithVEXOutput(vexOut).WithRawOutput(rawOut)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := scanner.Scan(ctx, sbomPath); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if _, err := os.Stat(vexOut); err != nil {
		t.Fatalf("VEX not written to %s: %v", vexOut, err)
	}
	body, err := os.ReadFile(vexOut) //nolint:gosec // sandboxed path
	if err != nil {
		t.Fatalf("read vex: %v", err)
	}
	if !bytes.Contains(body, []byte("openvex.dev")) {
		t.Errorf("VEX doesn't look right: %s", string(body))
	}
}

// TestIntegration_Purl_WithVEX asserts the purl path also downloads VEX
// when opted in.
func TestIntegration_Purl_WithVEX(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "purl.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "requests", "version": "2.19.0",
		"purl": "pkg:pypi/requests@2.19.0",
	}})

	serverURL, _, _ := buildMockServer(t, serverConfig{
		name:       "purl+vex",
		rawKey:     scan.ResultKeySBOM,
		rawBody:    rawPurlJSON,
		includeVEX: true,
		findings:   []model.NormalizedFinding{buildFinding("f-purl-vex", "GHSA-1234", "requests")},
	})

	vexOut := filepath.Join(tmpDir, "out.vex.json")
	rawOut := filepath.Join(tmpDir, "raw.json")
	scanner := buildScanner(t, serverURL).WithVEXOutput(vexOut).WithRawOutput(rawOut)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := scanner.Scan(ctx, sbomPath); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, err := os.Stat(vexOut); err != nil {
		t.Fatalf("VEX not written to %s: %v", vexOut, err)
	}
}

// TestIntegration_VEXRequestedButBackendMissingIt asserts the driver
// tolerates a backend that didn't produce VEX even though --vex-output was
// passed. The scan should complete with findings and log a warning; the
// missing VEX must not crash the pipeline.
func TestIntegration_VEXRequestedButBackendMissingIt(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "purl.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "requests", "version": "2.19.0",
		"purl": "pkg:pypi/requests@2.19.0",
	}})

	// Backend advertises sbom_results but no vex_results despite the CLI
	// asking for one.
	serverURL, _, _ := buildMockServer(t, serverConfig{
		name:       "purl-no-vex",
		rawKey:     scan.ResultKeySBOM,
		rawBody:    rawPurlJSON,
		includeVEX: false,
		findings:   []model.NormalizedFinding{buildFinding("f-nv-1", "GHSA-1234", "requests")},
	})

	vexOut := filepath.Join(tmpDir, "out.vex.json")
	rawOut := filepath.Join(tmpDir, "raw.json")
	scanner := buildScanner(t, serverURL).WithVEXOutput(vexOut).WithRawOutput(rawOut)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := scanner.Scan(ctx, sbomPath)
	if err != nil {
		t.Fatalf("Scan should succeed even when VEX is unavailable: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(result.Findings))
	}
	if _, err := os.Stat(vexOut); err == nil {
		t.Errorf("VEX unexpectedly written even though backend didn't advertise it")
	}
}

// TestIntegration_NoResultsRefs asserts a backend response with an empty
// results dict still lets the CLI print the findings table. Some scanner
// implementations (or scan states) may not populate any raw dumps.
func TestIntegration_NoResultsRefs(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "purl.cdx.json")
	writeSBOM(t, sbomPath, []map[string]any{{
		"type": "library", "name": "leftpad", "version": "1.3.0",
		"purl": "pkg:npm/leftpad@1.3.0",
	}})

	// Empty rawKey → mock advertises only all_results.
	serverURL, _, _ := buildMockServer(t, serverConfig{
		name:     "no-refs",
		rawKey:   "", // no sbom_results / sbom_cpe_results advertised
		rawBody:  nil,
		findings: []model.NormalizedFinding{buildFinding("f-empty-refs", "GHSA-999", "leftpad")},
	})

	scanner := buildScanner(t, serverURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := scanner.Scan(ctx, sbomPath)
	if err != nil {
		t.Fatalf("Scan should succeed even with no raw refs: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(result.Findings))
	}
}

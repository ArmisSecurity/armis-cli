package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/history"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// setupStatusEnv fixes the global CLI state to a known baseline for each
// subtest. The scan_status command reuses `getAuthProvider()`, which reads
// the same package-level `token` / `tenantID` / `clientID` variables that
// the sibling scan tests already use — hence the shared shape.
func setupStatusEnv(t *testing.T, serverURL string) func() {
	t.Helper()

	origToken := token
	origTenant := tenantID
	origClientID := clientID
	origClientSecret := clientSecret
	origColor := colorFlag
	origTheme := themeFlag
	origNoUpdate := noUpdateCheck
	origFormat := format

	// Route auth away from the real environment.
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	t.Setenv("ARMIS_API_URL", serverURL)
	// Isolate the scan-history store to a per-test dir so tests never touch
	// the developer's ~/.armis file.
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())

	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	format = testFormatHuman

	return func() {
		token = origToken
		tenantID = origTenant
		clientID = origClientID
		clientSecret = origClientSecret
		colorFlag = origColor
		themeFlag = origTheme
		noUpdateCheck = origNoUpdate
		format = origFormat
		_ = os.Unsetenv("ARMIS_API_URL")
	}
}

// runStatus is a tiny shim around runScanStatus that captures stdout for
// assertion. It calls the RunE directly (rather than executing the full
// cobra tree) so we can inject args and verify the returned error without
// spawning a subprocess.
func runStatus(t *testing.T, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	scanStatusCmd.SetOut(&buf)
	scanStatusCmd.SetErr(&buf)
	scanStatusCmd.SetContext(context.Background())
	err := runScanStatus(scanStatusCmd, args)
	return buf.String(), err
}

func statusServer(t *testing.T, status string, extra func(d *model.IngestStatusData)) string {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v1/ingest/status") {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		if q := r.URL.Query().Get("tenant_id"); q == "" {
			t.Errorf("tenant_id query param missing")
		}
		if q := r.URL.Query().Get("scan_id"); q == "" {
			t.Errorf("scan_id query param missing")
		}
		data := model.IngestStatusData{
			ScanID:         r.URL.Query().Get("scan_id"),
			TenantID:       r.URL.Query().Get("tenant_id"),
			ScanStatus:     status,
			ArtifactType:   "repo",
			ScanType:       "full",
			FileName:       "example.tar.gz",
			FileBytes:      2048,
			StartedAt:      "2026-07-27T10:00:00Z",
			UpdatedAt:      "2026-07-27T10:05:00Z",
			ExpirationTime: "2026-08-27T10:00:00Z",
		}
		if extra != nil {
			extra(&data)
		}
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
			Data: []model.IngestStatusData{data},
		})
	}
	server := testutil.NewTestServer(t, handler)
	return server.URL
}

// TestScanStatus_AllStatuses walks every ArtifactScanStatus enum value the
// API documents. For each one we verify the command exits without error,
// prints the expected status, and includes the state-specific hint line
// (the guidance sentence that lives under scanStatusHint).
func TestScanStatus_AllStatuses(t *testing.T) {
	cases := []struct {
		status   string
		wantHint string
	}{
		{"PENDING_UPLOAD", "Waiting for the artifact upload"},
		{"UPLOADED", "Upload complete"},
		{"INITIATED", "Scan queued"},
		{"IN_PROGRESS", "Analysis is running"},
		{"COMPLETED", "Scan finished"},
		{statusValFailed, "Scan failed"},
		{"STOPPED", "Scan was stopped"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.status, func(t *testing.T) {
			url := statusServer(t, tc.status, func(d *model.IngestStatusData) {
				if tc.status == statusValFailed {
					e := "worker crashed"
					d.LastError = &e
				}
			})
			cleanup := setupStatusEnv(t, url)
			defer cleanup()

			out, err := runStatus(t, []string{"scan-abc"})
			if err != nil {
				t.Fatalf("runStatus %s: %v", tc.status, err)
			}
			if !strings.Contains(out, tc.status) {
				t.Errorf("output does not include status %q:\n%s", tc.status, out)
			}
			if !strings.Contains(out, tc.wantHint) {
				t.Errorf("output does not include hint %q:\n%s", tc.wantHint, out)
			}
			if tc.status == statusValFailed && !strings.Contains(out, "worker crashed") {
				t.Errorf("FAILED output missing last error line:\n%s", out)
			}
		})
	}
}

// TestScanStatus_JSONFormat verifies the JSON output shape. Downstream
// tooling relies on the top-level `scan_id` plus the nested `status.*`
// fields; if we ever break that shape the CI (rather than a customer)
// should be the one to notice.
func TestScanStatus_JSONFormat(t *testing.T) {
	url := statusServer(t, "COMPLETED", nil)
	cleanup := setupStatusEnv(t, url)
	defer cleanup()

	format = statusFormatJSON
	out, err := runStatus(t, []string{"scan-xyz"})
	if err != nil {
		t.Fatalf("runStatus json: %v", err)
	}

	var payload scanStatusJSON
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if payload.ScanID != "scan-xyz" {
		t.Errorf("payload.ScanID = %q, want scan-xyz", payload.ScanID)
	}
	if payload.StatusData.ScanStatus != "COMPLETED" {
		t.Errorf("payload.StatusData.ScanStatus = %q, want COMPLETED", payload.StatusData.ScanStatus)
	}
	// When the scan_id came from the CLI arg (not history) the marker
	// should be absent.
	if payload.FromCache {
		t.Errorf("FromCache should be false when scan_id is passed explicitly")
	}
}

// TestScanStatus_FallsBackToHistory covers the "no scan_id argument" path:
// the command should read the most recent scan out of the history store
// and query the API for that ID.
func TestScanStatus_FallsBackToHistory(t *testing.T) {
	url := statusServer(t, "IN_PROGRESS", nil)
	cleanup := setupStatusEnv(t, url)
	defer cleanup()

	// Seed the history store with a matching entry so the command has
	// something to fall back on.
	store := history.NewStore()
	if err := store.Save(history.Entry{
		BaseURL:      url,
		TenantID:     testTenantID,
		ScanID:       "history-scan-42",
		ArtifactType: "repo",
		Artifact:     "test-repo",
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	out, err := runStatus(t, []string{})
	if err != nil {
		t.Fatalf("runStatus fallback: %v", err)
	}
	if !strings.Contains(out, "history-scan-42") {
		t.Errorf("expected fallback scan_id in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Resolved scan_id from local history") {
		t.Errorf("expected history-fallback hint in output, got:\n%s", out)
	}
}

// TestScanStatus_NoArgNoHistory verifies the failure mode when the user
// asks for the "last scan" and none exists. The error text must include
// both the tenant and the base URL so the user knows what the CLI was
// looking for.
func TestScanStatus_NoArgNoHistory(t *testing.T) {
	// No handler needed — the command must fail before making a network
	// call. Point at a dummy https URL so NewClient still accepts the
	// base URL when it runs.
	cleanup := setupStatusEnv(t, "https://example.invalid")
	defer cleanup()

	_, err := runStatus(t, []string{})
	if err == nil {
		t.Fatal("expected error when no scan_id is provided and history is empty")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no scan_id provided") {
		t.Errorf("error text should mention missing scan_id: %s", msg)
	}
	if !strings.Contains(msg, testTenantID) {
		t.Errorf("error text should mention tenant %q: %s", testTenantID, msg)
	}
}

// TestScanStatus_APIErrors verifies the 404 / 403 / 422 translation. Users
// commonly hit 404 when they paste the wrong scan_id — a plain "status
// 404: ..." bubbling up is far worse than a targeted hint.
func TestScanStatus_APIErrors(t *testing.T) {
	cases := []struct {
		name     string
		httpCode int
		want     string
	}{
		{"not_found", http.StatusNotFound, "scan bad-id not found"},
		{"forbidden", http.StatusForbidden, "access denied for scan"},
		{"validation", http.StatusUnprocessableEntity, "invalid scan_id"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				testutil.ErrorResponse(w, tc.httpCode, "boom")
			}
			server := testutil.NewTestServer(t, handler)
			cleanup := setupStatusEnv(t, server.URL)
			defer cleanup()

			_, err := runStatus(t, []string{"bad-id"})
			if err == nil {
				t.Fatal("expected error from API failure")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestScanStatus_EmptyData exercises the (unusual but documented) case where
// the API returns a 200 with an empty `data` array. Silently dropping the
// user with no output would be worse than a small explicit error.
func TestScanStatus_EmptyData(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{Data: []model.IngestStatusData{}})
	}
	server := testutil.NewTestServer(t, handler)
	cleanup := setupStatusEnv(t, server.URL)
	defer cleanup()

	_, err := runStatus(t, []string{"scan-empty"})
	if err == nil {
		t.Fatal("expected error when API returns empty data")
	}
	if !strings.Contains(err.Error(), "no status data returned") {
		t.Errorf("error = %q, expected 'no status data returned'", err.Error())
	}
}

// TestScanStatus_EmptyScanIDArg verifies the explicit-empty-string guard.
// Someone piping a shell variable can end up passing "" as the arg; we
// should refuse it instead of silently falling through to the history
// lookup.
func TestScanStatus_EmptyScanIDArg(t *testing.T) {
	cleanup := setupStatusEnv(t, "https://example.invalid")
	defer cleanup()

	_, err := runStatus(t, []string{""})
	if err == nil {
		t.Fatal("expected error for empty scan_id argument")
	}
	if !strings.Contains(err.Error(), "scan_id argument is empty") {
		t.Errorf("error = %q, expected empty-arg message", err.Error())
	}
}

// TestScanStatus_InvalidFormat verifies flag validation. The status
// command only supports human/json — SARIF and JUnit are meaningless for
// a single status record and must be rejected up front.
func TestScanStatus_InvalidFormat(t *testing.T) {
	cleanup := setupStatusEnv(t, "https://example.invalid")
	defer cleanup()

	format = "sarif"
	_, err := runStatus(t, []string{"scan-x"})
	if err == nil {
		t.Fatal("expected error for invalid --format value")
	}
	if !strings.Contains(err.Error(), "invalid --format") {
		t.Errorf("error = %q, expected format-validation message", err.Error())
	}
}

// TestScanStatus_FormatShorthandParses is a regression test for the
// flag-shadowing bug: `scan status <id> -f json` must parse against the
// persistent `-f, --format` flag inherited from `scan`. Previously a local
// --format (no shorthand) shadowed the persistent one, so Cobra rejected
// `-f` with "unknown shorthand flag: 'f'" and ignored $ARMIS_FORMAT.
func TestScanStatus_FormatShorthandParses(t *testing.T) {
	origFormat := format
	t.Cleanup(func() {
		format = origFormat
		// Reset the flag back to its default so parsing here doesn't leak
		// into other tests that execute through the command tree.
		if f := scanStatusCmd.Flags().Lookup("format"); f != nil {
			_ = f.Value.Set(origFormat)
		}
	})

	// The status subcommand must not own a *local* --format flag; it should
	// resolve to the inherited persistent one.
	if local := scanStatusCmd.LocalFlags().Lookup("format"); local != nil {
		t.Error("scan status declares a local --format flag; it must inherit the persistent -f/--format from `scan`")
	}

	// Parsing -f must succeed and populate the shared `format` var.
	if err := scanStatusCmd.ParseFlags([]string{"-f", "json"}); err != nil {
		t.Fatalf("parsing `-f json` failed (shorthand shadowed?): %v", err)
	}
	if format != statusFormatJSON {
		t.Errorf("format = %q after `-f json`, want %q", format, statusFormatJSON)
	}
}

// TestScanStatus_HistoryScopedByEnv makes sure the fallback respects the
// (base_url, tenant_id) scoping — a scan initiated against dev must not be
// returned as the "latest" scan when the CLI is talking to prod.
func TestScanStatus_HistoryScopedByEnv(t *testing.T) {
	url := statusServer(t, "COMPLETED", nil)
	cleanup := setupStatusEnv(t, url)
	defer cleanup()

	store := history.NewStore()
	// Seed a scan on a DIFFERENT base URL — the command should ignore it.
	if err := store.Save(history.Entry{
		BaseURL:      "https://some-other.armis.com",
		TenantID:     testTenantID,
		ScanID:       "wrong-env-scan",
		ArtifactType: "repo",
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	_, err := runStatus(t, []string{})
	if err == nil {
		t.Fatal("expected error since history has no entry for the current base URL")
	}
	if strings.Contains(err.Error(), "wrong-env-scan") {
		t.Errorf("cross-env scan_id leaked into fallback: %v", err)
	}
}

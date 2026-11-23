package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSBOMScanWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		wantOK   bool
		contains []string
		absent   []string
	}{
		{
			name:   "no SBOM scanning reports nothing",
			body:   `{"scan_status":"COMPLETED","results":{}}`,
			wantOK: false,
		},
		{
			name:   "complete SBOM scan reports nothing",
			body:   `{"scan_status":"COMPLETED","results":{},"sbom_scan_status":"COMPLETED"}`,
			wantOK: false,
		},
		{
			name: "partial scan names the reasons and the skipped files",
			body: `{"scan_status":"COMPLETED","results":{},
				"sbom_scan_status":"PARTIAL",
				"sbom_scan_reasons":["file_limit_exceeded","file_too_large"],
				"sbom_skipped_files":[{"path":"z/bom.json","reason":"file_limit_exceeded"},
				                      {"path":"huge.json","reason":"file_too_large"}],
				"sbom_skipped_count":2}`,
			wantOK: true,
			contains: []string{
				"SBOM scan incomplete: 2 SBOM file(s) were not scanned",
				"over the SBOM file limit, too large",
				"keep their previous state",
				"Skipped: z/bom.json, huge.json",
			},
			absent: []string{"more"},
		},
		{
			name: "long skip lists are shortened with a total",
			body: `{"scan_status":"COMPLETED","results":{},
				"sbom_scan_status":"PARTIAL","sbom_scan_reasons":["file_limit_exceeded"],
				"sbom_skipped_files":[{"path":"1.json"},{"path":"2.json"},{"path":"3.json"},
				                      {"path":"4.json"},{"path":"5.json"},{"path":"6.json"}],
				"sbom_skipped_count":40}`,
			wantOK:   true,
			contains: []string{"40 SBOM file(s)", "1.json, 2.json, 3.json, 4.json, 5.json and 35 more"},
			absent:   []string{"6.json"},
		},
		{
			name: "failed scan says nothing was scanned",
			body: `{"scan_status":"COMPLETED","results":{},
				"sbom_scan_status":"FAILED","sbom_scan_reasons":["grype_timeout"],
				"sbom_skipped_files":[{"path":"a.json","reason":"grype_timeout"}],
				"sbom_skipped_count":1}`,
			wantOK:   true,
			contains: []string{"SBOM scan failed: none of the SBOM files could be scanned", "(timed out)"},
		},
		{
			name: "an unknown reason is still shown readably",
			body: `{"scan_status":"COMPLETED","results":{},
				"sbom_scan_status":"PARTIAL","sbom_scan_reasons":["new_backend_reason"],
				"sbom_skipped_count":1}`,
			wantOK:   true,
			contains: []string{"(new backend reason)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var resp ArtifactScanResultsResponse
			if err := json.Unmarshal([]byte(tt.body), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			msg, ok := resp.SBOMScanWarning()

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (msg %q)", ok, tt.wantOK, msg)
			}
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not contain %q", msg, want)
				}
			}
			for _, unwanted := range tt.absent {
				if strings.Contains(msg, unwanted) {
					t.Errorf("message %q should not contain %q", msg, unwanted)
				}
			}
		})
	}
}

func TestSBOMScanWarningNilResponse(t *testing.T) {
	t.Parallel()
	var resp *ArtifactScanResultsResponse
	if msg, ok := resp.SBOMScanWarning(); ok || msg != "" {
		t.Errorf("nil response: got (%q, %v), want (\"\", false)", msg, ok)
	}
}

func TestSBOMScanWarningStripsControlCharactersFromRepositoryText(t *testing.T) {
	// A repository file name can hold terminal escapes: erase the line and move
	// the cursor up, over the findings summary printed above the warning.
	r := &ArtifactScanResultsResponse{
		SBOMScanStatus:  "PARTIAL",
		SBOMScanReasons: []string{"file_too_large", "odd\x1b[31m_reason"},
		SBOMSkippedFiles: []SkippedSBOMFile{
			{Path: "findings, scan clean\x1b[2K\x1b[1Abom.json", Reason: "file_too_large"},
			{Path: "\x1b\x07\x00", Reason: "file_too_large"},
		},
		SBOMSkippedCount: 2,
	}

	msg, ok := r.SBOMScanWarning()

	if !ok {
		t.Fatal("expected a warning")
	}
	if strings.ContainsAny(msg, "\x1b\r\n") {
		t.Fatalf("warning still holds control characters: %q", msg)
	}
	if !strings.Contains(msg, "bom.json") || !strings.Contains(msg, "odd") {
		t.Fatalf("expected the cleaned path and reason in the warning, got: %q", msg)
	}
	if !strings.Contains(msg, "and 1 more") {
		t.Fatalf("a path that is empty once cleaned is counted, not listed: %q", msg)
	}
}

func TestSBOMScanWarningBoundsAVeryLongPath(t *testing.T) {
	r := &ArtifactScanResultsResponse{
		SBOMScanStatus:   "PARTIAL",
		SBOMSkippedFiles: []SkippedSBOMFile{{Path: strings.Repeat("a/", 1<<20) + "bom.json"}},
		SBOMSkippedCount: 1,
	}

	msg, _ := r.SBOMScanWarning()

	if len(msg) > 1<<17 {
		t.Fatalf("warning not bounded: %d bytes", len(msg))
	}
}

func TestSBOMScanWarningWhenOnlyTheDetectionLimitWasHit(t *testing.T) {
	r := &ArtifactScanResultsResponse{
		SBOMScanStatus:  "PARTIAL",
		SBOMScanReasons: []string{"detection_limit_reached"},
	}

	msg, ok := r.SBOMScanWarning()

	if !ok {
		t.Fatal("expected a warning")
	}
	want := "SBOM scan incomplete: not every file was checked for SBOMs, so some " +
		"SBOM files may not have been scanned. Their findings keep their previous state."
	if msg != want {
		t.Fatalf("got  %q\nwant %q", msg, want)
	}
}

func TestSBOMScanWarningWithSkippedFilesAndTheDetectionLimit(t *testing.T) {
	r := &ArtifactScanResultsResponse{
		SBOMScanStatus:   "PARTIAL",
		SBOMScanReasons:  []string{"detection_limit_reached", "file_limit_exceeded"},
		SBOMSkippedFiles: []SkippedSBOMFile{{Path: "z/bom.json", Reason: "file_limit_exceeded"}},
		SBOMSkippedCount: 1,
	}

	msg, _ := r.SBOMScanWarning()

	want := "SBOM scan incomplete: 1 SBOM file(s) were not scanned (not every file was " +
		"checked for SBOMs, over the SBOM file limit). Their findings keep their previous " +
		"state. Skipped: z/bom.json"
	if msg != want {
		t.Fatalf("got  %q\nwant %q", msg, want)
	}
}

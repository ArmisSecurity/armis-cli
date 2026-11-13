package scan

import "testing"

func TestBuildScanResultReportsCompleted(t *testing.T) {
	// `scan sbom` builds its result here; the repo and image builders already
	// report "completed", and an empty status left a blank "Status:" line.
	result := BuildScanResult("scan-123", nil, false, false)
	if result.Status != "completed" {
		t.Errorf("Status = %q, want completed", result.Status)
	}
	if result.ScanID != "scan-123" || result.Summary.Total != 0 {
		t.Errorf("unexpected result: %+v", result)
	}
}

package scan

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// TestBuildScanResultKeepsExposedSecretsGradedLow covers the shared conversion path
// used by `scan sbom` (and any future scan type). It had the pre-exemption
// single-condition filter, so an exposed secret the backend graded low
// exploitability was dropped here even though repo and image scans exempt it.
func TestBuildScanResultKeepsExposedSecretsGradedLow(t *testing.T) {
	secret := model.NormalizedFinding{}
	secret.NormalizedTask.FindingID = "finding-secret"
	secret.NormalizedTask.Labels = []model.Label{
		{Description: "Exploitability Level", Value: "armis_appsec:exploitability:low"},
	}
	secret.NormalizedRemediation.Description = "hard-coded credential"
	secret.NormalizedRemediation.FindingCategory = "SECRET_EXPOSURE"

	result := BuildScanResult("scan-1", []model.NormalizedFinding{secret}, false, false)

	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (the exposed secret must survive the exploitability filter)",
			len(result.Findings))
	}
	if result.Summary.FilteredNonExploitable != 0 {
		t.Errorf("FilteredNonExploitable = %d, want 0", result.Summary.FilteredNonExploitable)
	}
	if result.Findings[0].Type != model.FindingTypeSecret {
		t.Errorf("Type = %s, want %s", result.Findings[0].Type, model.FindingTypeSecret)
	}
}

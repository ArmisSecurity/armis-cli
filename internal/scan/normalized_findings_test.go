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

// TestBuildScanResultDeduplicatesCodeFindings pins where the dedupe pass lives.
// repo and image call DeduplicateFindings inside their own buildScanResult, so a
// scan type going through this shared helper used to skip it -- a divergence with
// no visible effect today (see the package-findings case below) that would become
// a real one the moment a code-bearing scan type is added here.
func TestBuildScanResultDeduplicatesCodeFindings(t *testing.T) {
	codeFinding := func(id, endCol string) model.NormalizedFinding {
		nf := model.NormalizedFinding{}
		nf.NormalizedTask.FindingID = id
		nf.NormalizedRemediation.Description = "os command injection " + endCol
		nf.NormalizedRemediation.ToolSeverity = "HIGH"
		nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs = []string{"CWE-78: OS Command Injection"}
		file, line, col := "src/run.py", 12, 5
		nf.NormalizedTask.ExtraData.CodeLocation.FileName = &file
		nf.NormalizedTask.ExtraData.CodeLocation.StartLine = &line
		nf.NormalizedTask.ExtraData.CodeLocation.StartCol = &col
		return nf
	}

	result := BuildScanResult("scan-1", []model.NormalizedFinding{
		codeFinding("finding-b", "b"),
		codeFinding("finding-a", "a"),
	}, false, false)

	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (one defect at one location reported twice)", len(result.Findings))
	}
	if result.Findings[0].ID != "finding-a" {
		t.Errorf("kept ID = %s, want finding-a (smallest ID, so repeated scans agree)", result.Findings[0].ID)
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1 (the summary must count what the user sees)", result.Summary.Total)
	}
}

// TestBuildScanResultKeepsDistinctCVEsInOneComponent is the reason adding the
// dedupe pass above is safe for `scan sbom`, the helper's only caller today:
// every SBOM finding is a package CVE, and dedupable() excludes CVE-bearing
// findings outright because several CVEs in one dependency legitimately share a
// manifest location. Collapsing them would lose real results.
func TestBuildScanResultKeepsDistinctCVEsInOneComponent(t *testing.T) {
	pkgFinding := func(id, cve string) model.NormalizedFinding {
		nf := model.NormalizedFinding{}
		nf.NormalizedTask.FindingID = id
		nf.NormalizedRemediation.Description = "vulnerable dependency"
		nf.NormalizedRemediation.ToolSeverity = "HIGH"
		nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs = []string{cve}
		file, line := "package-lock.json", 1
		nf.NormalizedTask.ExtraData.CodeLocation.FileName = &file
		nf.NormalizedTask.ExtraData.CodeLocation.StartLine = &line
		return nf
	}

	result := BuildScanResult("scan-1", []model.NormalizedFinding{
		pkgFinding("finding-1", "CVE-2024-0001"),
		pkgFinding("finding-2", "CVE-2024-0002"),
	}, false, false)

	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (two CVEs in one component are two findings)", len(result.Findings))
	}
}

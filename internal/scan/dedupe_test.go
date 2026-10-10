package scan

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func codeFinding(id, file string, line, col int, sev model.Severity, cwes ...string) model.Finding {
	return model.Finding{
		ID:          id,
		File:        file,
		StartLine:   line,
		StartColumn: col,
		Severity:    sev,
		CWEs:        cwes,
		Type:        model.FindingTypeVulnerability,
	}
}

func ids(findings []model.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}

func TestDeduplicateFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		wantIDs  []string
	}{
		{
			name: "same location, same CWE, different prose collapses",
			// The observed shape: one `shell=True` line returned twice, same file,
			// line and start column, same CWE, differing only in wording and end
			// column.
			findings: []model.Finding{
				codeFinding("zz-narrative", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78"),
				codeFinding("CWE-78-canonical", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78"),
			},
			wantIDs: []string{"CWE-78-canonical"},
		},
		{
			name: "smallest ID wins regardless of arrival order",
			findings: []model.Finding{
				codeFinding("CWE-78-canonical", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78"),
				codeFinding("zz-narrative", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78"),
			},
			wantIDs: []string{"CWE-78-canonical"},
		},
		{
			// The real duplicates disagree on the CWE's descriptive tail, so identity
			// has to be the identifier alone.
			name: "same CWE identifier, different wording collapses",
			findings: []model.Finding{
				codeFinding("b", "src/a.py", 22, 5, model.SeverityHigh,
					"CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
				codeFinding("a", "src/a.py", 22, 5, model.SeverityHigh,
					"CWE-78: Improper Neutralization of Special Elements used in an OS Command ('Command Injection')"),
			},
			wantIDs: []string{"a"},
		},
		{
			name: "CWE order does not matter",
			findings: []model.Finding{
				codeFinding("b", "src/a.py", 3, 1, model.SeverityHigh, "CWE-78", "CWE-89"),
				codeFinding("a", "src/a.py", 3, 1, model.SeverityHigh, "CWE-89", "CWE-78"),
			},
			wantIDs: []string{"a"},
		},
		{
			name: "different CWE at one location is kept",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 3, 1, model.SeverityHigh, "CWE-78"),
				codeFinding("b", "src/a.py", 3, 1, model.SeverityHigh, "CWE-89"),
			},
			wantIDs: []string{"a", "b"},
		},
		{
			name: "different severity at one location is kept",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 3, 1, model.SeverityHigh, "CWE-78"),
				codeFinding("b", "src/a.py", 3, 1, model.SeverityMedium, "CWE-78"),
			},
			wantIDs: []string{"a", "b"},
		},
		{
			name: "different column is kept",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 3, 1, model.SeverityHigh, "CWE-78"),
				codeFinding("b", "src/a.py", 3, 40, model.SeverityHigh, "CWE-78"),
			},
			wantIDs: []string{"a", "b"},
		},
		{
			name: "package findings without a location are never collapsed",
			// Several CVEs in one dependency share a severity and carry no code
			// location; collapsing them would discard real results.
			findings: []model.Finding{
				{ID: "p1", Severity: model.SeverityCritical, Type: model.FindingTypeSCA, CVEs: []string{"CVE-2023-1"}},
				{ID: "p2", Severity: model.SeverityCritical, Type: model.FindingTypeSCA, CVEs: []string{"CVE-2023-2"}},
			},
			wantIDs: []string{"p1", "p2"},
		},
		{
			name: "package findings sharing a manifest line are never collapsed",
			findings: []model.Finding{
				{ID: "p1", File: "requirements.txt", StartLine: 4, Severity: model.SeverityHigh, CVEs: []string{"CVE-2023-1"}},
				{ID: "p2", File: "requirements.txt", StartLine: 4, Severity: model.SeverityHigh, CVEs: []string{"CVE-2023-2"}},
			},
			wantIDs: []string{"p1", "p2"},
		},
		{
			name:     "a single finding is returned untouched",
			findings: []model.Finding{codeFinding("a", "src/a.py", 1, 1, model.SeverityLow, "CWE-20")},
			wantIDs:  []string{"a"},
		},
		{
			name:     "no findings",
			findings: nil,
			wantIDs:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(DeduplicateFindings(tt.findings))
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("got %v, want %v", got, tt.wantIDs)
			}
			for i := range got {
				if got[i] != tt.wantIDs[i] {
					t.Errorf("got %v, want %v", got, tt.wantIDs)
					break
				}
			}
		})
	}
}

func TestDeduplicateFindingsPreservesOrder(t *testing.T) {
	// Report order is what the user reads, so a collapse must not reshuffle the
	// findings around it.
	findings := []model.Finding{
		codeFinding("first", "src/a.py", 1, 1, model.SeverityHigh, "CWE-20"),
		codeFinding("zz", "src/b.py", 2, 1, model.SeverityHigh, "CWE-78"),
		codeFinding("aa", "src/b.py", 2, 1, model.SeverityHigh, "CWE-78"),
		codeFinding("last", "src/c.py", 3, 1, model.SeverityHigh, "CWE-89"),
	}
	got := ids(DeduplicateFindings(findings))
	want := []string{"first", "aa", "last"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestCWEIdentifier(t *testing.T) {
	tests := map[string]string{
		"CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')": "CWE-78",
		"CWE-89":      "CWE-89",
		"cwe-20":      "CWE-20",
		"  CWE-522  ": "CWE-522",
		// Not an identifier: keep it whole so it still distinguishes findings.
		"Insecure Design":      "Insecure Design",
		"A03:2021 - Injection": "A03:2021 - Injection",
	}
	for in, want := range tests {
		if got := cweIdentifier(in); got != want {
			t.Errorf("cweIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDeduplicateFindingsKeepsDistinctTypes covers the reported failure: identity
// omitted Type/FindingCategory, so two genuinely different findings reported at one
// location collapsed and the lexicographically smaller ID won -- which could
// discard the exposed-secret finding.
func TestDeduplicateFindingsKeepsDistinctTypes(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		wantIDs  []string
	}{
		{
			// A hard-coded credential in a config file is commonly reported both as
			// an exposed secret and as a misconfiguration at the same file, line and
			// column, both HIGH, neither carrying a CWE. Collapsing them here keeps
			// "aaa-misconfig" and drops the secret.
			name: "secret and misconfig at one location both survive",
			findings: []model.Finding{
				func() model.Finding {
					f := codeFinding("aaa-misconfig", "deploy/values.yaml", 12, 3, model.SeverityHigh)
					f.Type = model.FindingTypeMisconfig
					f.FindingCategory = "INFRA_AS_CODE"
					return f
				}(),
				func() model.Finding {
					f := codeFinding("zzz-secret", "deploy/values.yaml", 12, 3, model.SeverityHigh)
					f.Type = model.FindingTypeSecret
					f.FindingCategory = "SECRET_EXPOSURE"
					return f
				}(),
			},
			wantIDs: []string{"aaa-misconfig", "zzz-secret"},
		},
		{
			// Same type, but the backend distinguished them by category.
			name: "same type, different finding_category both survive",
			findings: []model.Finding{
				func() model.Finding {
					f := codeFinding("a", "src/a.py", 4, 1, model.SeverityHigh, "CWE-798")
					f.FindingCategory = "CODE_VULNERABILITY"
					return f
				}(),
				func() model.Finding {
					f := codeFinding("b", "src/a.py", 4, 1, model.SeverityHigh, "CWE-798")
					f.FindingCategory = "SECRET_EXPOSURE"
					return f
				}(),
			},
			wantIDs: []string{"a", "b"},
		},
		{
			// Copilot's case: with no column and no CWE, file+line+severity is not
			// specific enough to call two findings the same defect -- two different
			// secrets on one line would collapse.
			name: "no column and no CWE is too unspecific to collapse",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 9, 0, model.SeverityHigh),
				codeFinding("b", "src/a.py", 9, 0, model.SeverityHigh),
			},
			wantIDs: []string{"a", "b"},
		},
		{
			// Still collapses when there is a real discriminator: same CWE, no column.
			name: "no column but a shared CWE still collapses",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 9, 0, model.SeverityHigh, "CWE-78"),
				codeFinding("b", "src/a.py", 9, 0, model.SeverityHigh, "CWE-78"),
			},
			wantIDs: []string{"a"},
		},
		{
			// The dash-separated spelling matcher.go already tolerates has to
			// normalize here too, or real duplicates keep separate keys.
			name: "dash-separated CWE spelling normalizes like matcher.go",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78 - OS Command Injection"),
				codeFinding("b", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78: OS Command Injection"),
			},
			wantIDs: []string{"a"},
		},
		{
			// A bare numeric CWE is the third spelling matcher.go accepts.
			name: "bare numeric CWE normalizes like matcher.go",
			findings: []model.Finding{
				codeFinding("a", "src/a.py", 22, 5, model.SeverityHigh, "78"),
				codeFinding("b", "src/a.py", 22, 5, model.SeverityHigh, "CWE-78"),
			},
			wantIDs: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(DeduplicateFindings(tt.findings))
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("DeduplicateFindings() = %v, want %v", got, tt.wantIDs)
			}
			for i := range got {
				if got[i] != tt.wantIDs[i] {
					t.Fatalf("DeduplicateFindings() = %v, want %v", got, tt.wantIDs)
				}
			}
		})
	}
}

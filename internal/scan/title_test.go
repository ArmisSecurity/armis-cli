package scan

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestGenerateFindingTitle(t *testing.T) {
	tests := []struct {
		name    string
		finding *model.Finding
		want    string
	}{
		{
			name: "SCA with single CVE",
			finding: &model.Finding{
				Type: model.FindingTypeSCA,
				CVEs: []string{"CVE-2024-1234"},
			},
			want: "CVE-2024-1234",
		},
		{
			name: "SCA with multiple CVEs",
			finding: &model.Finding{
				Type: model.FindingTypeSCA,
				CVEs: []string{"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"},
			},
			want: "CVE-2024-1234 (+2 more)",
		},
		{
			name: "SCA with two CVEs",
			finding: &model.Finding{
				Type: model.FindingTypeSCA,
				CVEs: []string{"CVE-2024-1234", "CVE-2024-5678"},
			},
			want: "CVE-2024-1234 (+1 more)",
		},
		{
			name: "SCA with no CVEs falls through",
			finding: &model.Finding{
				Type:        model.FindingTypeSCA,
				Description: "Outdated dependency",
			},
			want: "Outdated dependency",
		},
		{
			name: "OWASP category with title and CWE",
			finding: &model.Finding{
				OWASPCategories: []model.OWASPCategory{{ID: "A03", Title: "Injection"}},
				CWEs:            []string{"CWE-89"},
			},
			want: "Injection (CWE-89)",
		},
		{
			name: "OWASP category title without CWE",
			finding: &model.Finding{
				OWASPCategories: []model.OWASPCategory{{ID: "A07", Title: "Broken Authentication"}},
			},
			want: "Broken Authentication",
		},
		{
			name: "OWASP category with empty title falls through",
			finding: &model.Finding{
				OWASPCategories: []model.OWASPCategory{{ID: "A03", Title: ""}},
				Description:     "SQL injection vulnerability",
			},
			want: "SQL injection vulnerability",
		},
		{
			name: "Secret type",
			finding: &model.Finding{
				Type: model.FindingTypeSecret,
			},
			want: "Exposed Secret",
		},
		{
			name: "Description with sentence ending",
			finding: &model.Finding{
				Description: "SQL injection found. More details follow here.",
			},
			want: "SQL injection found",
		},
		{
			name: "Description single sentence with trailing period",
			finding: &model.Finding{
				Description: "Hardcoded credential.",
			},
			want: "Hardcoded credential",
		},
		{
			name: "Description multiline",
			finding: &model.Finding{
				Description: "First line\nSecond line\nThird line",
			},
			want: "First line",
		},
		{
			name: "Description without period or newline",
			finding: &model.Finding{
				Description: "Use of insecure random number generator",
			},
			want: "Use of insecure random number generator",
		},
		{
			name: "Category fallback",
			finding: &model.Finding{
				FindingCategory: "CODE_VULNERABILITY",
			},
			want: "Code Vulnerability",
		},
		{
			name:    "Empty finding returns default",
			finding: &model.Finding{},
			want:    "Security Finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateFindingTitle(tt.finding)
			if got != tt.want {
				t.Errorf("GenerateFindingTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}

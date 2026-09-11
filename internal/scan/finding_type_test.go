package scan

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestDeriveFindingType(t *testing.T) {
	tests := []struct {
		name            string
		hasCVEs         bool
		hasSecret       bool
		findingCategory string
		want            model.FindingType
	}{
		{
			// hasSecret is set whenever the captured blob contains a secret, so it
			// must not override an explicit code-vulnerability category: an
			// injection finding whose snippet happens to include a hard-coded
			// token is still an injection finding.
			name:            "code vulnerability category beats a secret in the blob",
			hasCVEs:         true,
			hasSecret:       true,
			findingCategory: "CODE_VULNERABILITY",
			want:            model.FindingTypeVulnerability,
		},
		{
			name:            "secret overrides CVEs",
			hasCVEs:         true,
			hasSecret:       true,
			findingCategory: "",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "lowercase vulnerability category beats a secret in the blob",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "vulnerability",
			want:            model.FindingTypeVulnerability,
		},
		{
			// A dependency finding whose captured blob happens to contain a token is
			// still a dependency finding. Any category that maps to a specific type
			// is the more specific signal and wins over the blob-level flag.
			name:            "package vulnerability category beats a secret in the blob",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "CODE_PACKAGE_VULNERABILITY",
			want:            model.FindingTypeSCA,
		},
		{
			// The reported failure: a Terraform/K8s misconfiguration whose blob has an
			// unrelated token a few lines away must not become an exposed secret --
			// with --fail-on-secret default-on that fails a build over a misconfig.
			name:            "infra-as-code category beats a secret in the blob",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "INFRA_AS_CODE",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "lowercase misconfig category beats a secret in the blob",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "misconfig",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "license category beats a secret in the blob",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "LICENSE_COMPLIANCE_RISK",
			want:            model.FindingTypeLicense,
		},
		{
			// No recognised category means no more specific signal than the flag, so
			// the flag still rescues the finding rather than defaulting it to SCA.
			name:            "secret still overrides an unrecognised category",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "UNKNOWN_CATEGORY",
			want:            model.FindingTypeSecret,
		},
		{
			// What the repository scanner actually emits for an exposed secret.
			name:            "SECRET_EXPOSURE category results in secret",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "SECRET_EXPOSURE",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "CVEs result in vulnerability",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "",
			want:            model.FindingTypeVulnerability,
		},
		{
			name:            "CODE_VULNERABILITY category results in vulnerability",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "CODE_VULNERABILITY",
			want:            model.FindingTypeVulnerability,
		},
		{
			name:            "lowercase vulnerability category results in vulnerability",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "vulnerability",
			want:            model.FindingTypeVulnerability,
		},
		{
			name:            "CODE_PACKAGE_VULNERABILITY category results in SCA",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "CODE_PACKAGE_VULNERABILITY",
			want:            model.FindingTypeSCA,
		},
		{
			name:            "lowercase sca category results in SCA",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "sca",
			want:            model.FindingTypeSCA,
		},
		{
			name:            "INFRA_AS_CODE category results in misconfig",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "INFRA_AS_CODE",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "lowercase misconfig category results in misconfig",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "misconfig",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "lowercase secret category results in secret",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "secret",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "uppercase SECRET category results in secret",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "SECRET",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "default to SCA for unknown category",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "UNKNOWN_CATEGORY",
			want:            model.FindingTypeSCA,
		},
		{
			name:            "default to SCA for empty category",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "",
			want:            model.FindingTypeSCA,
		},
		{
			// The CVE list discriminates inside the dependency space: a package
			// finding that names CVEs is reported as a vulnerability, not as SCA.
			name:            "CVEs upgrade a package category to vulnerability",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "CODE_PACKAGE_VULNERABILITY",
			want:            model.FindingTypeVulnerability,
		},
		{
			// ...but it does not override a non-dependency classification. An
			// exposed-secret category with a CVE attached is still an exposed secret.
			name:            "CVEs do not override a secret category",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "SECRET_EXPOSURE",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "CVEs do not override a license category",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "LICENSE_COMPLIANCE_RISK",
			want:            model.FindingTypeLicense,
		},
		{
			name:            "CVEs do not override an infra-as-code category",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "INFRA_AS_CODE",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "LICENSE_COMPLIANCE_RISK category results in license",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "LICENSE_COMPLIANCE_RISK",
			want:            model.FindingTypeLicense,
		},
		{
			name:            "lowercase license category results in license",
			hasCVEs:         false,
			hasSecret:       false,
			findingCategory: "license",
			want:            model.FindingTypeLicense,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveFindingType(tt.hasCVEs, tt.hasSecret, tt.findingCategory)
			if got != tt.want {
				t.Errorf("DeriveFindingType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSecretCategoryClassificationIsShared pins the two secret-category readers to
// one source of truth. IsSecretExposure (which exempts a finding from the
// exploitability filter) and DeriveFindingType (which types it) must agree on every
// category: if the backend adds a third spelling for secrets and only one of them
// learns about it, a finding gets exempted from filtering but typed as something
// else -- or worse, typed as a secret and still dropped by the filter.
func TestSecretCategoryClassificationIsShared(t *testing.T) {
	categories := []string{
		"SECRET", "SECRET_EXPOSURE", "secret", "secret_exposure", "  SECRET  ",
		"CODE_VULNERABILITY", "VULNERABILITY", "CODE_PACKAGE_VULNERABILITY", "SCA",
		"INFRA_AS_CODE", "MISCONFIG", "LICENSE_COMPLIANCE_RISK", "LICENSE",
		"UNKNOWN_CATEGORY", "",
	}

	for _, category := range categories {
		t.Run(category, func(t *testing.T) {
			nf := model.NormalizedFinding{}
			nf.NormalizedRemediation.FindingCategory = category

			typedAsSecret := DeriveFindingType(false, false, category) == model.FindingTypeSecret
			if got := IsSecretExposure(nf); got != typedAsSecret {
				t.Errorf("IsSecretExposure(%q) = %v, but DeriveFindingType says secret = %v",
					category, got, typedAsSecret)
			}
		})
	}
}

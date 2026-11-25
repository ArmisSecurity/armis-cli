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
			name:            "secret overrides everything",
			hasCVEs:         true,
			hasSecret:       true,
			findingCategory: "CODE_VULNERABILITY",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "secret overrides CVEs",
			hasCVEs:         true,
			hasSecret:       true,
			findingCategory: "",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "secret overrides category",
			hasCVEs:         false,
			hasSecret:       true,
			findingCategory: "CODE_VULNERABILITY",
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
			name:            "CVEs override category",
			hasCVEs:         true,
			hasSecret:       false,
			findingCategory: "CODE_PACKAGE_VULNERABILITY",
			want:            model.FindingTypeVulnerability,
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
		// The categories Armis Cloud serves (moose-common's FindingCategory),
		// and the finer ones .armisignore's category: directives name.
		{
			name:            "INFRA_AS_CODE_MISCONFIGURATION category results in misconfig",
			findingCategory: "INFRA_AS_CODE_MISCONFIGURATION",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "POLICY_VIOLATION category results in misconfig",
			findingCategory: "POLICY_VIOLATION",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "CI_CD_SECURITY_MISCONFIGURATION category results in misconfig",
			findingCategory: "CI_CD_SECURITY_MISCONFIGURATION",
			want:            model.FindingTypeMisconfig,
		},
		{
			name:            "LICENSE_COMPLIANCE category results in license",
			findingCategory: "LICENSE_COMPLIANCE",
			want:            model.FindingTypeLicense,
		},
		{
			name:            "SECRET_EXPOSURE category results in secret",
			findingCategory: "SECRET_EXPOSURE",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "HARDCODED_SECRET_EXPOSURE category results in secret",
			findingCategory: "HARDCODED_SECRET_EXPOSURE",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "CREDENTIAL_LEAKAGE category results in secret",
			findingCategory: "CREDENTIAL_LEAKAGE",
			want:            model.FindingTypeSecret,
		},
		{
			name:            "CVEs override a misconfiguration category",
			hasCVEs:         true,
			findingCategory: "INFRA_AS_CODE_MISCONFIGURATION",
			want:            model.FindingTypeVulnerability,
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

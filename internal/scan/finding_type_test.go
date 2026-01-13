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

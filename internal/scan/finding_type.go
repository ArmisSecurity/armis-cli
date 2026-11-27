package scan

import (
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// DeriveFindingType classifies a finding: a secret, then one with CVEs, then
// by its finding category. The categories are the ones Armis Cloud serves
// (INFRA_AS_CODE_MISCONFIGURATION, LICENSE_COMPLIANCE, SECRET_EXPOSURE, …),
// the finer ones of .armisignore's category: vocabulary, and the CLI's own
// type names.
func DeriveFindingType(hasCVEs bool, hasSecret bool, findingCategory string) model.FindingType {
	if hasSecret {
		return model.FindingTypeSecret
	}

	if hasCVEs {
		return model.FindingTypeVulnerability
	}

	category := strings.ToUpper(findingCategory)

	switch category {
	case "CODE_VULNERABILITY", "VULNERABILITY":
		return model.FindingTypeVulnerability
	case "CODE_PACKAGE_VULNERABILITY", "SCA":
		return model.FindingTypeSCA
	case "INFRA_AS_CODE_MISCONFIGURATION", "POLICY_VIOLATION", "CI_CD_SECURITY_MISCONFIGURATION",
		"INFRA_AS_CODE", "MISCONFIG":
		return model.FindingTypeMisconfig
	case "SECRET_EXPOSURE", "HARDCODED_SECRET_EXPOSURE", "CREDENTIAL_LEAKAGE", "SECRET":
		return model.FindingTypeSecret
	case "LICENSE_COMPLIANCE", "LICENSE_COMPLIANCE_RISK", "LICENSE":
		return model.FindingTypeLicense
	default:
		return model.FindingTypeSCA
	}
}

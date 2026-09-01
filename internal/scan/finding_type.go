package scan

import (
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func DeriveFindingType(hasCVEs bool, hasSecret bool, findingCategory string) model.FindingType {
	category := strings.ToUpper(findingCategory)

	// hasSecret comes from the code location, and the backend sets it whenever the
	// blob it captured contains a secret -- not only when the finding is *about*
	// the secret. A SQL injection whose snippet happens to start a few lines above
	// a hard-coded token arrives with hasSecret set, finding_category
	// CODE_VULNERABILITY and a CWE-89 title; classifying that as a secret
	// mis-sorts it everywhere the type is routed on (--group-by, SARIF consumers,
	// dashboards). An explicit code-vulnerability category is the more specific
	// signal, so it wins over the blob-level flag.
	if hasSecret && category != "CODE_VULNERABILITY" && category != "VULNERABILITY" {
		return model.FindingTypeSecret
	}

	if hasCVEs {
		return model.FindingTypeVulnerability
	}

	switch category {
	case "CODE_VULNERABILITY", "VULNERABILITY":
		return model.FindingTypeVulnerability
	case "CODE_PACKAGE_VULNERABILITY", "SCA":
		return model.FindingTypeSCA
	case "INFRA_AS_CODE", "MISCONFIG":
		return model.FindingTypeMisconfig
	// SECRET_EXPOSURE is what the repository scanner actually emits for an exposed
	// secret; without it such a finding fell through to the SCA default and was
	// only rescued by the hasSecret flag above.
	case "SECRET", "SECRET_EXPOSURE":
		return model.FindingTypeSecret
	case "LICENSE_COMPLIANCE_RISK", "LICENSE":
		return model.FindingTypeLicense
	default:
		return model.FindingTypeSCA
	}
}

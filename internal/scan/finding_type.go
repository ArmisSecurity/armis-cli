package scan

import (
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

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
	case "INFRA_AS_CODE", "MISCONFIG":
		return model.FindingTypeMisconfig
	case "SECRET":
		return model.FindingTypeSecret
	default:
		return model.FindingTypeSCA
	}
}

package scan

import (
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// findingTypeByCategory maps every finding_category spelling the backend emits to
// the type it classifies as.
//
// This is the single source of truth for reading finding_category. Both
// DeriveFindingType and IsSecretExposure consult it, so a new category spelling
// cannot be understood by one and not the other -- a divergence that would let a
// finding be exempted from exploitability filtering while typed as something else,
// or typed as a secret and still dropped by the filter.
var findingTypeByCategory = map[string]model.FindingType{
	"CODE_VULNERABILITY":         model.FindingTypeVulnerability,
	"VULNERABILITY":              model.FindingTypeVulnerability,
	"CODE_PACKAGE_VULNERABILITY": model.FindingTypeSCA,
	"SCA":                        model.FindingTypeSCA,
	"INFRA_AS_CODE":              model.FindingTypeMisconfig,
	"MISCONFIG":                  model.FindingTypeMisconfig,
	// SECRET_EXPOSURE is what the repository scanner actually emits for an exposed
	// secret; without it such a finding fell through to the SCA default and was
	// only rescued by the hasSecret flag.
	"SECRET":                  model.FindingTypeSecret,
	"SECRET_EXPOSURE":         model.FindingTypeSecret,
	"LICENSE_COMPLIANCE_RISK": model.FindingTypeLicense,
	"LICENSE":                 model.FindingTypeLicense,
}

// FindingTypeForCategory returns the type a finding_category classifies as, and
// whether the category was recognised at all. Matching is case-insensitive and
// whitespace-tolerant.
func FindingTypeForCategory(findingCategory string) (model.FindingType, bool) {
	t, ok := findingTypeByCategory[normalizeFindingCategory(findingCategory)]
	return t, ok
}

func normalizeFindingCategory(findingCategory string) string {
	return strings.ToUpper(strings.TrimSpace(findingCategory))
}

func DeriveFindingType(hasCVEs bool, hasSecret bool, findingCategory string) model.FindingType {
	categoryType, categoryKnown := FindingTypeForCategory(findingCategory)

	// hasSecret comes from the code location, and the backend sets it whenever the
	// blob it captured contains a secret -- not only when the finding is *about*
	// the secret. A SQL injection whose snippet happens to start a few lines above
	// a hard-coded token arrives with hasSecret set, finding_category
	// CODE_VULNERABILITY and a CWE-89 title; a Terraform misconfiguration with a
	// token a few lines away arrives with hasSecret set and INFRA_AS_CODE.
	// Classifying either as a secret mis-sorts it everywhere the type is routed on
	// (--group-by, SARIF consumers, dashboards) and, with --fail-on-secret on by
	// default, fails a build over a finding that is not an exposed secret. Any
	// recognised category is the more specific signal, so it wins over the
	// blob-level flag; the flag only rescues a finding whose category tells us
	// nothing, which would otherwise default to SCA.
	if categoryKnown {
		// The CVE list discriminates inside the dependency space -- a package
		// finding that names CVEs is reported as a vulnerability rather than as SCA
		// -- but it is not a classification of its own, so it does not override a
		// code, secret, misconfiguration or license category.
		if hasCVEs && categoryType == model.FindingTypeSCA {
			return model.FindingTypeVulnerability
		}
		return categoryType
	}

	// Nothing more specific than the flags is available.
	if hasSecret {
		return model.FindingTypeSecret
	}

	if hasCVEs {
		return model.FindingTypeVulnerability
	}

	return model.FindingTypeSCA
}

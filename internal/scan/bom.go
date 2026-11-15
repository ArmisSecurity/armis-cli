package scan

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// BOM types accepted by --bom. These mirror the backend BomType values
// (Project-Moose moose_common.bom.types) and are sent verbatim in the ingest
// request's bom_types field.
const (
	BOMTypeSBOM  = "sbom"
	BOMTypeAIBOM = "aibom"
	BOMTypeCBOM  = "cbom"
	BOMTypeAll   = "all" // the combined BOM
)

// BOM formats accepted by --bom-format: the four versioned values and the two
// aliases of the backend FormatValue. The value is sent as typed; the server
// resolves an alias per type, as ResolveBOMFormat does.
const (
	BOMFormatCycloneDX17 = "cyclonedx-1.7"
	BOMFormatCycloneDX16 = "cyclonedx-1.6"
	BOMFormatSPDX23      = "spdx-2.3"
	BOMFormatSPDX301     = "spdx-3.0.1"
	BOMFormatCycloneDX   = "cyclonedx" // alias of cyclonedx-1.7
	BOMFormatSPDX        = "spdx"      // alias of spdx-2.3 for sbom, spdx-3.0.1 for aibom
)

// BOMOutputStdout is the --bom-output value that writes the one requested BOM
// to stdout.
const BOMOutputStdout = "-"

// BOMTypeOrder is the order in which BOM types are sent, downloaded and
// reported.
var BOMTypeOrder = []string{BOMTypeSBOM, BOMTypeAIBOM, BOMTypeCBOM, BOMTypeAll}

// BOMFormats lists the --bom-format values, default first.
var BOMFormats = []string{
	BOMFormatCycloneDX17, BOMFormatCycloneDX16, BOMFormatSPDX23, BOMFormatSPDX301,
	BOMFormatCycloneDX, BOMFormatSPDX,
}

// resultKeyStem and variantCode mirror results_key in Project-Moose
// moose_common/bom/constants.py: "<stem>_results" for CycloneDX 1.7, and
// "<stem>_<code>_results" for the other formats.
var resultKeyStem = map[string]string{
	BOMTypeSBOM:  "bom_sbom",
	BOMTypeAIBOM: "aibom",
	BOMTypeCBOM:  "cbom",
	BOMTypeAll:   "bom",
}

var variantCode = map[string]string{
	BOMFormatCycloneDX16: "cdx16",
	BOMFormatSPDX23:      "spdx23",
	BOMFormatSPDX301:     "spdx301",
}

// ValidateBOMFlags checks --bom, --bom-format and --bom-output before any
// network call. bomSet reports whether --bom was given at all, so that
// "--bom=" is told apart from no --bom. It returns the BOM types lower-cased,
// deduplicated and in BOMTypeOrder (nil without --bom), and the lower-cased
// format. --bom-format and --bom-output without --bom are not errors; the
// caller warns about them.
func ValidateBOMFlags(types []string, bomSet bool, format, output string) ([]string, string, error) {
	// The server's format values are case-sensitive, so normalize first, as
	// --sbom-format is.
	format = strings.ToLower(format)
	if !slices.Contains(BOMFormats, format) {
		return nil, format, fmt.Errorf("invalid --bom-format value %q: must be one of %v", format, BOMFormats)
	}
	if !bomSet {
		return nil, format, nil
	}

	seen := make(map[string]bool)
	for _, raw := range types {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			continue
		}
		if !slices.Contains(BOMTypeOrder, t) {
			return nil, format, fmt.Errorf("invalid --bom value %q: must be one of %v", raw, BOMTypeOrder)
		}
		seen[t] = true
	}
	if len(seen) == 0 {
		return nil, format, fmt.Errorf("--bom requires a value: one of %v", BOMTypeOrder)
	}
	normalized := make([]string, 0, len(seen))
	for _, t := range BOMTypeOrder {
		if seen[t] {
			normalized = append(normalized, t)
		}
	}

	for _, t := range normalized {
		if err := checkBOMPair(t, format); err != nil {
			return nil, format, err
		}
	}

	if err := checkBOMOutput(output, normalized); err != nil {
		return nil, format, err
	}
	return normalized, format, nil
}

// checkBOMPair rejects the type and format pairs the server answers with 422
// export_format_unavailable. spdx-3.0.1, and spdx for aibom, pass here: the
// server rejects them until it offers SPDX 3.0.1.
func checkBOMPair(bomType, format string) error {
	isSPDX := format == BOMFormatSPDX || format == BOMFormatSPDX23 || format == BOMFormatSPDX301
	switch {
	case bomType == BOMTypeAIBOM && format == BOMFormatSPDX23:
		return fmt.Errorf("--bom-format %s is not available for --bom %s: the %s's SPDX form is %s",
			format, bomType, BOMLabel(bomType), BOMFormatSPDX301)
	case (bomType == BOMTypeCBOM || bomType == BOMTypeAll) && isSPDX:
		return fmt.Errorf("--bom-format %s is not available for --bom %s: the %s has no SPDX form",
			format, bomType, BOMLabel(bomType))
	}
	return nil
}

// checkBOMOutput checks --bom-output: "-" takes one type, and a path must not
// traverse upward or name an existing file. A missing directory is created at
// download time.
func checkBOMOutput(output string, types []string) error {
	if output == "" {
		return nil
	}
	if output == BOMOutputStdout {
		if len(types) > 1 {
			return fmt.Errorf("--bom-output - takes one BOM type, got %d: %s", len(types), strings.Join(types, ","))
		}
		return nil
	}
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; output is the user's own --bom-output flag
	cleaned, err := util.SanitizePath(output)
	if err != nil {
		return fmt.Errorf("invalid --bom-output value %q: %w", output, err)
	}
	// armis:ignore cwe:22 reason:read-only existence check on a sanitized path from the user's own flag
	info, err := os.Stat(cleaned)
	if err == nil && !info.IsDir() {
		return fmt.Errorf("invalid --bom-output value %q: not a directory", output)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("invalid --bom-output value %q: %w", output, err)
	}
	return nil
}

// ResolveBOMFormat returns the versioned format an alias names for bomType,
// as the server's resolve_format does: cyclonedx is cyclonedx-1.7, and spdx is
// spdx-2.3 for sbom and spdx-3.0.1 for aibom. A versioned value is returned
// unchanged; type and format pairs are checked by ValidateBOMFlags.
func ResolveBOMFormat(bomType, format string) (string, error) {
	switch format {
	case BOMFormatCycloneDX:
		return BOMFormatCycloneDX17, nil
	case BOMFormatSPDX:
		switch bomType {
		case BOMTypeSBOM:
			return BOMFormatSPDX23, nil
		case BOMTypeAIBOM:
			return BOMFormatSPDX301, nil
		}
		return "", fmt.Errorf("--bom-format %s is not available for --bom %s", format, bomType)
	case BOMFormatCycloneDX17, BOMFormatCycloneDX16, BOMFormatSPDX23, BOMFormatSPDX301:
		return format, nil
	}
	return "", fmt.Errorf("unknown BOM format %q", format)
}

// BOMResultKey returns the results key under which the server links the BOM
// of bomType in the resolved format, such as aibom_cdx16_results for
// ("aibom", "cyclonedx-1.6"). It returns "" for an unknown type or format.
func BOMResultKey(bomType, format string) string {
	stem, ok := resultKeyStem[bomType]
	if !ok {
		return ""
	}
	if format == BOMFormatCycloneDX17 {
		return stem + "_results"
	}
	code, ok := variantCode[format]
	if !ok {
		return ""
	}
	return stem + "_" + code + "_results"
}

// BOMFileName returns the file name of a downloaded BOM, such as
// repo-bom-cbom.json. SPDX formats end in .spdx.json, as the --sbom-format
// spdx file does.
func BOMFileName(artifact, bomType, format string) string {
	ext := ".json"
	if strings.HasPrefix(format, BOMFormatSPDX) {
		ext = ".spdx.json"
	}
	return artifact + "-bom-" + bomType + ext
}

// BOMLabel returns the name of a BOM type in messages.
func BOMLabel(bomType string) string {
	switch bomType {
	case BOMTypeSBOM:
		return "SBOM"
	case BOMTypeAIBOM:
		return "AI-BOM"
	case BOMTypeCBOM:
		return "CBOM"
	case BOMTypeAll:
		return "Combined BOM"
	}
	return bomType
}

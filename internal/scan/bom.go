package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/api"
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

// DefaultBOMDir is where BOM files go without --bom-output.
const DefaultBOMDir = ".armis"

// BOMOptions configures the BOM downloads of a scan (--bom, --bom-format,
// --bom-output).
type BOMOptions struct {
	Types  []string  // normalized by cmdutil.ValidateBOMFlags, in BOMTypeOrder
	Format string    // as typed, alias included; resolved per type
	Output string    // directory, BOMOutputStdout, or "" for DefaultBOMDir
	Target string    // the scan target as typed, for the empty-BOM line
	Stdout io.Writer // stdout mode destination; nil means os.Stdout
}

// BOMDownloadError lists the BOM types that could not be downloaded. Err is
// the results-call error when that call failed for every type, else nil.
type BOMDownloadError struct {
	Types []string
	Err   error
}

func (e *BOMDownloadError) Error() string {
	msg := "could not download BOM types " + strings.Join(e.Types, ", ")
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *BOMDownloadError) Unwrap() error { return e.Err }

// SplitBOMError separates the result of SBOMVEXDownloader.Download into the
// BOM types that failed and the error left to print as a warning: the
// results-call error of a *BOMDownloadError, or any other error unchanged.
func SplitBOMError(err error) ([]string, error) {
	var bomErr *BOMDownloadError
	if errors.As(err, &bomErr) {
		return bomErr.Types, bomErr.Err
	}
	return nil, err
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

// ResolveBOMFormat returns the versioned format an alias names for bomType,
// as the server's resolve_format does: cyclonedx is cyclonedx-1.7, and spdx is
// spdx-2.3 for sbom and spdx-3.0.1 for aibom. A versioned value is returned
// unchanged; type and format pairs are checked by cmdutil.ValidateBOMFlags.
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

// maxIndentDepth is the deepest nesting indentBOM pretty-prints. Indenting
// writes a line per value with its depth in spaces, so the output of a deep
// document grows with the square of its depth.
const maxIndentDepth = 64

// indentBOM pretty-prints a valid BOM with IndentJSON when it nests at most
// maxIndentDepth deep, and returns a deeper one unchanged.
func indentBOM(data []byte) []byte {
	if !jsonDepthAtMost(data, maxIndentDepth) {
		return data
	}
	return IndentJSON(data)
}

// jsonDepthAtMost reports whether the objects and arrays of a valid JSON
// document nest at most limit deep. Brackets inside strings do not count.
func jsonDepthAtMost(data []byte, limit int) bool {
	depth := 0
	inString, escaped := false, false
	for _, c := range data {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			depth++
			if depth > limit {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

// bomIsEmpty reports whether the BOM of bomType lists nothing. With a
// bom_summary the server's status decides: its SPDX documents always name the
// scan root as a package, so the document cannot tell. Without one,
// isEmptyBOM reads the document.
func bomIsEmpty(summary *api.BOMSummary, bomType string, data []byte, format string) bool {
	if summary != nil {
		st, ok := summary.TypeStatus(bomType)
		return ok && st.Status == api.BOMStatusEmpty
	}
	return isEmptyBOM(data, format)
}

// isEmptyBOM reports whether a BOM lists nothing: no components and no
// services for CycloneDX, no packages for SPDX 2.3. Input that is not a JSON
// object, and SPDX 3.0.1 (a JSON-LD graph without top-level lists), is not
// called empty. It is the fallback for a results response without
// bom_summary.
func isEmptyBOM(data []byte, format string) bool {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	switch format {
	case BOMFormatSPDX23:
		return isEmptyList(doc["packages"])
	case BOMFormatSPDX301:
		return false
	}
	return isEmptyList(doc["components"]) && isEmptyList(doc["services"])
}

// isEmptyList reports whether a JSON value is absent, null or an empty array.
func isEmptyList(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return false
	}
	return len(items) == 0
}

// emptyBOMMessage is the stderr line for an empty BOM of bomType.
func emptyBOMMessage(bomType, target string) string {
	switch bomType {
	case BOMTypeAIBOM:
		return "No AI components found in " + target
	case BOMTypeCBOM:
		return "No crypto components found in " + target
	case BOMTypeSBOM:
		return "No packages found in " + target
	}
	return "No components found in " + target
}

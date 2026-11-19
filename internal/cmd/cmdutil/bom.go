package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// BOMFlagNames names the flags that carry the BOM types, format and output,
// for the messages of NormalizeBOMFlags and ValidateBOMFlags. DefaultTypes
// marks types the user did not give, so a refused pair says they are the
// default.
type BOMFlagNames struct {
	Types, Format, Output string
	DefaultTypes          bool
}

// ScanBOMFlags are the BOM flags of the scan commands.
var ScanBOMFlags = BOMFlagNames{Types: "--bom", Format: "--bom-format", Output: "--bom-output"}

// BOMCommandFlags are the flags of bom repo and bom image.
var BOMCommandFlags = BOMFlagNames{Types: "--type", Format: "--format", Output: "--output"}

// NormalizeBOMFlags checks the BOM type and format values before any
// network call. Every scan subcommand runs it, as it does the --sbom-format
// check, and so do the bom subcommands. bomSet reports whether the types flag
// was given at all, so that "--bom=" is told apart from no --bom. It returns
// the BOM types lower-cased, deduplicated and in scan.BOMTypeOrder (nil
// without types), and the lower-cased format. --bom-format and --bom-output
// without --bom are not errors; the caller warns about them. names gives the
// flag names for the messages.
func NormalizeBOMFlags(names BOMFlagNames, types []string, bomSet bool, format string) ([]string, string, error) {
	// The server's format values are case-sensitive, so normalize first, as
	// --sbom-format is.
	format = strings.ToLower(format)
	if !slices.Contains(scan.BOMFormats, format) {
		return nil, format, fmt.Errorf("invalid %s value %q: must be one of %v", names.Format, format, scan.BOMFormats)
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
		if !slices.Contains(scan.BOMTypeOrder, t) {
			return nil, format, fmt.Errorf("invalid %s value %q: must be one of %v", names.Types, raw, scan.BOMTypeOrder)
		}
		seen[t] = true
	}
	if len(seen) == 0 {
		return nil, format, fmt.Errorf("%s requires a value: one of %v", names.Types, scan.BOMTypeOrder)
	}
	normalized := make([]string, 0, len(seen))
	for _, t := range scan.BOMTypeOrder {
		if seen[t] {
			normalized = append(normalized, t)
		}
	}
	return normalized, format, nil
}

// ValidateBOMFlags checks what a BOM download needs, before any network call:
// each type and format pair, and the output. types and format come from
// NormalizeBOMFlags; without types there is nothing to check. scan repo, scan
// image and the bom subcommands run it; the other scan subcommands ignore the
// BOM flags. names gives the flag names for the messages.
func ValidateBOMFlags(names BOMFlagNames, types []string, format, output string) error {
	if len(types) == 0 {
		return nil
	}
	for _, t := range types {
		if err := checkBOMPair(names, t, format); err != nil {
			return err
		}
	}
	return checkBOMOutput(names, output, types)
}

// checkBOMPair rejects the type and format pairs the server answers with 422
// export_format_unavailable. spdx-3.0.1, and spdx for aibom, pass here: the
// server rejects them until it offers SPDX 3.0.1.
func checkBOMPair(names BOMFlagNames, bomType, format string) error {
	typeArg := names.Types + " " + bomType
	if names.DefaultTypes {
		typeArg += " (the default)"
	}
	switch {
	case bomType == scan.BOMTypeAIBOM && format == scan.BOMFormatSPDX23:
		return fmt.Errorf("%s %s is not available for %s: the %s's SPDX form is %s",
			names.Format, format, typeArg, scan.BOMLabel(bomType), scan.BOMFormatSPDX301)
	case (bomType == scan.BOMTypeCBOM || bomType == scan.BOMTypeAll) && scan.IsSPDXFormat(format):
		return fmt.Errorf("%s %s is not available for %s: the %s has no SPDX form",
			names.Format, format, typeArg, scan.BOMLabel(bomType))
	}
	return nil
}

// checkBOMOutput checks the output: "-" takes one type, and a path must not
// traverse upward or name an existing file. A missing directory is created at
// download time.
func checkBOMOutput(names BOMFlagNames, output string, types []string) error {
	if output == "" {
		return nil
	}
	if output == scan.BOMOutputStdout {
		if len(types) > 1 {
			return fmt.Errorf("%s - takes one BOM type, got %d: %s", names.Output, len(types), strings.Join(types, ","))
		}
		return nil
	}
	// armis:ignore cwe:22 reason:SanitizePath IS the path traversal prevention; output is the user's own output flag
	cleaned, err := util.SanitizePath(output)
	if err != nil {
		return fmt.Errorf("invalid %s value %q: %w", names.Output, output, err)
	}
	// armis:ignore cwe:22 reason:read-only existence check on a sanitized path from the user's own flag
	info, err := os.Stat(cleaned)
	if err == nil && !info.IsDir() {
		return fmt.Errorf("invalid %s value %q: not a directory", names.Output, output)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("invalid %s value %q: %w", names.Output, output, err)
	}
	return nil
}

// RefuseFileNameOutput refuses an output directory that does not exist and
// ends in .json: it is most likely meant as a file name, and would be created
// as a directory holding the BOM file. An existing directory passes, as do
// "" and "-". The hint offers stdout only for one type, the only case it
// takes. bom repo and bom image run it after ValidateBOMFlags.
func RefuseFileNameOutput(names BOMFlagNames, output string, types []string) error {
	if output == "" || output == scan.BOMOutputStdout || !strings.EqualFold(filepath.Ext(output), ".json") {
		return nil
	}
	// armis:ignore cwe:22 reason:read-only existence check; ValidateBOMFlags has sanitized the user's own flag
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if len(types) == 1 {
		return fmt.Errorf("invalid %s value %q: %s takes a directory, not a file name; use %s - to write the BOM to stdout, or name a directory",
			names.Output, output, names.Output, names.Output)
	}
	return fmt.Errorf("invalid %s value %q: %s takes a directory, not a file name; name a directory for the %d BOM files",
		names.Output, output, names.Output, len(types))
}

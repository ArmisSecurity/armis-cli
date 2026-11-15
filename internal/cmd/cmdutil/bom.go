package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// NormalizeBOMFlags checks the --bom and --bom-format values before any
// network call. Every scan subcommand runs it, as it does the --sbom-format
// check. bomSet reports whether --bom was given at all, so that "--bom=" is
// told apart from no --bom. It returns the BOM types lower-cased, deduplicated
// and in scan.BOMTypeOrder (nil without --bom), and the lower-cased format.
// --bom-format and --bom-output without --bom are not errors; the caller warns
// about them.
func NormalizeBOMFlags(types []string, bomSet bool, format string) ([]string, string, error) {
	// The server's format values are case-sensitive, so normalize first, as
	// --sbom-format is.
	format = strings.ToLower(format)
	if !slices.Contains(scan.BOMFormats, format) {
		return nil, format, fmt.Errorf("invalid --bom-format value %q: must be one of %v", format, scan.BOMFormats)
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
			return nil, format, fmt.Errorf("invalid --bom value %q: must be one of %v", raw, scan.BOMTypeOrder)
		}
		seen[t] = true
	}
	if len(seen) == 0 {
		return nil, format, fmt.Errorf("--bom requires a value: one of %v", scan.BOMTypeOrder)
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
// each type and format pair, and --bom-output. types and format come from
// NormalizeBOMFlags; without types there is nothing to check. Only scan repo
// and scan image run it, as the other scan subcommands ignore the BOM flags.
func ValidateBOMFlags(types []string, format, output string) error {
	if len(types) == 0 {
		return nil
	}
	for _, t := range types {
		if err := checkBOMPair(t, format); err != nil {
			return err
		}
	}
	return checkBOMOutput(output, types)
}

// checkBOMPair rejects the type and format pairs the server answers with 422
// export_format_unavailable. spdx-3.0.1, and spdx for aibom, pass here: the
// server rejects them until it offers SPDX 3.0.1.
func checkBOMPair(bomType, format string) error {
	isSPDX := format == scan.BOMFormatSPDX || format == scan.BOMFormatSPDX23 || format == scan.BOMFormatSPDX301
	switch {
	case bomType == scan.BOMTypeAIBOM && format == scan.BOMFormatSPDX23:
		return fmt.Errorf("--bom-format %s is not available for --bom %s: the %s's SPDX form is %s",
			format, bomType, scan.BOMLabel(bomType), scan.BOMFormatSPDX301)
	case (bomType == scan.BOMTypeCBOM || bomType == scan.BOMTypeAll) && isSPDX:
		return fmt.Errorf("--bom-format %s is not available for --bom %s: the %s has no SPDX form",
			format, bomType, scan.BOMLabel(bomType))
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
	if output == scan.BOMOutputStdout {
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

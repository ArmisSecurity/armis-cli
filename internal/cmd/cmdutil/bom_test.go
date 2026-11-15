package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateBOMFlags(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "boms.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name       string
		types      []string
		bomSet     bool
		format     string
		output     string
		wantTypes  []string
		wantFormat string
		wantErr    string
	}{
		{name: "no --bom", format: "cyclonedx-1.7", wantFormat: "cyclonedx-1.7"},
		{name: "no --bom ignores types", types: []string{"aibom"}, format: "cyclonedx-1.7", wantFormat: "cyclonedx-1.7"},
		{name: "--bom-format and --bom-output without --bom", format: "cyclonedx-1.6", output: dir, wantFormat: "cyclonedx-1.6"},
		{name: "--bom= is an error", types: []string{}, bomSet: true, format: "cyclonedx-1.7",
			wantErr: "--bom requires a value: one of [sbom aibom cbom all]"},
		{name: "only empty items is an error", types: []string{"", " "}, bomSet: true, format: "cyclonedx-1.7",
			wantErr: "--bom requires a value: one of [sbom aibom cbom all]"},
		{name: "case, duplicates and empty items", types: []string{"AIBOM", "aibom", ""}, bomSet: true, format: "cyclonedx-1.7",
			wantTypes: []string{"aibom"}, wantFormat: "cyclonedx-1.7"},
		{name: "put in BOMTypeOrder", types: []string{"cbom", "aibom"}, bomSet: true, format: "cyclonedx-1.7",
			wantTypes: []string{"aibom", "cbom"}, wantFormat: "cyclonedx-1.7"},
		{name: "every type", types: []string{"all", "cbom", "sbom", "aibom"}, bomSet: true, format: "cyclonedx-1.7",
			wantTypes: []string{"sbom", "aibom", "cbom", "all"}, wantFormat: "cyclonedx-1.7"},
		{name: "spaces around items", types: []string{"aibom", " cbom"}, bomSet: true, format: "cyclonedx-1.7",
			wantTypes: []string{"aibom", "cbom"}, wantFormat: "cyclonedx-1.7"},
		{name: "--bom-format is lower-cased", types: []string{"cbom"}, bomSet: true, format: "CycloneDX-1.6",
			wantTypes: []string{"cbom"}, wantFormat: "cyclonedx-1.6"},
		{name: "alias cyclonedx", types: []string{"all"}, bomSet: true, format: "cyclonedx",
			wantTypes: []string{"all"}, wantFormat: "cyclonedx"},
		{name: "unknown type", types: []string{"aibom", "xbom"}, bomSet: true, format: "cyclonedx-1.7",
			wantErr: `invalid --bom value "xbom": must be one of [sbom aibom cbom all]`},
		{name: "unknown format", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.5",
			wantErr: `invalid --bom-format value "cyclonedx-1.5": must be one of [cyclonedx-1.7 cyclonedx-1.6 spdx-2.3 spdx-3.0.1 cyclonedx spdx]`},
		{name: "unknown format without --bom", format: "xml",
			wantErr: `invalid --bom-format value "xml"`},
		{name: "empty format", types: []string{"aibom"}, bomSet: true, format: "",
			wantErr: `invalid --bom-format value ""`},
		{name: "stdout with one type", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.7", output: "-",
			wantTypes: []string{"aibom"}, wantFormat: "cyclonedx-1.7"},
		{name: "stdout with two types", types: []string{"cbom", "aibom"}, bomSet: true, format: "cyclonedx-1.7", output: "-",
			wantErr: "--bom-output - takes one BOM type, got 2: aibom,cbom"},
		{name: "output is a file", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.7", output: file,
			wantErr: fmt.Sprintf("invalid --bom-output value %q: not a directory", file)},
		{name: "output with ..", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.7", output: "../boms",
			wantErr: `invalid --bom-output value "../boms": path traversal detected`},
		{name: "output directory that does not exist yet", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.7",
			output: filepath.Join(dir, "new"), wantTypes: []string{"aibom"}, wantFormat: "cyclonedx-1.7"},
		{name: "existing output directory", types: []string{"aibom"}, bomSet: true, format: "cyclonedx-1.7",
			output: dir, wantTypes: []string{"aibom"}, wantFormat: "cyclonedx-1.7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTypes, gotFormat, err := ValidateBOMFlags(tt.types, tt.bomSet, tt.format, tt.output)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(gotTypes, tt.wantTypes) {
				t.Errorf("types = %v, want %v", gotTypes, tt.wantTypes)
			}
			if gotFormat != tt.wantFormat {
				t.Errorf("format = %q, want %q", gotFormat, tt.wantFormat)
			}
		})
	}
}

func TestValidateBOMFlagsSPDX(t *testing.T) {
	tests := []struct {
		bomType string
		format  string
		wantErr string
	}{
		{"aibom", "spdx-2.3", "--bom-format spdx-2.3 is not available for --bom aibom: the AI-BOM's SPDX form is spdx-3.0.1"},
		{"cbom", "spdx", "--bom-format spdx is not available for --bom cbom: the CBOM has no SPDX form"},
		{"cbom", "spdx-2.3", "--bom-format spdx-2.3 is not available for --bom cbom: the CBOM has no SPDX form"},
		{"cbom", "spdx-3.0.1", "--bom-format spdx-3.0.1 is not available for --bom cbom: the CBOM has no SPDX form"},
		{"all", "spdx", "--bom-format spdx is not available for --bom all: the Combined BOM has no SPDX form"},
		{"all", "spdx-2.3", "--bom-format spdx-2.3 is not available for --bom all: the Combined BOM has no SPDX form"},
		{"all", "spdx-3.0.1", "--bom-format spdx-3.0.1 is not available for --bom all: the Combined BOM has no SPDX form"},
		// Accepted here; the server answers 422 export_format_unavailable for
		// SPDX 3.0.1 until it offers that format.
		{"sbom", "spdx", ""},
		{"sbom", "spdx-2.3", ""},
		{"sbom", "spdx-3.0.1", ""},
		{"aibom", "spdx", ""},
		{"aibom", "spdx-3.0.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.bomType+" "+tt.format, func(t *testing.T) {
			_, _, err := ValidateBOMFlags([]string{tt.bomType}, true, tt.format, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected %s with %s to pass, got: %v", tt.bomType, tt.format, err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}

	t.Run("a rejected pair beside an accepted type", func(t *testing.T) {
		_, _, err := ValidateBOMFlags([]string{"sbom", "cbom"}, true, "spdx", "")
		if err == nil || !strings.Contains(err.Error(), "--bom cbom") {
			t.Fatalf("error = %v, want the cbom pair rejected", err)
		}
	})
}

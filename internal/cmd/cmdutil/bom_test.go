package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// checkBOMFlags runs the checks of scan repo and scan image: NormalizeBOMFlags
// in PersistentPreRunE, then ValidateBOMFlags.
func checkBOMFlags(types []string, bomSet bool, format, output string) ([]string, string, error) {
	types, format, err := NormalizeBOMFlags(ScanBOMFlags, types, bomSet, format)
	if err != nil {
		return nil, format, err
	}
	return types, format, ValidateBOMFlags(ScanBOMFlags, types, format, output)
}

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
			gotTypes, gotFormat, err := checkBOMFlags(tt.types, tt.bomSet, tt.format, tt.output)
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
			_, _, err := checkBOMFlags([]string{tt.bomType}, true, tt.format, "")
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
		_, _, err := checkBOMFlags([]string{"sbom", "cbom"}, true, "spdx", "")
		if err == nil || !strings.Contains(err.Error(), "--bom cbom") {
			t.Fatalf("error = %v, want the cbom pair rejected", err)
		}
	})
}

// TestNormalizeBOMFlagsLeavesPairsAndOutput covers what every scan subcommand
// checks: the values only. A pair the server rejects and an unusable
// --bom-output pass, since scan status and scan sbom ignore them.
func TestNormalizeBOMFlagsLeavesPairsAndOutput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "boms.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	rows := []struct {
		name   string
		types  []string
		format string
		output string
	}{
		{"aibom with spdx-2.3", []string{"aibom"}, "spdx-2.3", ""},
		{"cbom with spdx", []string{"cbom"}, "spdx", ""},
		{"stdout with two types", []string{"aibom", "cbom"}, "cyclonedx-1.7", "-"},
		{"output is a file", []string{"aibom"}, "cyclonedx-1.7", file},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			types, format, err := NormalizeBOMFlags(ScanBOMFlags, row.types, true, row.format)
			if err != nil {
				t.Fatalf("NormalizeBOMFlags: %v, want no error", err)
			}
			if err := ValidateBOMFlags(ScanBOMFlags, types, format, row.output); err == nil {
				t.Fatalf("ValidateBOMFlags passed %s, want an error", row.name)
			}
		})
	}

	t.Run("ValidateBOMFlags without types checks nothing", func(t *testing.T) {
		if err := ValidateBOMFlags(ScanBOMFlags, nil, "spdx", file); err != nil {
			t.Fatalf("ValidateBOMFlags without types: %v, want nil", err)
		}
	})
}

// TestBOMCommandFlagMessages runs the same checks with the flag names of the
// bom subcommands: every message names --type, --format and --output, never
// the scan flags.
func TestBOMCommandFlagMessages(t *testing.T) {
	file := filepath.Join(t.TempDir(), "boms.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	rows := []struct {
		name    string
		types   []string
		format  string
		output  string
		wantErr string
	}{
		{"no value", []string{""}, "cyclonedx-1.7", "", "--type requires a value: one of [sbom aibom cbom all]"},
		{"unknown type", []string{"xbom"}, "cyclonedx-1.7", "", `invalid --type value "xbom": must be one of [sbom aibom cbom all]`},
		{"unknown format", []string{"all"}, "xml", "", `invalid --format value "xml": must be one of [cyclonedx-1.7 cyclonedx-1.6 spdx-2.3 spdx-3.0.1 cyclonedx spdx]`},
		{"aibom with spdx-2.3", []string{"aibom"}, "spdx-2.3", "", "--format spdx-2.3 is not available for --type aibom: the AI-BOM's SPDX form is spdx-3.0.1"},
		{"all with spdx", []string{"all"}, "spdx", "", "--format spdx is not available for --type all: the Combined BOM has no SPDX form"},
		{"stdout with two types", []string{"cbom", "sbom"}, "cyclonedx-1.7", "-", "--output - takes one BOM type, got 2: sbom,cbom"},
		{"output is a file", []string{"all"}, "cyclonedx-1.7", file, fmt.Sprintf("invalid --output value %q: not a directory", file)},
		{"output with ..", []string{"all"}, "cyclonedx-1.7", "../boms", `invalid --output value "../boms": path traversal detected`},
		{"accepted", []string{"sbom", "aibom"}, "spdx", "", ""},
	}
	t.Run("the default type says so", func(t *testing.T) {
		names := BOMCommandFlags
		names.DefaultTypes = true
		err := ValidateBOMFlags(names, []string{"all"}, "spdx", "")
		want := "--format spdx is not available for --type all (the default): the Combined BOM has no SPDX form"
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
	})
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			types, format, err := NormalizeBOMFlags(BOMCommandFlags, row.types, true, row.format)
			if err == nil {
				err = ValidateBOMFlags(BOMCommandFlags, types, format, row.output)
			}
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != row.wantErr {
				t.Fatalf("error = %v, want %q", err, row.wantErr)
			}
			if strings.Contains(err.Error(), "--bom") {
				t.Errorf("error %q names a scan flag", err)
			}
		})
	}
}

func TestRefuseFileNameOutput(t *testing.T) {
	dir := t.TempDir()
	jsonDir := filepath.Join(dir, "boms.json")
	if err := os.Mkdir(jsonDir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const oneTypeHint = "--output takes a directory, not a file name; use --output - to write the BOM to stdout, or name a directory"
	rows := []struct {
		name     string
		output   string
		types    []string
		wantHint string // "" for no error
	}{
		{"unset", "", []string{"all"}, ""},
		{"stdout", "-", []string{"all"}, ""},
		{"a new directory", filepath.Join(dir, "boms"), []string{"all"}, ""},
		{"a new .json path", filepath.Join(dir, "sbom.json"), []string{"sbom"}, oneTypeHint},
		{"a new .JSON path", filepath.Join(dir, "sbom.JSON"), []string{"all"}, oneTypeHint},
		{"an existing directory ending in .json", jsonDir, []string{"all"}, ""},
		{"a new .spdx.json path", filepath.Join(dir, "sbom.spdx.json"), []string{"sbom"}, oneTypeHint},
		{"two types get no stdout hint", filepath.Join(dir, "out.json"), []string{"sbom", "cbom"},
			"--output takes a directory, not a file name; name a directory for the 2 BOM files"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := RefuseFileNameOutput(BOMCommandFlags, row.output, row.types)
			if (err != nil) != (row.wantHint != "") {
				t.Fatalf("RefuseFileNameOutput(%q) = %v, want error %v", row.output, err, row.wantHint != "")
			}
			if err != nil && !strings.HasSuffix(err.Error(), row.wantHint) {
				t.Errorf("error = %q, want it to end with %q", err, row.wantHint)
			}
		})
	}
}

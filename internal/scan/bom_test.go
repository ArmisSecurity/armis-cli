package scan

import (
	"bytes"
	"errors"
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

func TestResolveBOMFormat(t *testing.T) {
	tests := []struct {
		bomType, format, want string
		wantErr               bool
	}{
		{"sbom", "spdx", "spdx-2.3", false},
		{"aibom", "spdx", "spdx-3.0.1", false},
		{"all", "cyclonedx", "cyclonedx-1.7", false},
		{"cbom", "cyclonedx-1.6", "cyclonedx-1.6", false},
		{"sbom", "spdx-2.3", "spdx-2.3", false},
		{"aibom", "cyclonedx-1.7", "cyclonedx-1.7", false},
		{"cbom", "spdx", "", true},
		{"all", "spdx", "", true},
		{"sbom", "xml", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.bomType+" "+tt.format, func(t *testing.T) {
			got, err := ResolveBOMFormat(tt.bomType, tt.format)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ResolveBOMFormat(%q, %q) = %q, want %q", tt.bomType, tt.format, got, tt.want)
			}
		})
	}
}

// bomKeyCases are the type and resolved format pairs the server stores, with
// the results key of Project-Moose results_key and the file armis-cli writes.
var bomKeyCases = []struct {
	bomType, format, key, file string
}{
	{"sbom", "cyclonedx-1.7", "bom_sbom_results", "repo-bom-sbom.json"},
	{"sbom", "cyclonedx-1.6", "bom_sbom_cdx16_results", "repo-bom-sbom.json"},
	{"sbom", "spdx-2.3", "bom_sbom_spdx23_results", "repo-bom-sbom.spdx.json"},
	{"sbom", "spdx-3.0.1", "bom_sbom_spdx301_results", "repo-bom-sbom.spdx.json"},
	{"aibom", "cyclonedx-1.7", "aibom_results", "repo-bom-aibom.json"},
	{"aibom", "cyclonedx-1.6", "aibom_cdx16_results", "repo-bom-aibom.json"},
	{"aibom", "spdx-3.0.1", "aibom_spdx301_results", "repo-bom-aibom.spdx.json"},
	{"cbom", "cyclonedx-1.7", "cbom_results", "repo-bom-cbom.json"},
	{"cbom", "cyclonedx-1.6", "cbom_cdx16_results", "repo-bom-cbom.json"},
	{"all", "cyclonedx-1.7", "bom_results", "repo-bom-all.json"},
	{"all", "cyclonedx-1.6", "bom_cdx16_results", "repo-bom-all.json"},
}

func TestBOMResultKey(t *testing.T) {
	for _, tt := range bomKeyCases {
		if got := BOMResultKey(tt.bomType, tt.format); got != tt.key {
			t.Errorf("BOMResultKey(%q, %q) = %q, want %q", tt.bomType, tt.format, got, tt.key)
		}
	}
	for _, bad := range [][2]string{{"xbom", "cyclonedx-1.7"}, {"cbom", "cyclonedx"}, {"sbom", "spdx"}} {
		if got := BOMResultKey(bad[0], bad[1]); got != "" {
			t.Errorf("BOMResultKey(%q, %q) = %q, want empty", bad[0], bad[1], got)
		}
	}
}

func TestBOMFileName(t *testing.T) {
	for _, tt := range bomKeyCases {
		if got := BOMFileName("repo", tt.bomType, tt.format); got != tt.file {
			t.Errorf("BOMFileName(repo, %q, %q) = %q, want %q", tt.bomType, tt.format, got, tt.file)
		}
	}
}

func TestBOMLabel(t *testing.T) {
	want := map[string]string{"sbom": "SBOM", "aibom": "AI-BOM", "cbom": "CBOM", "all": "Combined BOM"}
	for bomType, label := range want {
		if got := BOMLabel(bomType); got != label {
			t.Errorf("BOMLabel(%q) = %q, want %q", bomType, got, label)
		}
	}
}

func TestIsEmptyBOM(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		format string
		want   bool
	}{
		{"CycloneDX without lists", `{"bomFormat":"CycloneDX"}`, "cyclonedx-1.7", true},
		{"CycloneDX with empty lists", `{"components":[],"services":[]}`, "cyclonedx-1.6", true},
		{"CycloneDX with null components", `{"components":null}`, "cyclonedx-1.7", true},
		{"CycloneDX with a component", `{"components":[{"name":"a"}]}`, "cyclonedx-1.7", false},
		{"CycloneDX with only a service", `{"components":[],"services":[{"name":"s"}]}`, "cyclonedx-1.7", false},
		{"SPDX 2.3 without packages", `{"spdxVersion":"SPDX-2.3"}`, "spdx-2.3", true},
		{"SPDX 2.3 with empty packages", `{"packages":[]}`, "spdx-2.3", true},
		{"SPDX 2.3 with a package", `{"packages":[{"name":"p"}]}`, "spdx-2.3", false},
		{"SPDX 2.3 ignores components", `{"components":[{"name":"a"}]}`, "spdx-2.3", true},
		{"SPDX 3.0.1 is not checked", `{"@graph":[]}`, "spdx-3.0.1", false},
		{"not JSON", `<bom/>`, "cyclonedx-1.7", false},
		{"a JSON array", `[]`, "cyclonedx-1.7", false},
		{"components not a list", `{"components":{}}`, "cyclonedx-1.7", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyBOM([]byte(tt.data), tt.format); got != tt.want {
				t.Errorf("isEmptyBOM(%s, %s) = %v, want %v", tt.data, tt.format, got, tt.want)
			}
		})
	}
}

func TestJSONDepthAtMost(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		limit int
		want  bool
	}{
		{"a scalar", `1`, 0, true},
		{"an object at the limit", `{"a":[1]}`, 2, true},
		{"one level over", `{"a":[[1]]}`, 2, false},
		{"siblings do not add up", `[[1],[2],{"a":3}]`, 2, true},
		{"brackets in a string do not count", `{"a":"[[[{{{"}`, 1, true},
		{"an escaped quote stays in the string", `{"a":"\"[[["}`, 1, true},
		{"an escaped backslash ends before the quote", `{"a":"\\"}`, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jsonDepthAtMost([]byte(tt.data), tt.limit); got != tt.want {
				t.Errorf("jsonDepthAtMost(%s, %d) = %v, want %v", tt.data, tt.limit, got, tt.want)
			}
		})
	}
}

func TestIndentBOM(t *testing.T) {
	nested := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
	}
	if got, want := indentBOM(nested(maxIndentDepth)), IndentJSON(nested(maxIndentDepth)); !bytes.Equal(got, want) {
		t.Errorf("depth %d is not pretty-printed", maxIndentDepth)
	}
	deep := nested(5000)
	if got := indentBOM(deep); !bytes.Equal(got, deep) {
		t.Errorf("depth 5000 grew to %d bytes, want it unchanged", len(got))
	}
}

func TestEmptyBOMMessage(t *testing.T) {
	want := map[string]string{
		"aibom": "No AI components found in .",
		"cbom":  "No crypto components found in .",
		"sbom":  "No packages found in .",
		"all":   "No components found in .",
	}
	for bomType, msg := range want {
		if got := emptyBOMMessage(bomType, "."); got != msg {
			t.Errorf("emptyBOMMessage(%q) = %q, want %q", bomType, got, msg)
		}
	}
}

func TestSplitBOMError(t *testing.T) {
	cause := errors.New("results call failed")
	types, rest := SplitBOMError(fmt.Errorf("wrapped: %w", &BOMDownloadError{Types: []string{"cbom"}, Err: cause}))
	if !reflect.DeepEqual(types, []string{"cbom"}) || rest != cause {
		t.Errorf("SplitBOMError(BOMDownloadError) = %v, %v", types, rest)
	}
	types, rest = SplitBOMError(&BOMDownloadError{Types: []string{"aibom"}})
	if !reflect.DeepEqual(types, []string{"aibom"}) || rest != nil {
		t.Errorf("SplitBOMError without Err = %v, %v; want [aibom], nil", types, rest)
	}
	other := errors.New("other")
	if types, rest = SplitBOMError(other); types != nil || rest != other {
		t.Errorf("SplitBOMError(other) = %v, %v; want nil, other", types, rest)
	}
	if types, rest = SplitBOMError(nil); types != nil || rest != nil {
		t.Errorf("SplitBOMError(nil) = %v, %v", types, rest)
	}
}

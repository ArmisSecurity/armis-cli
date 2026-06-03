package cmd

import (
	"reflect"
	"testing"
)

func TestParseSkipPackages(t *testing.T) {
	// Hoist the repeated package names into constants so the want slices below
	// don't trip goconst (which flags an identical string literal repeated 3+
	// times across the package).
	const (
		lodash  = "lodash"
		express = "express"
		react   = "react"
	)

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		// FieldsFunc returns an empty (non-nil) slice when there are no fields;
		// an empty slice yields an empty skip set, which is the intended no-op.
		{"empty", "", []string{}},
		{"whitespace only", "   \t\n", []string{}},
		{"single", "lodash", []string{lodash}},
		{"comma separated", "lodash,express", []string{lodash, express}},
		{"comma with spaces", "lodash, express, react", []string{lodash, express, react}},
		{"whitespace separated", "lodash express react", []string{lodash, express, react}},
		{"mixed separators", "lodash,  express\treact", []string{lodash, express, react}},
		{"trailing comma drops empty field", "lodash,express,", []string{lodash, express}},
		{"leading and doubled separators", ",,lodash,,express", []string{lodash, express}},
		{"scoped package", "@myorg/utils,express", []string{"@myorg/utils", express}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSkipPackages(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSkipPackages(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

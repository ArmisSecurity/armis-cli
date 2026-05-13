package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestParseInlineComment(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefixes []string
		want     *InlineDirective
	}{
		{
			name:     "bare armis:ignore with hash comment",
			line:     "# armis:ignore",
			prefixes: []string{"#"},
			want:     &InlineDirective{},
		},
		{
			name:     "bare armis:ignore with slash comment",
			line:     "// armis:ignore",
			prefixes: []string{"//"},
			want:     &InlineDirective{},
		},
		{
			name:     "bare armis:ignore with double-dash comment",
			line:     "-- armis:ignore",
			prefixes: []string{"--"},
			want:     &InlineDirective{},
		},
		{
			name:     "bare armis:ignore with HTML comment",
			line:     "<!-- armis:ignore -->",
			prefixes: []string{"<!--"},
			want:     &InlineDirective{},
		},
		{
			name:     "bare armis:ignore with CSS comment",
			line:     "/* armis:ignore */",
			prefixes: []string{"/*"},
			want:     &InlineDirective{},
		},
		{
			name:     "bare armis:ignore with semicolon comment",
			line:     "; armis:ignore",
			prefixes: []string{";"},
			want:     &InlineDirective{},
		},
		{
			name:     "category scope",
			line:     "# armis:ignore category:sast",
			prefixes: []string{"#"},
			want:     &InlineDirective{Category: "sast"},
		},
		{
			name:     "rule scope",
			line:     "// armis:ignore rule:CKV_AWS_18",
			prefixes: []string{"//"},
			want:     &InlineDirective{Rule: "CKV_AWS_18"},
		},
		{
			name:     "cwe scope",
			line:     "# armis:ignore cwe:798",
			prefixes: []string{"#"},
			want:     &InlineDirective{CWE: "798"},
		},
		{
			name:     "severity scope",
			line:     "// armis:ignore severity:HIGH",
			prefixes: []string{"//"},
			want:     &InlineDirective{Severity: "HIGH"},
		},
		{
			name:     "multiple params",
			line:     "# armis:ignore category:sast cwe:79",
			prefixes: []string{"#"},
			want:     &InlineDirective{Category: "sast", CWE: "79"},
		},
		{
			name:     "with reason",
			line:     "// armis:ignore cwe:798 reason: this is a test token",
			prefixes: []string{"//"},
			want:     &InlineDirective{CWE: "798", Reason: "this is a test token"},
		},
		{
			name:     "case insensitive ARMIS:IGNORE",
			line:     "# ARMIS:IGNORE severity:low",
			prefixes: []string{"#"},
			want:     &InlineDirective{Severity: "LOW"},
		},
		{
			name:     "inline after code",
			line:     "password = 'test' # armis:ignore category:secrets",
			prefixes: []string{"#"},
			want:     &InlineDirective{Category: "secrets"},
		},
		{
			name:     "no comment prefix - not a directive",
			line:     "armis:ignore",
			prefixes: []string{"#"},
			want:     nil,
		},
		{
			name:     "wrong comment prefix",
			line:     "// armis:ignore",
			prefixes: []string{"#"},
			want:     nil,
		},
		{
			name:     "php allows both hash and slash",
			line:     "# armis:ignore",
			prefixes: []string{"//", "#"},
			want:     &InlineDirective{},
		},
		{
			name:     "in string literal no prefix match",
			line:     `msg := "armis:ignore this"`,
			prefixes: []string{"//"},
			want:     nil,
		},
		{ //nolint:gosec // G101 false positive: test fixture URL, not a credential
			name:     "prefix inside string literal URL rejected",
			line:     `url := "http://armis:ignore@example.com"`,
			prefixes: []string{"//"},
			want:     nil,
		},
		{
			name:     "prefix inside double-quoted string rejected",
			line:     `x := "// armis:ignore"`,
			prefixes: []string{"//"},
			want:     nil,
		},
		{
			name:     "prefix inside single-quoted string rejected",
			line:     `x := '// armis:ignore'`,
			prefixes: []string{"//"},
			want:     nil,
		},
		{
			name:     "real comment after string literal accepted",
			line:     `x := "value" // armis:ignore cwe:798`,
			prefixes: []string{"//"},
			want:     &InlineDirective{CWE: "798"},
		},
		{
			name:     "params in any order - severity then category",
			line:     "# armis:ignore severity:HIGH category:sast",
			prefixes: []string{"#"},
			want:     &InlineDirective{Severity: "HIGH", Category: "sast"},
		},
		{
			name:     "params in any order - cwe then category",
			line:     "# armis:ignore cwe:79 category:sast",
			prefixes: []string{"#"},
			want:     &InlineDirective{CWE: "79", Category: "sast"},
		},
		{
			name:     "params in any order - rule then severity then cwe",
			line:     "// armis:ignore rule:CKV_AWS_18 severity:HIGH cwe:798",
			prefixes: []string{"//"},
			want:     &InlineDirective{Rule: "CKV_AWS_18", Severity: "HIGH", CWE: "798"},
		},
		{
			name:     "prefix inside backtick string rejected",
			line:     "x := `// armis:ignore`",
			prefixes: []string{"//"},
			want:     nil,
		},
		{
			name:     "real comment after backtick string accepted",
			line:     "x := `value` // armis:ignore cwe:79",
			prefixes: []string{"//"},
			want:     &InlineDirective{CWE: "79"},
		},
		{
			name:     "tabs between params handled",
			line:     "# armis:ignore\tcategory:sast\tcwe:79",
			prefixes: []string{"#"},
			want:     &InlineDirective{Category: "sast", CWE: "79"},
		},
		{
			name:     "multiple spaces between params handled",
			line:     "# armis:ignore  category:sast   cwe:79",
			prefixes: []string{"#"},
			want:     &InlineDirective{Category: "sast", CWE: "79"},
		},
		{
			name:     "unknown key only - returns nil",
			line:     "# armis:ignore catgory:sast",
			prefixes: []string{"#"},
			want:     nil,
		},
		{
			name:     "unknown key with valid key - keeps valid",
			line:     "# armis:ignore catgory:sast cwe:79",
			prefixes: []string{"#"},
			want:     &InlineDirective{CWE: "79"},
		},
		{
			name:     "block comment in JS",
			line:     "/* armis:ignore cwe:79 */",
			prefixes: []string{"//", "/*"},
			want:     &InlineDirective{CWE: "79"},
		},
		{
			name:     "leading whitespace",
			line:     "    // armis:ignore severity:CRITICAL",
			prefixes: []string{"//"},
			want:     &InlineDirective{Severity: "CRITICAL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseInlineComment(tt.line, tt.prefixes)
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected directive, got nil")
			}
			if got.Category != tt.want.Category {
				t.Errorf("Category = %q, want %q", got.Category, tt.want.Category)
			}
			if got.Rule != tt.want.Rule {
				t.Errorf("Rule = %q, want %q", got.Rule, tt.want.Rule)
			}
			if got.CWE != tt.want.CWE {
				t.Errorf("CWE = %q, want %q", got.CWE, tt.want.CWE)
			}
			if got.Severity != tt.want.Severity {
				t.Errorf("Severity = %q, want %q", got.Severity, tt.want.Severity)
			}
			if got.Reason != tt.want.Reason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.want.Reason)
			}
		})
	}
}

func TestMatchesInlineDirective(t *testing.T) {
	tests := []struct {
		name      string
		finding   model.Finding
		directive *InlineDirective
		want      bool
	}{
		{
			name:      "bare directive matches any finding",
			finding:   model.Finding{Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
			directive: &InlineDirective{},
			want:      true,
		},
		{
			name:      "category matches",
			finding:   model.Finding{Type: model.FindingTypeSecret},
			directive: &InlineDirective{Category: "secrets"},
			want:      true,
		},
		{
			name:      "category does not match",
			finding:   model.Finding{Type: model.FindingTypeVulnerability},
			directive: &InlineDirective{Category: "secrets"},
			want:      false,
		},
		{
			name:      "cwe matches",
			finding:   model.Finding{CWEs: []string{"CWE-79: Cross-site Scripting"}},
			directive: &InlineDirective{CWE: "79"},
			want:      true,
		},
		{
			name:      "cwe does not match",
			finding:   model.Finding{CWEs: []string{"CWE-89"}},
			directive: &InlineDirective{CWE: "79"},
			want:      false,
		},
		{
			name:      "severity matches",
			finding:   model.Finding{Severity: model.SeverityHigh},
			directive: &InlineDirective{Severity: "HIGH"},
			want:      true,
		},
		{
			name:      "severity does not match",
			finding:   model.Finding{Severity: model.SeverityLow},
			directive: &InlineDirective{Severity: "HIGH"},
			want:      false,
		},
		{
			name:      "AND logic: both category and cwe must match - both match",
			finding:   model.Finding{Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-79"}},
			directive: &InlineDirective{Category: "sast", CWE: "79"},
			want:      true,
		},
		{
			name:      "AND logic: category matches but cwe does not",
			finding:   model.Finding{Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-89"}},
			directive: &InlineDirective{Category: "sast", CWE: "79"},
			want:      false,
		},
		{
			name:      "AND logic: cwe matches but category does not",
			finding:   model.Finding{Type: model.FindingTypeSecret, CWEs: []string{"CWE-79"}},
			directive: &InlineDirective{Category: "sast", CWE: "79"},
			want:      false,
		},
		{
			name:      "rule matches finding ID",
			finding:   model.Finding{ID: "CKV_AWS_18"},
			directive: &InlineDirective{Rule: "CKV_AWS_18"},
			want:      true,
		},
		{
			name:      "rule does not match",
			finding:   model.Finding{ID: "CKV_AWS_20"},
			directive: &InlineDirective{Rule: "CKV_AWS_18"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesInlineDirective(tt.finding, tt.directive)
			if got != tt.want {
				t.Errorf("matchesInlineDirective() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyInlineSuppression(t *testing.T) {
	t.Run("suppresses finding on same line", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.py", "import os\npassword = 'test' # armis:ignore\nprint(password)\n")

		findings := []model.Finding{
			{File: "main.py", StartLine: 2, Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 suppressed, got %d", count)
		}
		if !findings[0].Suppressed {
			t.Error("finding should be suppressed")
		}
		if findings[0].SuppressionInfo.Source != suppressionInline { //nolint:goconst // test assertion clarity
			t.Errorf("source = %q, want inline", findings[0].SuppressionInfo.Source)
		}
	})

	t.Run("suppresses finding on line below comment", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.go", "package main\n// armis:ignore\nvar secret = \"abc\"\n")

		findings := []model.Finding{
			{File: "main.go", StartLine: 3, Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 suppressed, got %d", count)
		}
	})

	t.Run("suppresses finding with comment 2 lines above", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.go", "package main\n// armis:ignore cwe:770\n// some other comment\nvar data = readAll()\n")

		findings := []model.Finding{
			{File: "main.go", StartLine: 4, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-770"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 suppressed (comment 2 lines above), got %d", count)
		}
	})

	t.Run("suppresses finding with comment 3 lines above through stacked comments", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.go", "package main\n// armis:ignore cwe:22\n// #nosec G304\n// nolint:gosec\nvar path = readFile(input)\n")

		findings := []model.Finding{
			{File: "main.go", StartLine: 5, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-22"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 suppressed (comment 3 lines above through stacked comments), got %d", count)
		}
	})

	t.Run("stops scanning upward at non-comment code line", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.go", "package main\n// armis:ignore cwe:79\nvar x = 1\n// unrelated comment\nvar y = unsafe(input)\n")

		findings := []model.Finding{
			{File: "main.go", StartLine: 5, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-79"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 (code line breaks upward scan), got %d", count)
		}
	})

	t.Run("scans through blank lines", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.go", "package main\n// armis:ignore cwe:22\n\nvar path = readFile(input)\n")

		findings := []model.Finding{
			{File: "main.go", StartLine: 4, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-22"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 (blank line skipped), got %d", count)
		}
	})

	t.Run("skips findings already suppressed by armisignore", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.py", "# armis:ignore\npassword = 'x'\n")

		findings := []model.Finding{
			{
				File: "main.py", StartLine: 2, Type: model.FindingTypeSecret, Severity: model.SeverityHigh,
				Suppressed:      true,
				SuppressionInfo: &model.SuppressionInfo{Type: string(DirectiveSeverity), Value: "HIGH", Source: "armisignore"},
			},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 suppressed (already suppressed), got %d", count)
		}
	})

	t.Run("skips findings with StartLine 0", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module test\n# armis:ignore\n")

		findings := []model.Finding{
			{File: "go.mod", StartLine: 0, Type: model.FindingTypeSCA},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0, got %d", count)
		}
	})

	t.Run("skips missing files", func(t *testing.T) {
		dir := t.TempDir()

		findings := []model.Finding{
			{File: "missing.py", StartLine: 1, Type: model.FindingTypeSecret},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0, got %d", count)
		}
		if findings[0].Suppressed {
			t.Error("finding should not be suppressed for missing file")
		}
	})

	t.Run("skips files larger than 10MB", func(t *testing.T) {
		dir := t.TempDir()
		// Create a file just over the limit
		large := strings.Repeat("x", maxInlineFileSize+1)
		writeFile(t, dir, "big.py", large)

		findings := []model.Finding{
			{File: "big.py", StartLine: 1, Type: model.FindingTypeSecret},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 for large file, got %d", count)
		}
	})

	t.Run("path traversal blocked", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "safe.py", "# armis:ignore\npassword='x'\n")

		findings := []model.Finding{
			{File: "../../../etc/passwd", StartLine: 1, Type: model.FindingTypeSecret},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 for traversal path, got %d", count)
		}
	})

	t.Run("line beyond file length", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "short.py", "# just one line\n")

		findings := []model.Finding{
			{File: "short.py", StartLine: 99, Type: model.FindingTypeSecret},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0, got %d", count)
		}
	})

	t.Run("CRLF line endings handled", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.py", "import os\r\n# armis:ignore\r\npassword = 'x'\r\n")

		findings := []model.Finding{
			{File: "main.py", StartLine: 3, Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 (CRLF), got %d", count)
		}
	})

	t.Run("scoped directive with AND logic rejects mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "app.py", "# armis:ignore category:sast cwe:79\ninjection = user_input\n")

		findings := []model.Finding{
			{File: "app.py", StartLine: 2, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-89"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 (CWE mismatch), got %d", count)
		}
	})

	t.Run("scoped directive with AND logic accepts full match", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "app.py", "# armis:ignore category:sast cwe:79\ninjection = user_input\n")

		findings := []model.Finding{
			{File: "app.py", StartLine: 2, Type: model.FindingTypeVulnerability, CWEs: []string{"CWE-79"}},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1, got %d", count)
		}
	})

	t.Run("caches file reads across multiple findings", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.py", "# armis:ignore\nfirst = 'secret'\nsecond = 'secret'\n")

		findings := []model.Finding{
			{File: "main.py", StartLine: 2, Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
			{File: "main.py", StartLine: 3, Type: model.FindingTypeSecret, Severity: model.SeverityHigh},
		}

		count := ApplyInlineSuppression(findings, dir)
		// Only line 2 has the directive above it; line 3 does not
		if count != 1 {
			t.Fatalf("expected 1 (only line 2 has directive above), got %d", count)
		}
	})

	t.Run("dockerfile without extension recognized", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "Dockerfile", "FROM ubuntu\n# armis:ignore\nRUN echo secret\n")

		findings := []model.Finding{
			{File: "Dockerfile", StartLine: 3, Type: model.FindingTypeMisconfig, Severity: model.SeverityMedium},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 1 {
			t.Fatalf("expected 1 for Dockerfile, got %d", count)
		}
	})

	t.Run("unknown extension skipped", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "data.bin", "# armis:ignore\nsecret data\n")

		findings := []model.Finding{
			{File: "data.bin", StartLine: 2, Type: model.FindingTypeSecret},
		}

		count := ApplyInlineSuppression(findings, dir)
		if count != 0 {
			t.Fatalf("expected 0 for unknown ext, got %d", count)
		}
	})

	t.Run("suppression info populated correctly", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "main.py", "# armis:ignore cwe:798 reason: test token only\npassword = 'test'\n")

		findings := []model.Finding{
			{File: "main.py", StartLine: 2, Type: model.FindingTypeSecret, CWEs: []string{"CWE-798"}},
		}

		ApplyInlineSuppression(findings, dir)
		info := findings[0].SuppressionInfo
		if info == nil {
			t.Fatal("SuppressionInfo is nil")
		}
		if info.Type != string(DirectiveCWE) {
			t.Errorf("Type = %q, want cwe", info.Type)
		}
		if info.Value != "798" {
			t.Errorf("Value = %q, want 798", info.Value)
		}
		if info.Reason != "test token only" {
			t.Errorf("Reason = %q, want 'test token only'", info.Reason)
		}
		if info.Source != suppressionInline {
			t.Errorf("Source = %q, want inline", info.Source)
		}
	})
}

func TestBuildInlineSuppressionInfo(t *testing.T) {
	tests := []struct {
		name      string
		directive *InlineDirective
		wantType  string
		wantValue string
	}{
		{
			name:      "bare directive",
			directive: &InlineDirective{},
			wantType:  suppressionInline,
			wantValue: "armis:ignore",
		},
		{
			name:      "cwe takes priority",
			directive: &InlineDirective{CWE: "79", Category: "sast"},
			wantType:  "cwe",
			wantValue: "79",
		},
		{
			name:      "rule takes priority over category",
			directive: &InlineDirective{Rule: "CKV_AWS_18", Category: "iac"},
			wantType:  "rule",
			wantValue: "CKV_AWS_18",
		},
		{
			name:      "category alone",
			directive: &InlineDirective{Category: "secrets"},
			wantType:  "category",
			wantValue: "secrets",
		},
		{
			name:      "severity alone",
			directive: &InlineDirective{Severity: "LOW"},
			wantType:  string(DirectiveSeverity),
			wantValue: "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := buildInlineSuppressionInfo(tt.directive)
			if info.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", info.Type, tt.wantType)
			}
			if info.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", info.Value, tt.wantValue)
			}
			if info.Source != suppressionInline {
				t.Errorf("Source = %q, want inline", info.Source)
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

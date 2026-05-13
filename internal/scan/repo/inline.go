package repo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

const (
	maxInlineFileSize   = 10 * 1024 * 1024 // 10MB
	suppressionInline   = "inline"
	suppressionTypeCWE  = "cwe"
	suppressionTypeRule = "rule"
)

// InlineDirective represents a parsed armis:ignore comment.
type InlineDirective struct {
	Category string
	Rule     string
	CWE      string
	Severity string
	Reason   string
}

// commentPrefixes maps file extensions to their line comment prefixes.
var commentPrefixes = map[string][]string{
	".py": {"#"}, ".rb": {"#"}, ".sh": {"#"}, ".bash": {"#"}, ".zsh": {"#"},
	".yaml": {"#"}, ".yml": {"#"}, ".tf": {"#"}, ".toml": {"#"}, ".r": {"#"},
	".dockerfile": {"#"},

	".js": {"//", "/*"}, ".ts": {"//", "/*"}, ".jsx": {"//", "/*"}, ".tsx": {"//", "/*"},
	".java": {"//", "/*"}, ".c": {"//", "/*"}, ".h": {"//", "/*"},
	".cpp": {"//", "/*"}, ".hpp": {"//", "/*"}, ".cs": {"//", "/*"},
	".go": {"//"}, ".rs": {"//"}, ".swift": {"//", "/*"}, ".kt": {"//", "/*"},
	".scala": {"//", "/*"}, ".dart": {"//", "/*"}, ".groovy": {"//", "/*"},

	".php": {"//", "#", "/*"},

	".sql": {"--", "/*"}, ".lua": {"--"}, ".hs": {"--"},

	".ini": {";"}, ".cfg": {";"},

	".html": {"<!--"}, ".xml": {"<!--"}, ".svg": {"<!--"},

	".css": {"/*"}, ".scss": {"/*", "//"}, ".less": {"/*", "//"},
}

var inlineDirectivePrefix = regexp.MustCompile(`(?i)armis:ignore\b`)

// ApplyInlineSuppression scans source files for armis:ignore comments
// and marks matching findings as suppressed. Returns count of findings suppressed.
func ApplyInlineSuppression(findings []model.Finding, repoRoot string) int {
	type fileLines struct {
		lines []string
		valid bool
	}
	cache := make(map[string]*fileLines)

	loadFile := func(filePath string) *fileLines {
		if cached, ok := cache[filePath]; ok {
			return cached
		}

		entry := &fileLines{}
		cache[filePath] = entry

		info, err := os.Stat(filePath)
		if err != nil || info.IsDir() || info.Size() > maxInlineFileSize {
			return entry
		}

		f, err := os.Open(filePath) // #nosec G304 - path validated via SafeJoinPath
		if err != nil {
			return entry
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close %s: %v\n", filePath, closeErr)
			}
		}()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			entry.lines = append(entry.lines, scanner.Text())
		}
		if scanner.Err() == nil {
			entry.valid = true
		}
		return entry
	}

	suppressed := 0
	for i := range findings {
		if findings[i].Suppressed {
			continue
		}
		if findings[i].StartLine == 0 || findings[i].File == "" {
			continue
		}

		absPath, err := util.SafeJoinPath(repoRoot, findings[i].File)
		if err != nil {
			continue
		}

		fl := loadFile(absPath)
		if !fl.valid {
			continue
		}

		lineIdx := findings[i].StartLine - 1
		if lineIdx < 0 || lineIdx >= len(fl.lines) {
			continue
		}

		ext := strings.ToLower(filepath.Ext(findings[i].File))
		if ext == "" {
			base := strings.ToLower(filepath.Base(findings[i].File))
			if base == "dockerfile" {
				ext = ".dockerfile"
			}
		}

		prefixes, ok := commentPrefixes[ext]
		if !ok {
			continue
		}

		// Check the finding line itself, then scan upward through comment/blank lines
		// (up to 5 lines above) to find a matching armis:ignore directive.
		var directive *InlineDirective
		if d := parseInlineComment(fl.lines[lineIdx], prefixes); d != nil {
			directive = d
		} else {
			for offset := 1; offset <= 5 && lineIdx-offset >= 0; offset++ {
				above := fl.lines[lineIdx-offset]
				trimmed := strings.TrimSpace(above)
				if trimmed == "" {
					continue
				}
				if d := parseInlineComment(above, prefixes); d != nil {
					directive = d
					break
				}
				if !isCommentLine(trimmed, prefixes) {
					break
				}
			}
		}

		if directive == nil {
			continue
		}

		if matchesInlineDirective(findings[i], directive) { //nolint:gosec // G602 false positive: i is bounded by range
			findings[i].Suppressed = true                                       //nolint:gosec // G602 false positive: i is bounded by range
			findings[i].SuppressionInfo = buildInlineSuppressionInfo(directive) //nolint:gosec // G602 false positive: i is bounded by range
			suppressed++
		}
	}

	return suppressed
}

// parseInlineComment checks if a line contains a valid armis:ignore comment
// after a recognized comment prefix that is not inside a string literal.
func parseInlineComment(line string, prefixes []string) *InlineDirective {
	trimmed := strings.TrimSpace(line)

	for _, prefix := range prefixes {
		idx := findCommentStart(trimmed, prefix)
		if idx == -1 {
			continue
		}

		after := trimmed[idx+len(prefix):]
		after = strings.TrimSpace(after)
		// Strip trailing comment closers for block comment syntaxes
		after = strings.TrimSuffix(after, "-->")
		after = strings.TrimSuffix(after, "*/")
		after = strings.TrimSpace(after)

		if !inlineDirectivePrefix.MatchString(after) {
			continue
		}

		d := parseDirectiveParams(after)
		return d
	}
	return nil
}

// isCommentLine returns true if the trimmed line starts with any of the given comment prefixes.
func isCommentLine(trimmed string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// findCommentStart finds the first occurrence of prefix that is not inside a
// quoted string (single, double, or backtick). Returns -1 if not found or
// only found inside quotes.
func findCommentStart(line, prefix string) int {
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false

	for i := 0; i <= len(line)-len(prefix); i++ {
		ch := line[i]

		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && !inBacktick {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble && !inBacktick {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle && !inBacktick {
			inDouble = !inDouble
			continue
		}
		if ch == '`' && !inSingle && !inDouble {
			inBacktick = !inBacktick
			continue
		}

		if !inSingle && !inDouble && !inBacktick && line[i:i+len(prefix)] == prefix {
			return i
		}
	}
	return -1
}

// parseDirectiveParams extracts key:value pairs from the text after "armis:ignore".
// Parameters may appear in any order. "reason:" captures the rest of the line.
// Returns nil if params are provided but none are recognized (likely a typo).
func parseDirectiveParams(text string) *InlineDirective {
	d := &InlineDirective{}

	// Strip the "armis:ignore" prefix
	loc := inlineDirectivePrefix.FindStringIndex(text)
	if loc == nil {
		return d
	}
	remainder := strings.TrimSpace(text[loc[1]:])
	if remainder == "" {
		return d
	}

	// Handle "reason:" as rest-of-line before field splitting
	lower := strings.ToLower(remainder)
	if idx := strings.Index(lower, "reason:"); idx != -1 {
		d.Reason = strings.TrimSpace(remainder[idx+7:])
		remainder = strings.TrimSpace(remainder[:idx])
	}

	hasParams := false
	recognized := false

	tokens := strings.Fields(remainder)
	for _, token := range tokens {
		colonIdx := strings.Index(token, ":")
		if colonIdx == -1 {
			continue
		}
		hasParams = true
		key := strings.ToLower(token[:colonIdx])
		value := token[colonIdx+1:]

		switch key {
		case string(DirectiveCategory):
			d.Category = strings.ToLower(value)
			recognized = true
		case string(DirectiveRule):
			d.Rule = value
			recognized = true
		case string(DirectiveCWE):
			d.CWE = value
			recognized = true
		case string(DirectiveSeverity):
			d.Severity = strings.ToUpper(value)
			recognized = true
		}
	}

	// If params were provided but none recognized, treat as invalid directive
	if hasParams && !recognized && d.Reason == "" {
		return nil
	}

	return d
}

// matchesInlineDirective applies AND logic: all non-empty scope params must match.
func matchesInlineDirective(finding model.Finding, d *InlineDirective) bool {
	if d.Category != "" {
		expected, ok := categoryToFindingType[d.Category]
		if !ok || finding.Type != expected {
			return false
		}
	}

	if d.Rule != "" {
		if !strings.EqualFold(finding.ID, d.Rule) {
			return false
		}
	}

	if d.CWE != "" {
		if !cweMatches(finding.CWEs, d.CWE) {
			return false
		}
	}

	if d.Severity != "" {
		if !strings.EqualFold(string(finding.Severity), d.Severity) {
			return false
		}
	}

	return true
}

func buildInlineSuppressionInfo(d *InlineDirective) *model.SuppressionInfo {
	info := &model.SuppressionInfo{
		Source: suppressionInline,
		Reason: d.Reason,
	}

	switch {
	case d.CWE != "":
		info.Type = suppressionTypeCWE
		info.Value = d.CWE
	case d.Rule != "":
		info.Type = suppressionTypeRule
		info.Value = d.Rule
	case d.Category != "":
		info.Type = string(DirectiveCategory)
		info.Value = d.Category
	case d.Severity != "":
		info.Type = string(DirectiveSeverity)
		info.Value = d.Severity
	default:
		info.Type = suppressionInline
		info.Value = "armis:ignore"
	}

	return info
}

// countSuppressed counts the total number of suppressed findings.
func countSuppressed(findings []model.Finding) int {
	count := 0
	for _, f := range findings {
		if f.Suppressed {
			count++
		}
	}
	return count
}

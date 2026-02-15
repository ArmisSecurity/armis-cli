// Package output provides formatters for scan results.
package output

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

const (
	groupBySeverity = "severity"
	noCWELabel      = "No CWE"

	// Resource limits for snippet loading to prevent memory exhaustion (CWE-770)
	maxLineLength  = 10 * 1024  // 10KB max per line
	maxSnippetSize = 100 * 1024 // 100KB max total snippet size
)

// Package-level compiled regex patterns (performance optimization)
var (
	numberedListPattern = regexp.MustCompile(`\s*(\d+)[.\)]\s+`)
	diffHunkPattern     = regexp.MustCompile(`@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
)

// severityRanks defines the sort order for severities (lower = more severe)
var severityRanks = map[model.Severity]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
	model.SeverityInfo:     4,
}

// wrapText wraps text at the specified width, preserving existing newlines.
// Each line is prefixed with indent, and continuation lines get the same indent.
func wrapText(text string, width int, indent string) string {
	if width <= 0 {
		width = DefaultWrapWidth
	}

	var result strings.Builder
	paragraphs := strings.Split(text, "\n")

	for i, paragraph := range paragraphs {
		if i > 0 {
			result.WriteString("\n")
		}
		if strings.TrimSpace(paragraph) == "" {
			result.WriteString(indent)
			continue
		}
		result.WriteString(wrapLine(paragraph, width, indent))
	}
	return result.String()
}

// wrapLine wraps a single line of text at word boundaries.
func wrapLine(line string, width int, indent string) string {
	effectiveWidth := width - len(indent)
	if effectiveWidth <= 10 {
		effectiveWidth = 60 // minimum reasonable width
	}

	words := strings.Fields(line)
	if len(words) == 0 {
		return indent
	}

	var result strings.Builder
	result.WriteString(indent)
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)

		if i == 0 {
			result.WriteString(word)
			lineLen = wordLen
		} else if lineLen+1+wordLen <= effectiveWidth {
			result.WriteString(" ")
			result.WriteString(word)
			lineLen += 1 + wordLen
		} else {
			result.WriteString("\n")
			result.WriteString(indent)
			result.WriteString(word)
			lineLen = wordLen
		}
	}
	return result.String()
}

// formatRecommendations formats a recommendations string that may contain
// inline numbered items (e.g., "1. xxx 2. xxx") into a properly formatted list.
func formatRecommendations(text string, baseIndent string) string {
	if text == "" {
		return ""
	}

	// Check if the text contains numbered patterns
	matches := numberedListPattern.FindAllStringIndex(text, -1)
	if len(matches) <= 1 {
		// No numbered list detected, or just one item - wrap normally
		return wrapText(text, DefaultWrapWidth, baseIndent)
	}

	// Split the text by numbered patterns
	var items []string
	var numbers []string
	var preamble string // Text before the first numbered item
	lastEnd := 0

	for _, match := range matches {
		if match[0] > lastEnd {
			// There's text before this match
			if len(items) > 0 {
				// Belongs to the previous item
				items[len(items)-1] += strings.TrimSpace(text[lastEnd:match[0]])
			} else {
				// Text before the first numbered item - store as preamble
				preamble = strings.TrimSpace(text[lastEnd:match[0]])
			}
		}
		// Extract the number
		numMatch := numberedListPattern.FindStringSubmatch(text[match[0]:match[1]])
		if len(numMatch) > 1 {
			numbers = append(numbers, numMatch[1])
		}
		items = append(items, "")
		lastEnd = match[1]
	}

	// Add remaining text to the last item
	if lastEnd < len(text) && len(items) > 0 {
		items[len(items)-1] = strings.TrimSpace(text[lastEnd:])
	}

	// Format output
	var result strings.Builder

	// Output preamble if present
	if preamble != "" {
		result.WriteString(wrapText(preamble, DefaultWrapWidth, baseIndent))
		result.WriteString("\n")
	}

	// Format each numbered item with proper indentation
	for i, item := range items {
		if i > 0 {
			result.WriteString("\n")
		}
		if i < len(numbers) {
			num := numbers[i]
			prefix := baseIndent + num + ". "
			// Continuation lines get extra indent to align past the number
			continuationIndent := baseIndent + strings.Repeat(" ", len(num)+2)
			result.WriteString(wrapTextWithFirstLinePrefix(item, DefaultWrapWidth, prefix, continuationIndent))
		}
	}
	return result.String()
}

// wrapTextWithFirstLinePrefix wraps text where the first line has a different
// prefix than continuation lines (useful for numbered lists).
func wrapTextWithFirstLinePrefix(text string, width int, firstPrefix string, contPrefix string) string {
	if width <= 0 {
		width = DefaultWrapWidth
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return firstPrefix
	}

	var result strings.Builder
	result.WriteString(firstPrefix)
	lineLen := len(firstPrefix)

	for i, word := range words {
		wordLen := len(word)

		if i == 0 {
			result.WriteString(word)
			lineLen += wordLen
		} else if lineLen+1+wordLen <= width {
			result.WriteString(" ")
			result.WriteString(word)
			lineLen += 1 + wordLen
		} else {
			result.WriteString("\n")
			result.WriteString(contPrefix)
			result.WriteString(word)
			lineLen = len(contPrefix) + wordLen
		}
	}
	return result.String()
}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) write(format string, args ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// HumanFormatter formats scan results in a human-readable format.
type HumanFormatter struct{}

// GitBlameInfo contains git blame information for a code location.
type GitBlameInfo struct {
	Author    string
	Email     string
	Date      string
	CommitSHA string
}

// FindingGroup represents a group of findings organized by a common attribute.
type FindingGroup struct {
	Key      string
	Label    string
	Findings []model.Finding
}

type indentWriter struct {
	w      io.Writer
	prefix string
	atBOL  bool
}

func (iw *indentWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if iw.atBOL {
			_, err := iw.w.Write([]byte(iw.prefix))
			if err != nil {
				return written, err
			}
			iw.atBOL = false
		}

		idx := bytes.IndexByte(p, '\n')
		if idx == -1 {
			n, err := iw.w.Write(p)
			written += n
			return written, err
		}

		n, err := iw.w.Write(p[:idx+1])
		written += n
		if err != nil {
			return written, err
		}
		iw.atBOL = true
		p = p[idx+1:]
	}
	return written, nil
}

// Format formats the scan result in human-readable format with default options.
func (f *HumanFormatter) Format(result *model.ScanResult, w io.Writer) error {
	return f.FormatWithOptions(result, w, FormatOptions{GroupBy: "none"})
}

// FormatWithOptions formats the scan result in human-readable format with custom options.
func (f *HumanFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
	ew := &errWriter{w: w}
	s := GetStyles()
	width := TerminalWidth()

	// 1. Header banner (bold text, no box)
	ew.write("%s\n", s.HeaderBanner.Render("ARMIS SECURITY SCAN RESULTS"))

	// 2. Scan ID & Status with styled labels and values
	labelStyle := s.MutedText
	ew.write("%s  %s\n", labelStyle.Render("Scan ID:"), s.ScanID.Render(result.ScanID))
	ew.write("%s  %s\n", labelStyle.Render("Status:"), s.StatusComplete.Render(result.Status))
	ew.write("\n")

	// 3. Brief status line for immediate orientation (skip if full summary at top)
	if !opts.SummaryTop {
		if err := renderBriefStatus(w, result); err != nil {
			return err
		}
	}

	// 4. Summary at top if requested
	if opts.SummaryTop {
		ew.write("\n")
		if err := renderSummaryDashboard(w, result); err != nil {
			return err
		}
	}

	// 5. Findings section
	if len(result.Findings) > 0 {
		ew.write("\n")
		sectionStyle := s.SectionTitle.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colorBorder).
			BorderBottom(true).
			BorderTop(false).
			BorderLeft(false).
			BorderRight(false).
			Width(width)
		ew.write("%s\n", sectionStyle.Render("FINDINGS"))

		// 5. Individual findings
		if opts.GroupBy != "" && opts.GroupBy != "none" {
			groups := groupFindings(result.Findings, opts.GroupBy)
			renderGroupedFindings(w, groups, opts)
		} else {
			sortedFindings := sortFindingsBySeverity(result.Findings)
			renderFindings(w, sortedFindings, opts)
		}
	}

	// 6. Full detailed summary dashboard at the end (skip if already shown at top)
	if !opts.SummaryTop {
		ew.write("\n")
		if err := renderSummaryDashboard(w, result); err != nil {
			return err
		}
		ew.write("\n")
	}

	// Footer (simple thin line)
	ew.write("%s\n", s.FooterSeparator.Render(strings.Repeat("─", width)))
	ew.write("\n")

	return ew.err
}

// SyncColors synchronizes the output package's styles with the
// centralized color state from internal/cli. Must be called after cli.InitColors().
func SyncColors() {
	SyncStylesWithColorMode()
}

func sortFindingsBySeverity(findings []model.Finding) []model.Finding {
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	return sorted
}

func loadSnippetFromFile(repoPath string, finding model.Finding) (snippet string, snippetStart int, err error) {
	if finding.File == "" {
		return "", 0, fmt.Errorf("no file path in finding")
	}

	var fullPath string
	if repoPath != "" {
		var pathErr error
		fullPath, pathErr = util.SafeJoinPath(repoPath, finding.File)
		if pathErr != nil {
			return "", 0, fmt.Errorf("invalid file path %q: %w", finding.File, pathErr)
		}
	} else {
		// Without repoPath, only allow relative paths without traversal
		if filepath.IsAbs(finding.File) {
			return "", 0, fmt.Errorf("absolute path not allowed without repository context: %q", finding.File)
		}
		sanitized, pathErr := util.SanitizePath(finding.File)
		if pathErr != nil {
			return "", 0, fmt.Errorf("invalid file path: %w", pathErr)
		}
		fullPath = sanitized
	}

	f, err := os.Open(fullPath) // #nosec G304 - file path is from scan results
	if err != nil {
		return "", 0, fmt.Errorf("open file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			if err != nil {
				// Wrap both errors to avoid losing the close error
				err = fmt.Errorf("close file: %w (original error: %v)", closeErr, err)
			} else {
				err = fmt.Errorf("close file: %w", closeErr)
			}
		}
	}()

	start := finding.SnippetStartLine
	if start <= 0 {
		start = finding.StartLine
	}
	if start <= 0 {
		start = 1
	}

	end := finding.EndLine
	if end < start {
		end = start + 3
	}

	contextStart := start - 4
	if contextStart < 1 {
		contextStart = 1
	}

	contextEnd := end + 4

	scanner := bufio.NewScanner(f)
	// Set a bounded buffer to prevent memory exhaustion from extremely long lines
	scanner.Buffer(make([]byte, 4096), maxLineLength)

	var buf []string
	var totalSize int
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum < contextStart {
			continue
		}
		if lineNum > contextEnd {
			break
		}
		line := scanner.Text()

		// Truncate line if it exceeds max length (shouldn't happen with bounded scanner,
		// but provides defense in depth)
		if len(line) > maxLineLength {
			line = line[:maxLineLength] + "... (truncated)"
		}

		// Check total size limit to prevent memory exhaustion
		totalSize += len(line) + 1 // +1 for newline
		if totalSize > maxSnippetSize {
			buf = append(buf, "... (snippet truncated due to size)")
			break
		}

		buf = append(buf, line)
	}
	if err := scanner.Err(); err != nil {
		// Handle bufio.ErrTooLong gracefully - the scanner hit its buffer limit
		if err == bufio.ErrTooLong {
			if len(buf) > 0 {
				buf = append(buf, "... (line too long, truncated)")
			} else {
				return "", 0, fmt.Errorf("file contains lines exceeding size limit")
			}
		} else {
			return "", 0, fmt.Errorf("scan file: %w", err)
		}
	}
	if len(buf) == 0 {
		return "", 0, fmt.Errorf("no lines read")
	}

	return strings.Join(buf, "\n"), contextStart, nil
}

// formatCodeSnippetWithFrame formats a code snippet with a simple header (no box border)
// Uses syntax highlighting for code readability with background highlighting for vulnerable lines.
func formatCodeSnippetWithFrame(finding model.Finding) string {
	s := GetStyles()
	plainLines := strings.Split(finding.CodeSnippet, "\n")

	snippetStart := 1
	if finding.SnippetStartLine > 0 {
		snippetStart = finding.SnippetStartLine
	}

	// Skip syntax highlighting for redacted snippets (contain secrets)
	isRedacted := strings.Contains(finding.CodeSnippet, "redacted")

	// Get syntax-highlighted lines (skip for redacted content)
	var highlightedLines []string
	if isRedacted {
		highlightedLines = plainLines
	} else {
		highlightedLines = HighlightCode(finding.CodeSnippet, finding.File)
	}

	// Max code line width for truncation
	maxCodeWidth := TerminalWidth() - 15

	var codeLines []string
	for i := range plainLines {
		actualLine := snippetStart + i
		isVulnerable := finding.StartLine > 0 && finding.EndLine > 0 &&
			actualLine >= finding.StartLine && actualLine <= finding.EndLine

		// Format line number
		lineNum := s.CodeLineNumber.Render(fmt.Sprintf("%4d", actualLine))

		// Get highlighted line (with bounds check)
		var highlightedLine string
		if i < len(highlightedLines) {
			highlightedLine = highlightedLines[i]
		} else {
			highlightedLine = plainLines[i]
		}

		// Get the plain text for width calculation and truncation
		plainLine := plainLines[i]
		if runewidth.StringWidth(plainLine) > maxCodeWidth {
			plainLine = truncatePlainLine(plainLine, maxCodeWidth)
			// Re-highlight the truncated line
			highlightedLine = HighlightLine(plainLine, finding.File)
		}

		// Format the code line
		var codeLine string
		if isVulnerable {
			// Apply syntax highlighting with persistent background color
			// Uses HighlightLineWithBackground to handle Chroma's ANSI resets
			codeLine = HighlightLineWithBackground(plainLine, finding.File, colorVulnBg)
			// Add arrow indicator for vulnerable lines (colored by severity)
			arrowStyle := s.GetSeverityText(finding.Severity)
			codeLines = append(codeLines, fmt.Sprintf("%s %s  %s", arrowStyle.Render(IconPointer), lineNum, codeLine))
		} else {
			codeLine = highlightedLine
			codeLines = append(codeLines, fmt.Sprintf("  %s  %s", lineNum, codeLine))
		}
	}

	// Build file location header
	var result strings.Builder
	if finding.File != "" {
		location := finding.File
		if finding.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.StartLine)
		}
		result.WriteString(s.MutedText.Render(location) + "\n")
	}

	for _, line := range codeLines {
		result.WriteString(line + "\n")
	}

	return result.String()
}

// truncatePlainLine truncates plain text to maxWidth with ellipsis
func truncatePlainLine(line string, maxWidth int) string {
	width := 0
	for i, r := range line {
		rw := runewidth.RuneWidth(r)
		if width+rw+3 > maxWidth { // +3 for "..."
			return line[:i] + "..."
		}
		width += rw
	}
	return line
}

func highlightColumns(line string, startCol, endCol, currentLine, startLine, endLine int) string {
	s := GetStyles()
	highlight := func(text string) string {
		return s.VulnColumnHighlight.Render(text)
	}

	if currentLine == startLine && currentLine == endLine {
		if startCol > len(line) {
			return highlight(line)
		}
		before := line[:startCol-1]
		if endCol > len(line) {
			endCol = len(line)
		}
		highlighted := line[startCol-1 : endCol]
		after := ""
		if endCol < len(line) {
			after = line[endCol:]
		}
		return before + highlight(highlighted) + after
	} else if currentLine == startLine {
		if startCol > len(line) {
			return highlight(line)
		}
		before := line[:startCol-1]
		highlighted := line[startCol-1:]
		return before + highlight(highlighted)
	} else if currentLine == endLine {
		if endCol > len(line) {
			endCol = len(line)
		}
		highlighted := line[:endCol]
		after := ""
		if endCol < len(line) {
			after = line[endCol:]
		}
		return highlight(highlighted) + after
	}
	return highlight(line)
}

func scanDuration(result *model.ScanResult) string {
	if result.StartedAt == "" || result.EndedAt == "" {
		return ""
	}

	start, err := time.Parse(time.RFC3339, result.StartedAt)
	if err != nil {
		return ""
	}
	end, err := time.Parse(time.RFC3339, result.EndedAt)
	if err != nil {
		return ""
	}

	if end.Before(start) {
		return ""
	}

	dur := end.Sub(start)

	h := int(dur.Hours())
	m := int(dur.Minutes()) % 60
	s := int(dur.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// pluralize returns singular or plural form based on count.
func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

// renderBriefStatus renders a concise one-line summary of findings count by severity.
// Example output: "Found 5 issues: 2 critical, 1 high, 2 medium"
func renderBriefStatus(w io.Writer, result *model.ScanResult) error {
	ew := &errWriter{w: w}
	s := GetStyles()

	total := result.Summary.Total

	// Handle edge case: no findings
	if total == 0 {
		successStyle := s.SuccessText
		ew.write("%s %s\n", IconSuccess, successStyle.Render("No issues found"))
		return ew.err
	}

	// Build severity breakdown string with styled counts
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	var parts []string
	for _, sev := range severities {
		count := result.Summary.BySeverity[sev]
		if count > 0 {
			sevStyle := s.GetSeverityText(sev)
			parts = append(parts, sevStyle.Render(fmt.Sprintf("%d %s", count, strings.ToLower(string(sev)))))
		}
	}

	// Format: "N issues  ·  X critical, Y high, Z medium"
	ew.write("%s  %s  %s\n",
		s.Bold.Render(fmt.Sprintf("%d %s", total, pluralize("issue", total))),
		s.MutedText.Render("·"),
		strings.Join(parts, s.MutedText.Render(", ")))

	return ew.err
}

func renderSummaryDashboard(w io.Writer, result *model.ScanResult) error {
	ew := &errWriter{w: w}
	s := GetStyles()
	width := TerminalWidth()

	// Build the summary content
	var content strings.Builder

	// Header - clean, no emoji
	content.WriteString("SCAN COMPLETE\n")

	// Total findings - simple and prominent
	content.WriteString(fmt.Sprintf("%d findings", result.Summary.Total))

	// Duration if available (inline)
	if duration := scanDuration(result); duration != "" {
		content.WriteString(fmt.Sprintf("  •  %s", duration))
	}
	content.WriteString("\n")

	// Filtered count if any
	if result.Summary.FilteredNonExploitable > 0 {
		filtered := s.MutedText.Render(fmt.Sprintf("(%d filtered as non-exploitable)", result.Summary.FilteredNonExploitable))
		content.WriteString(filtered + "\n")
	}

	// Severity breakdown - minimal inline format with colored dots
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	var sevParts []string
	for _, sev := range severities {
		count := result.Summary.BySeverity[sev]
		sevStyle := s.GetSeverityText(sev)
		dot := sevStyle.Render(SeverityDot)
		label := strings.ToLower(string(sev))
		sevParts = append(sevParts, fmt.Sprintf("%s %d %s", dot, count, label))
	}
	content.WriteString(strings.Join(sevParts, "  ") + "\n")

	// Category breakdown - inline
	if len(result.Summary.ByCategory) > 0 {
		content.WriteString("\n")

		type categoryCount struct {
			category string
			count    int
		}

		categories := make([]categoryCount, 0, len(result.Summary.ByCategory))
		for cat, count := range result.Summary.ByCategory {
			categories = append(categories, categoryCount{category: cat, count: count})
		}

		sort.Slice(categories, func(i, j int) bool {
			if categories[i].count != categories[j].count {
				return categories[i].count > categories[j].count
			}
			return categories[i].category < categories[j].category
		})

		var catParts []string
		for _, cc := range categories {
			catParts = append(catParts, fmt.Sprintf("%s (%d)", util.FormatCategory(cc.category), cc.count))
		}
		catLabel := s.MutedText.Render("Categories:")
		content.WriteString(fmt.Sprintf("%s %s\n", catLabel, strings.Join(catParts, ", ")))
	}

	// Render the summary box using predefined style
	ew.write("%s\n", s.SummaryBox.Width(width).Render(content.String()))
	return ew.err
}

func renderFindings(w io.Writer, findings []model.Finding, opts FormatOptions) {
	s := GetStyles()
	total := len(findings)
	width := TerminalWidth()
	for i, finding := range findings {
		// Add breathing room before each finding separator (except first)
		if i > 0 {
			_, _ = fmt.Fprintf(w, "\n") // One blank line before separator
		}

		// Finding separator line with counter: ─── FINDING 1 of 6 ───
		header := fmt.Sprintf(" FINDING %d of %d ", i+1, total)
		headerLen := len(header)
		leftPad := (width - headerLen) / 2
		rightPad := width - headerLen - leftPad
		if leftPad < 3 {
			leftPad = 3
		}
		if rightPad < 3 {
			rightPad = 3
		}
		separator := strings.Repeat("─", leftPad) + header + strings.Repeat("─", rightPad)
		_, _ = fmt.Fprintf(w, "%s\n\n", s.FindingHeader.Render(separator)) // One blank line after separator

		renderFinding(w, finding, opts)
	}
	_, _ = fmt.Fprintf(w, "\n")
}

func renderFinding(w io.Writer, finding model.Finding, opts FormatOptions) {
	s := GetStyles()

	// Severity (bold colored text) + Title on same line
	sevStyle := s.GetSeverityText(finding.Severity)
	dot := sevStyle.Render(SeverityDot)
	displayTitle := getHumanDisplayTitle(finding)
	_, _ = fmt.Fprintf(w, "%s %s  %s\n", dot, sevStyle.Render(string(finding.Severity)), s.Bold.Render(displayTitle))

	// Build compact metadata line: category · CWE/CVE (file location moved to code block header)
	var metaParts []string

	// Category first (what type of issue)
	if finding.FindingCategory != "" {
		metaParts = append(metaParts, util.FormatCategory(finding.FindingCategory))
	}

	// CWE/CVE identifiers
	if len(finding.CWEs) > 0 {
		metaParts = append(metaParts, finding.CWEs[0]) // Show first CWE
	}
	if len(finding.CVEs) > 0 {
		metaParts = append(metaParts, finding.CVEs[0]) // Show first CVE
	}

	// Print compact metadata line
	if len(metaParts) > 0 {
		sep := s.MutedText.Render(" · ")
		_, _ = fmt.Fprintf(w, "%s\n", strings.Join(metaParts, sep))
	}

	// Git blame on separate line if available
	labelStyle := s.MutedText
	if finding.File != "" && opts.RepoPath != "" && finding.StartLine > 0 {
		if blameInfo := getGitBlame(opts.RepoPath, finding.File, finding.StartLine, opts.Debug); blameInfo != nil {
			maskedEmail := maskEmail(blameInfo.Email)
			_, _ = fmt.Fprintf(w, "%s %s <%s> (%s, %s)\n",
				labelStyle.Render("Blame:"), blameInfo.Author, maskedEmail, blameInfo.Date, blameInfo.CommitSHA[:7])
		}
	}

	if finding.CodeSnippet == "" && opts.RepoPath != "" && finding.StartLine > 0 {
		if snippet, snippetStart, err := loadSnippetFromFile(opts.RepoPath, finding); err == nil {
			finding.CodeSnippet = snippet
			finding.SnippetStartLine = snippetStart
		}
	}

	// Code snippet with framed box
	if finding.CodeSnippet != "" {
		_, _ = fmt.Fprintf(w, "\n")
		_, _ = fmt.Fprintf(w, "%s\n", formatCodeSnippetWithFrame(finding))
	}

	// Display proposed fix if available
	if finding.Fix != nil {
		_, _ = fmt.Fprintf(w, "%s", formatFixSection(finding.Fix))
	}

	// Display validation info if available
	if finding.Validation != nil {
		_, _ = fmt.Fprintf(w, "%s", formatValidationSection(finding.Validation))
	}
}

func renderGroupedFindings(w io.Writer, groups []FindingGroup, opts FormatOptions) {
	s := GetStyles()
	width := TerminalWidth()
	for i, group := range groups {
		if i > 0 {
			_, _ = fmt.Fprintf(w, "\n")
		}

		// Styled group header using centralized style
		headerStyle := s.HeaderBox.Width(width)
		header := fmt.Sprintf("%s (%d %s)", group.Label, len(group.Findings), pluralize("finding", len(group.Findings)))
		_, _ = fmt.Fprintf(w, "%s\n\n", headerStyle.Render(header))

		for j, finding := range group.Findings {
			if j > 0 {
				_, _ = fmt.Fprintf(w, "\n")
			}
			iw := &indentWriter{w: w, prefix: "  ", atBOL: true}
			renderFinding(iw, finding, opts)
		}
	}
	_, _ = fmt.Fprintf(w, "\n")
}

func groupFindings(findings []model.Finding, groupBy string) []FindingGroup {
	groupMap := make(map[string][]model.Finding)

	for _, finding := range findings {
		var key string
		switch groupBy {
		case "cwe":
			if len(finding.CWEs) > 0 {
				key = finding.CWEs[0]
			} else {
				key = noCWELabel
			}
		case groupBySeverity:
			key = string(finding.Severity)
		case "file":
			if finding.File != "" {
				key = finding.File
			} else {
				key = "Unknown File"
			}
		default:
			key = "All"
		}
		groupMap[key] = append(groupMap[key], finding)
	}

	styles := GetStyles()
	var groups []FindingGroup
	for key, findings := range groupMap {
		label := key
		if groupBy == "cwe" && key != "No CWE" {
			label = fmt.Sprintf("CWE: %s", key)
		} else if groupBy == "severity" {
			sev := model.Severity(key)
			styledDot := styles.GetSeverityText(sev).Render(SeverityDot)
			label = fmt.Sprintf("%s %s", styledDot, key)
		} else if groupBy == "file" {
			label = fmt.Sprintf("File: %s", key)
		}

		groups = append(groups, FindingGroup{
			Key:      key,
			Label:    label,
			Findings: sortFindingsBySeverity(findings),
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groupBy == "severity" {
			return severityRank(model.Severity(groups[i].Key)) < severityRank(model.Severity(groups[j].Key))
		}
		return groups[i].Key < groups[j].Key
	})

	return groups
}

func severityRank(sev model.Severity) int {
	if rank, ok := severityRanks[sev]; ok {
		return rank
	}
	return 999
}

func isGitRepo(repoPath string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = repoPath
	err := cmd.Run()
	return err == nil
}

func getGitBlame(repoPath, file string, line int, debug bool) *GitBlameInfo {
	if !isGitRepo(repoPath) {
		if debug {
			fmt.Fprintf(os.Stderr, "DEBUG: git blame skipped - %s is not a git repository\n", repoPath)
		}
		return nil
	}

	filePath, err := util.SafeJoinPath(repoPath, file)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "DEBUG: git blame skipped - invalid file path %q: %v\n", file, err)
		}
		return nil
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if debug {
			fmt.Fprintf(os.Stderr, "DEBUG: git blame skipped - file does not exist: %s\n", filePath)
		}
		return nil
	}

	// #nosec G204 -- file path is validated above, git blame is intentional for showing code ownership
	// Use "--" separator to prevent file argument from being interpreted as an option
	cmd := exec.Command("git", "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--porcelain", "--", file)
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "DEBUG: git blame failed for %s:%d - %v\n", file, line, err)
		}
		return nil
	}

	return parseGitBlame(string(output))
}

func parseGitBlame(output string) *GitBlameInfo {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return nil
	}

	info := &GitBlameInfo{}

	parts := strings.Fields(lines[0])
	if len(parts) > 0 {
		info.CommitSHA = parts[0]
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			info.Author = strings.TrimPrefix(line, "author ")
		} else if strings.HasPrefix(line, "author-mail ") {
			email := strings.TrimPrefix(line, "author-mail ")
			info.Email = strings.Trim(email, "<>")
		} else if strings.HasPrefix(line, "author-time ") {
			timestamp := strings.TrimPrefix(line, "author-time ")
			if unixTime, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
				info.Date = time.Unix(unixTime, 0).Format("2006-01-02")
			} else {
				info.Date = timestamp
			}
		}
	}

	if info.Author == "" || info.CommitSHA == "" {
		return nil
	}

	return info
}

func maskEmail(email string) string {
	if email == "" {
		return ""
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	localPart := parts[0]
	domain := parts[1]

	if len(localPart) <= 2 {
		return localPart[0:1] + "***@" + domain[0:1] + "***." + getTopLevelDomain(domain)
	}

	maskedLocal := localPart[0:1] + "***"
	maskedDomain := domain[0:1] + "***." + getTopLevelDomain(domain)

	return maskedLocal + "@" + maskedDomain
}

func getTopLevelDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return domain
}

// getHumanDisplayTitle returns a concise title for human output.
// For OWASP-based titles, extracts just the category (e.g., "Injection" instead of
// "Injection (CWE-89: Improper Neutralization...)").
// CWE/CVE details are shown separately in the metadata line.
func getHumanDisplayTitle(finding model.Finding) string {
	title := finding.Title

	// If title contains parenthesized CWE info, extract just the prefix
	// Pattern: "Category Name (CWE-XXX: ...)" → "Category Name"
	if idx := strings.Index(title, " (CWE-"); idx > 0 {
		return strings.TrimSpace(title[:idx])
	}

	return title
}

// formatFixSection formats the proposed fix section for display.
func formatFixSection(fix *model.Fix) string {
	if fix == nil {
		return ""
	}

	s := GetStyles()
	var sb strings.Builder

	// Display fix status header
	sb.WriteString("\n")
	if fix.IsValid {
		sb.WriteString(s.SuccessText.Render(fmt.Sprintf("%s Validated Fix", IconSuccess)) + "\n")
	} else {
		sb.WriteString(s.MutedText.Render("Proposed Fix") + "\n")
	}

	// Display explanation with text wrapping
	if fix.Explanation != "" {
		labelStyle := s.SubsectionTitle
		sb.WriteString("\n" + labelStyle.Render("Explanation:") + "\n")
		sb.WriteString(wrapText(fix.Explanation, DefaultWrapWidth, "  "))
		sb.WriteString("\n")
	}

	// Display recommendations as formatted list
	if fix.Recommendations != "" {
		labelStyle := s.SubsectionTitle
		sb.WriteString("\n" + labelStyle.Render("Recommendations:") + "\n")
		sb.WriteString(formatRecommendations(fix.Recommendations, "  "))
		sb.WriteString("\n")
	}

	// Display patch (unified diff) if available - preferred over proposed code snippets
	hasPatch := fix.Patch != nil && *fix.Patch != ""
	if hasPatch {
		sb.WriteString("\n")
		sb.WriteString(formatDiffWithColorsStyled(*fix.Patch))
	}

	// Display proposed fixes (code snippets) only if no patch is available
	// The diff is more concise and informative when present
	if len(fix.ProposedFixes) > 0 && !hasPatch {
		labelStyle := s.SubsectionTitle
		sb.WriteString("\n" + labelStyle.Render("Proposed Code Changes:") + "\n")
		for _, snippet := range fix.ProposedFixes {
			sb.WriteString(formatProposedSnippet(snippet))
		}
	}

	// Display feedback if available with text wrapping
	if fix.Feedback != "" {
		labelStyle := s.SubsectionTitle
		sb.WriteString("\n" + labelStyle.Render("Feedback:") + "\n")
		sb.WriteString(wrapText(fix.Feedback, DefaultWrapWidth, "  "))
		sb.WriteString("\n")
	}

	return sb.String()
}

// formatProposedSnippet formats a single code snippet for the proposed fix.
// Uses syntax highlighting for code readability.
func formatProposedSnippet(snippet model.CodeSnippetFix) string {
	s := GetStyles()
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  File: %s", snippet.FilePath))
	if snippet.StartLine != nil && snippet.EndLine != nil {
		sb.WriteString(fmt.Sprintf(" (lines %d-%d)", *snippet.StartLine, *snippet.EndLine))
	} else if snippet.StartLine != nil {
		sb.WriteString(fmt.Sprintf(" (line %d)", *snippet.StartLine))
	}
	sb.WriteString("\n")

	// Get syntax-highlighted lines
	highlightedLines := HighlightCode(snippet.Content, snippet.FilePath)

	startLine := 1
	if snippet.StartLine != nil {
		startLine = *snippet.StartLine
	}
	for i, line := range highlightedLines {
		lineNum := s.ProposedLineNumber.Render(fmt.Sprintf("%4d", startLine+i))
		sb.WriteString(fmt.Sprintf("  %s  %s\n", lineNum, line))
	}

	return sb.String()
}

// DiffLineType represents the type of a line in a unified diff
type DiffLineType int

const (
	DiffLineContext DiffLineType = iota // Context line (no +/-)
	DiffLineAdd                         // Added line (+)
	DiffLineRemove                      // Removed line (-)
	DiffLineHunk                        // Hunk header (@@ ... @@)
)

// DiffLine represents a parsed line from a unified diff
type DiffLine struct {
	Type    DiffLineType
	Content string // Line content without the +/- prefix
	Raw     string // Original line including prefix
	OldNum  int    // Line number in old file (0 if not applicable)
	NewNum  int    // Line number in new file (0 if not applicable)
}

// ChangeSpan represents a range of characters that differ between two lines
type ChangeSpan struct {
	Start int
	End   int
}

// parseDiffHunk extracts line numbers from a hunk header like "@@ -31,6 +31,8 @@"
func parseDiffHunk(line string) (oldStart, oldCount, newStart, newCount int) {
	matches := diffHunkPattern.FindStringSubmatch(line)
	if len(matches) < 4 {
		return 1, 1, 1, 1 // Fallback
	}

	oldStart, _ = strconv.Atoi(matches[1])
	if matches[2] != "" {
		oldCount, _ = strconv.Atoi(matches[2])
	} else {
		oldCount = 1
	}
	newStart, _ = strconv.Atoi(matches[3])
	if len(matches) > 4 && matches[4] != "" {
		newCount, _ = strconv.Atoi(matches[4])
	} else {
		newCount = 1
	}
	return
}

// parseDiffLines parses a unified diff patch into structured DiffLine entries
func parseDiffLines(patch string) []DiffLine {
	var result []DiffLine
	lines := strings.Split(patch, "\n")

	var oldLineNum, newLineNum int
	seenHunk := false // Track whether we've seen the first @@ hunk header

	for _, line := range lines {
		// Skip file headers (--- a/file, +++ b/file) that appear BEFORE the first hunk.
		// After a hunk header, lines starting with --- or +++ are actual diff content
		// (e.g., a removed SQL comment "-- DROP TABLE" appears as "--- DROP TABLE").
		if !seenHunk && (strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ")) {
			continue
		}

		if strings.HasPrefix(line, "@@") {
			seenHunk = true
			oldStart, _, newStart, _ := parseDiffHunk(line)
			oldLineNum = oldStart
			newLineNum = newStart
			result = append(result, DiffLine{
				Type:    DiffLineHunk,
				Content: line,
				Raw:     line,
			})
		} else if strings.HasPrefix(line, "+") {
			result = append(result, DiffLine{
				Type:    DiffLineAdd,
				Content: line[1:], // Strip the + prefix
				Raw:     line,
				NewNum:  newLineNum,
			})
			newLineNum++
		} else if strings.HasPrefix(line, "-") {
			result = append(result, DiffLine{
				Type:    DiffLineRemove,
				Content: line[1:], // Strip the - prefix
				Raw:     line,
				OldNum:  oldLineNum,
			})
			oldLineNum++
		} else if line != "" { // Context line (preserve empty lines within diff)
			// Context lines in unified diff start with a space - strip it like +/- prefixes
			content := line
			if strings.HasPrefix(line, " ") {
				content = line[1:]
			}
			result = append(result, DiffLine{
				Type:    DiffLineContext,
				Content: content,
				Raw:     line,
				OldNum:  oldLineNum,
				NewNum:  newLineNum,
			})
			oldLineNum++
			newLineNum++
		} else if len(result) > 0 { // Empty line within diff content
			result = append(result, DiffLine{
				Type:    DiffLineContext,
				Content: "",
				Raw:     "",
				OldNum:  oldLineNum,
				NewNum:  newLineNum,
			})
			oldLineNum++
			newLineNum++
		}
	}

	return result
}

// findInlineChanges compares two strings and returns spans of differing characters.
// Uses LCS (Longest Common Subsequence) on tokens for accurate change detection,
// properly handling insertions and deletions without cascading false positives.
func findInlineChanges(oldLine, newLine string) (oldSpans, newSpans []ChangeSpan) {
	// Tokenize both lines by word boundaries
	oldTokens := tokenizeLine(oldLine)
	newTokens := tokenizeLine(newLine)

	// Compute LCS to find matching tokens
	lcs := computeLCS(oldTokens, newTokens)

	// Build position maps: token index -> byte position
	oldPositions := buildTokenPositions(oldTokens)
	newPositions := buildTokenPositions(newTokens)

	// Walk through both token lists, using LCS to identify matches
	oldIdx, newIdx, lcsIdx := 0, 0, 0

	for oldIdx < len(oldTokens) || newIdx < len(newTokens) {
		// Check if current tokens match the next LCS element
		oldMatchesLCS := lcsIdx < len(lcs) && oldIdx < len(oldTokens) && oldTokens[oldIdx] == lcs[lcsIdx]
		newMatchesLCS := lcsIdx < len(lcs) && newIdx < len(newTokens) && newTokens[newIdx] == lcs[lcsIdx]

		if oldMatchesLCS && newMatchesLCS {
			// Both match LCS - this token is unchanged, advance all pointers
			oldIdx++
			newIdx++
			lcsIdx++
		} else if !oldMatchesLCS && oldIdx < len(oldTokens) {
			// Old token not in LCS - it was removed
			start := oldPositions[oldIdx]
			end := start + len(oldTokens[oldIdx])
			oldSpans = append(oldSpans, ChangeSpan{Start: start, End: end})
			oldIdx++
		} else if !newMatchesLCS && newIdx < len(newTokens) {
			// New token not in LCS - it was added
			start := newPositions[newIdx]
			end := start + len(newTokens[newIdx])
			newSpans = append(newSpans, ChangeSpan{Start: start, End: end})
			newIdx++
		} else {
			// Safety: advance if stuck (shouldn't happen with correct LCS)
			if oldIdx < len(oldTokens) {
				oldIdx++
			}
			if newIdx < len(newTokens) {
				newIdx++
			}
		}
	}

	return
}

// computeLCS computes the Longest Common Subsequence of two string slices.
// Returns the subsequence elements (not indices).
func computeLCS(a, b []string) []string {
	m, n := len(a), len(b)
	if m == 0 || n == 0 {
		return nil
	}

	// Build DP table
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	// Backtrack to find LCS
	lcs := make([]string, 0, dp[m][n])
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			lcs = append(lcs, a[i-1])
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}

	// Reverse to get correct order
	for left, right := 0, len(lcs)-1; left < right; left, right = left+1, right-1 {
		lcs[left], lcs[right] = lcs[right], lcs[left]
	}

	return lcs
}

// buildTokenPositions returns a slice mapping token index to byte position in the original string.
func buildTokenPositions(tokens []string) []int {
	positions := make([]int, len(tokens))
	pos := 0
	for i, token := range tokens {
		positions[i] = pos
		pos += len(token)
	}
	return positions
}

// tokenizeLine splits a line into word-like tokens preserving positions
func tokenizeLine(s string) []string {
	var tokens []string
	var current strings.Builder

	for _, r := range s {
		if isWordChar(r) {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(r))
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// isWordChar returns true if the rune is part of a word
func isWordChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
}

// formatDiffWithColorsStyled formats a unified diff with enhanced visual styling.
// Features: background colors, line numbers, gutter styling, inline change highlighting, syntax highlighting.
func formatDiffWithColorsStyled(patch string) string {
	s := GetStyles()
	lines := parseDiffLines(patch)
	termWidth := TerminalWidth()

	// Extract filename from diff header for syntax highlighting
	filename := extractDiffFilename(patch)

	var sb strings.Builder

	// Track remove lines for inline highlighting with subsequent add lines
	var pendingRemoves []DiffLine
	// Track if we just saw a hunk header (to skip leading empty lines)
	afterHunk := false

	for _, line := range lines {
		switch line.Type {
		case DiffLineHunk:
			// Flush any pending removes
			for _, r := range pendingRemoves {
				sb.WriteString(formatDiffRemoveLine(r, s, nil, termWidth, filename))
			}
			pendingRemoves = nil
			sb.WriteString(formatDiffHunkLine(line, s))
			afterHunk = true

		case DiffLineRemove:
			afterHunk = false
			// Collect removes to potentially pair with subsequent adds
			pendingRemoves = append(pendingRemoves, line)

		case DiffLineAdd:
			afterHunk = false
			// Check if we can pair with a pending remove for inline highlighting
			if len(pendingRemoves) > 0 {
				removeLine := pendingRemoves[0]
				pendingRemoves = pendingRemoves[1:]
				oldSpans, newSpans := findInlineChanges(removeLine.Content, line.Content)
				sb.WriteString(formatDiffRemoveLine(removeLine, s, oldSpans, termWidth, filename))
				sb.WriteString(formatDiffAddLine(line, s, newSpans, termWidth, filename))
			} else {
				sb.WriteString(formatDiffAddLine(line, s, nil, termWidth, filename))
			}

		case DiffLineContext:
			// Skip leading empty context lines right after hunk header
			if afterHunk && strings.TrimSpace(line.Content) == "" {
				continue
			}
			afterHunk = false
			// Flush pending removes first
			for _, r := range pendingRemoves {
				sb.WriteString(formatDiffRemoveLine(r, s, nil, termWidth, filename))
			}
			pendingRemoves = nil
			sb.WriteString(formatDiffContextLine(line, s, termWidth, filename))
		}
	}

	// Flush any remaining removes
	for _, r := range pendingRemoves {
		sb.WriteString(formatDiffRemoveLine(r, s, nil, termWidth, filename))
	}

	return sb.String()
}

// extractDiffFilename extracts the filename from unified diff header lines.
// Looks for "+++ b/path/to/file" or "+++ path/to/file" patterns.
func extractDiffFilename(patch string) string {
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+++ ") {
			path := strings.TrimPrefix(line, "+++ ")
			// Handle "b/path" format (git diff)
			path = strings.TrimPrefix(path, "b/")
			// Handle "/dev/null" for new files
			if path == "/dev/null" {
				continue
			}
			return path
		}
	}
	return ""
}

// formatDiffHunkLine formats a hunk header line (@@ ... @@)
func formatDiffHunkLine(line DiffLine, s *Styles) string {
	return "  " + s.DiffHunk.Render(line.Content) + "\n"
}

// formatDiffContextLine formats a context line with line numbers and syntax highlighting
func formatDiffContextLine(line DiffLine, s *Styles, termWidth int, filename string) string {
	lineNum := fmt.Sprintf("%3d", line.NewNum)
	content := truncateDiffLine(line.Content, termWidth-10)
	// Apply syntax highlighting to context lines
	highlighted := HighlightLine(content, filename)
	return fmt.Sprintf("  %s   %s\n", s.DiffLineNumber.Render(lineNum), highlighted)
}

// formatDiffRemoveLine formats a removed line with background color and optional inline highlights
func formatDiffRemoveLine(line DiffLine, s *Styles, highlights []ChangeSpan, termWidth int, filename string) string {
	_ = filename // Reserved for future syntax highlighting of diff lines
	lineNum := fmt.Sprintf("%3d", line.OldNum)
	marker := s.DiffRemove.Render("-")
	// Truncate BEFORE applying highlights to avoid cutting through ANSI escape sequences
	content, truncated := truncateDiffLineWithFlag(line.Content, termWidth-10)
	// Adjust highlight spans if content was truncated
	adjustedHighlights := adjustHighlightSpans(highlights, len(content))
	content = applyInlineHighlights(content, adjustedHighlights, s.DiffRemoveHighlight, s.DiffRemoveLine)
	if truncated {
		content += "…"
	}
	// Apply background to the entire content area
	styledContent := s.DiffRemoveLine.Render(content)
	return fmt.Sprintf("  %s %s %s\n", s.DiffLineNumber.Render(lineNum), marker, styledContent)
}

// formatDiffAddLine formats an added line with background color and optional inline highlights
func formatDiffAddLine(line DiffLine, s *Styles, highlights []ChangeSpan, termWidth int, filename string) string {
	_ = filename // Reserved for future syntax highlighting of diff lines
	lineNum := fmt.Sprintf("%3d", line.NewNum)
	marker := s.DiffAdd.Render("+")
	// Truncate BEFORE applying highlights to avoid cutting through ANSI escape sequences
	content, truncated := truncateDiffLineWithFlag(line.Content, termWidth-10)
	// Adjust highlight spans if content was truncated
	adjustedHighlights := adjustHighlightSpans(highlights, len(content))
	content = applyInlineHighlights(content, adjustedHighlights, s.DiffAddHighlight, s.DiffAddLine)
	if truncated {
		content += "…"
	}
	// Apply background to the entire content area
	styledContent := s.DiffAddLine.Render(content)
	return fmt.Sprintf("  %s %s %s\n", s.DiffLineNumber.Render(lineNum), marker, styledContent)
}

// applyInlineHighlights applies highlight styling to specific spans within a line
func applyInlineHighlights(content string, spans []ChangeSpan, highlightStyle, baseStyle lipgloss.Style) string {
	if len(spans) == 0 {
		return content
	}

	var result strings.Builder
	lastEnd := 0

	for _, span := range spans {
		// Clamp span to content bounds
		start := span.Start
		end := span.End
		if start < 0 {
			start = 0
		}
		if end > len(content) {
			end = len(content)
		}
		if start >= end || start >= len(content) {
			continue
		}

		// Add unhighlighted portion
		if lastEnd < start {
			result.WriteString(content[lastEnd:start])
		}

		// Add highlighted portion
		result.WriteString(highlightStyle.Render(content[start:end]))
		lastEnd = end
	}

	// Add remaining content
	if lastEnd < len(content) {
		result.WriteString(content[lastEnd:])
	}

	return result.String()
}

// truncateDiffLine truncates a line to fit within the given width
func truncateDiffLine(line string, maxWidth int) string {
	truncated, _ := truncateDiffLineWithFlag(line, maxWidth)
	return truncated
}

// truncateDiffLineWithFlag truncates a line and returns whether truncation occurred.
// This allows callers to add ellipsis after applying styling (to avoid ANSI corruption).
func truncateDiffLineWithFlag(line string, maxWidth int) (string, bool) {
	if maxWidth <= 0 {
		return line, false
	}
	width := runewidth.StringWidth(line)
	if width <= maxWidth {
		return line, false
	}
	// Truncate without ellipsis - caller will add it after styling
	return runewidth.Truncate(line, maxWidth-1, ""), true
}

// adjustHighlightSpans clamps highlight spans to fit within the given content length.
// Spans that extend beyond maxLen are truncated; spans entirely beyond are removed.
func adjustHighlightSpans(spans []ChangeSpan, maxLen int) []ChangeSpan {
	if len(spans) == 0 || maxLen <= 0 {
		return spans
	}
	var result []ChangeSpan
	for _, span := range spans {
		if span.Start >= maxLen {
			continue // Span is entirely beyond truncated content
		}
		adjusted := ChangeSpan{Start: span.Start, End: span.End}
		if adjusted.End > maxLen {
			adjusted.End = maxLen
		}
		if adjusted.Start < adjusted.End {
			result = append(result, adjusted)
		}
	}
	return result
}

// formatValidationSection formats the finding validation section for display.
// Uses a compact single-line summary format for quick scanning.
func formatValidationSection(validation *model.FindingValidation) string {
	if validation == nil {
		return ""
	}

	s := GetStyles()
	var sb strings.Builder

	labelStyle := s.SubsectionTitle
	sb.WriteString("\n" + labelStyle.Render("Validation:") + "\n")

	// Build compact summary line: "  ✓ 100% confidence | HIGH | REACHABLE | Exposure: 6 (externally accessible)"
	var parts []string

	// Confidence with styled indicator
	confidenceIcon := GetConfidenceIcon(validation.Confidence)
	var confidenceStyle lipgloss.Style
	if validation.Confidence >= 80 {
		confidenceStyle = s.SuccessText
	} else if validation.Confidence >= 50 {
		confidenceStyle = s.WarningText
	} else {
		confidenceStyle = s.MutedText
	}
	parts = append(parts, confidenceStyle.Render(fmt.Sprintf("%s %d%% confidence", confidenceIcon, validation.Confidence)))

	// AI Severity (if present)
	if validation.ValidatedSeverity != nil {
		parts = append(parts, s.Bold.Render(*validation.ValidatedSeverity))
	}

	// Reachability
	if validation.TaintPropagation != "" {
		parts = append(parts, string(validation.TaintPropagation))
	}

	// Exposure level
	if validation.Exposure != nil {
		exposureDesc := getExposureDescription(*validation.Exposure)
		parts = append(parts, fmt.Sprintf("Exposure: %d (%s)", *validation.Exposure, exposureDesc))
	}

	sb.WriteString("  ")
	sb.WriteString(strings.Join(parts, " │ "))
	sb.WriteString("\n")

	// Analysis explanation as wrapped paragraph below the summary
	if validation.Explanation != "" {
		sb.WriteString("\n")
		sb.WriteString(wrapText(validation.Explanation, DefaultWrapWidth, "  "))
		sb.WriteString("\n")
	}

	return sb.String()
}

// getExposureDescription returns a human-readable description for the exposure level.
func getExposureDescription(exposure int) string {
	switch {
	case exposure == 0:
		return "not exposed"
	case exposure <= 2:
		return "internal only"
	case exposure <= 4:
		return "limited exposure"
	case exposure <= 5:
		return "moderate exposure"
	default:
		return "externally accessible"
	}
}

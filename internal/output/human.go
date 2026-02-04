// Package output provides formatters for scan results.
package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/mattn/go-runewidth"
)

const (
	groupBySeverity = "severity"
	noCWELabel      = "No CWE"

	// Resource limits for snippet loading to prevent memory exhaustion (CWE-770)
	maxLineLength  = 10 * 1024  // 10KB max per line
	maxSnippetSize = 100 * 1024 // 100KB max total snippet size
)

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
			n, err := iw.w.Write([]byte(iw.prefix))
			if err != nil {
				return written, err
			}
			_ = n
			iw.atBOL = false
		}

		idx := strings.IndexByte(string(p), '\n')
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

	// 1. Header banner
	ew.write("\n")
	ew.write("═══════════════════════════════════════════════════════════════\n")
	ew.write("  ARMIS SECURITY SCAN RESULTS\n")
	ew.write("═══════════════════════════════════════════════════════════════\n")
	ew.write("\n")

	// 2. Scan ID & Status
	ew.write("Scan ID:     %s\n", result.ScanID)
	ew.write("Status:      %s\n", result.Status)
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
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("  SUMMARY\n")
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("\n")
		if err := renderSummaryDashboard(w, result); err != nil {
			return err
		}
	}

	// 5. Findings section
	if len(result.Findings) > 0 {
		ew.write("\n")
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("  FINDINGS\n")
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("\n")

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
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("  SUMMARY\n")
		ew.write("───────────────────────────────────────────────────────────────\n")
		ew.write("\n")
		if err := renderSummaryDashboard(w, result); err != nil {
			return err
		}
		ew.write("\n")
	}

	ew.write("═══════════════════════════════════════════════════════════════\n")
	ew.write("\n")

	return ew.err
}

func getSeverityIcon(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🔵"
	case model.SeverityInfo:
		return "⚪"
	default:
		return "•"
	}
}

func getSeverityColor(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return colorRed
	case model.SeverityHigh:
		return colorOrange
	case model.SeverityMedium:
		return colorYellow
	case model.SeverityLow:
		return colorBlue
	case model.SeverityInfo:
		return colorGray
	default:
		return ""
	}
}

var (
	colorReset     = "\033[0m"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorOrange    = "\033[33m"
	colorYellow    = "\033[93m"
	colorBlue      = "\033[34m"
	colorGray      = "\033[90m"
	colorBgRed     = "\033[101m"
	colorBold      = "\033[1m"
	colorUnderline = "\033[4m" //nolint:unused // reserved for future formatting options
)

func init() {
	// Support NO_COLOR standard (https://no-color.org/) and dumb terminals
	if os.Getenv("NO_COLOR") != "" || strings.Contains(strings.ToLower(os.Getenv("TERM")), "dumb") {
		disableColors()
	}
}

func disableColors() {
	colorReset = ""
	colorRed = ""
	colorGreen = ""
	colorOrange = ""
	colorYellow = ""
	colorBlue = ""
	colorGray = ""
	colorBgRed = ""
	colorBold = ""
	colorUnderline = ""
}

func sortFindingsBySeverity(findings []model.Finding) []model.Finding {
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)

	severityRank := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}

	sort.Slice(sorted, func(i, j int) bool {
		rankI, okI := severityRank[sorted[i].Severity]
		rankJ, okJ := severityRank[sorted[j].Severity]

		if !okI {
			rankI = 999
		}
		if !okJ {
			rankJ = 999
		}

		return rankI < rankJ
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

func formatCodeSnippet(finding model.Finding) string {
	lang := detectLanguage(finding.File)

	lines := strings.Split(finding.CodeSnippet, "\n")
	var formatted []string
	formatted = append(formatted, "```"+lang)

	snippetStart := 1
	if finding.SnippetStartLine > 0 {
		snippetStart = finding.SnippetStartLine
	}

	for i, line := range lines {
		actualLine := snippetStart + i
		lineNumStr := fmt.Sprintf("%4d  ", actualLine)

		if finding.StartLine > 0 && finding.EndLine > 0 {
			if actualLine >= finding.StartLine && actualLine <= finding.EndLine {
				if finding.StartColumn > 0 && finding.EndColumn > 0 {
					highlighted := highlightColumns(line, finding.StartColumn, finding.EndColumn, actualLine, finding.StartLine, finding.EndLine)
					formatted = append(formatted, lineNumStr+highlighted)
				} else {
					formatted = append(formatted, lineNumStr+colorBgRed+colorBold+line+colorReset)
				}
			} else {
				formatted = append(formatted, lineNumStr+line)
			}
		} else {
			formatted = append(formatted, lineNumStr+line)
		}
	}

	formatted = append(formatted, "```")

	return strings.Join(formatted, "\n")
}

func highlightColumns(line string, startCol, endCol, currentLine, startLine, endLine int) string {
	if currentLine == startLine && currentLine == endLine {
		if startCol > len(line) {
			return colorBgRed + colorBold + line + colorReset
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
		return before + colorBgRed + colorBold + highlighted + colorReset + after
	} else if currentLine == startLine {
		if startCol > len(line) {
			return colorBgRed + colorBold + line + colorReset
		}
		before := line[:startCol-1]
		highlighted := line[startCol-1:]
		return before + colorBgRed + colorBold + highlighted + colorReset
	} else if currentLine == endLine {
		if endCol > len(line) {
			endCol = len(line)
		}
		highlighted := line[:endCol]
		after := ""
		if endCol < len(line) {
			after = line[endCol:]
		}
		return colorBgRed + colorBold + highlighted + colorReset + after
	}
	return colorBgRed + colorBold + line + colorReset
}

func detectLanguage(filename string) string {
	if filename == "" {
		return ""
	}

	ext := strings.ToLower(filepath.Ext(filename))
	langMap := map[string]string{
		".abap":        "abap",
		".adb":         "ada",
		".ads":         "ada",
		".ada":         "ada",
		".agda":        "agda",
		".als":         "alloy",
		".apib":        "apiblueprint",
		".apl":         "apl",
		".applescript": "applescript",
		".scpt":        "applescript",
		".arc":         "arc",
		".ino":         "arduino",
		".as":          "actionscript",
		".asciidoc":    "asciidoc",
		".adoc":        "asciidoc",
		".asc":         "asciidoc",
		".ash":         "ash",
		".asm":         "assembly",
		".s":           "assembly",
		".nasm":        "assembly",
		".au3":         "autoit",
		".awk":         "awk",
		".bal":         "ballerina",
		".bat":         "batch",
		".cmd":         "batch",
		".befunge":     "befunge",
		".bib":         "bibtex",
		".bison":       "bison",
		".blade":       "blade",
		".bf":          "brainfuck",
		".b":           "brainfuck",
		".brs":         "brightscript",
		".c":           "c",
		".h":           "c",
		".cats":        "c",
		".idc":         "c",
		".w":           "c",
		".cs":          "csharp",
		".csx":         "csharp",
		".cpp":         "cpp",
		".cc":          "cpp",
		".cxx":         "cpp",
		".hpp":         "cpp",
		".hh":          "cpp",
		".hxx":         "cpp",
		".c++":         "cpp",
		".h++":         "cpp",
		".cmake":       "cmake",
		".cbl":         "cobol",
		".cob":         "cobol",
		".cpy":         "cobol",
		".coffee":      "coffeescript",
		".cfm":         "coldfusion",
		".cfc":         "coldfusion",
		".lisp":        "commonlisp",
		".lsp":         "commonlisp",
		".cl":          "commonlisp",
		".coq":         "coq",
		".cr":          "crystal",
		".css":         "css",
		".cu":          "cuda",
		".cuh":         "cuda",
		".d":           "d",
		".di":          "d",
		".dart":        "dart",
		".diff":        "diff",
		".patch":       "diff",
		".dockerfile":  "dockerfile",
		".dot":         "dot",
		".gv":          "dot",
		".dylan":       "dylan",
		".e":           "eiffel",
		".ex":          "elixir",
		".exs":         "elixir",
		".elm":         "elm",
		".el":          "elisp",
		".emacs":       "elisp",
		".erl":         "erlang",
		".hrl":         "erlang",
		".fs":          "fsharp",
		".fsi":         "fsharp",
		".fsx":         "fsharp",
		".factor":      "factor",
		".fy":          "fancy",
		".purs":        "purescript",
		".f":           "fortran",
		".f90":         "fortran",
		".f95":         "fortran",
		".for":         "fortran",
		".fth":         "forth",
		".4th":         "forth",
		".ftl":         "freemarker",
		".g4":          "antlr",
		".gd":          "gdscript",
		".glsl":        "glsl",
		".vert":        "glsl",
		".frag":        "glsl",
		".geo":         "glsl",
		".gml":         "gml",
		".go":          "go",
		".gql":         "graphql",
		".graphql":     "graphql",
		".groovy":      "groovy",
		".gvy":         "groovy",
		".gy":          "groovy",
		".gsh":         "groovy",
		".hack":        "hack",
		".haml":        "haml",
		".handlebars":  "handlebars",
		".hbs":         "handlebars",
		".hs":          "haskell",
		".lhs":         "haskell",
		".hx":          "haxe",
		".hxsl":        "haxe",
		".hlsl":        "hlsl",
		".html":        "html",
		".htm":         "html",
		".http":        "http",
		".hy":          "hy",
		".pro":         "idris",
		".idr":         "idris",
		".ni":          "inform7",
		".i7x":         "inform7",
		".iss":         "innosetup",
		".io":          "io",
		".ik":          "ioke",
		".java":        "java",
		".js":          "javascript",
		".mjs":         "javascript",
		".cjs":         "javascript",
		".jsx":         "jsx",
		".json":        "json",
		".json5":       "json5",
		".jsonnet":     "jsonnet",
		".jl":          "julia",
		".kt":          "kotlin",
		".kts":         "kotlin",
		".lean":        "lean",
		".hlean":       "lean",
		".less":        "less",
		".ly":          "lilypond",
		".ily":         "lilypond",
		".lol":         "lolcode",
		".lua":         "lua",
		".m":           "objectivec",
		".mm":          "objectivec",
		".mk":          "makefile",
		".mak":         "makefile",
		".md":          "markdown",
		".markdown":    "markdown",
		".mkd":         "markdown",
		".max":         "maxscript",
		".ms":          "maxscript",
		".mel":         "mel",
		".moo":         "moocode",
		".n":           "nemerle",
		".nim":         "nim",
		".nix":         "nix",
		".nu":          "nushell",
		".ml":          "ocaml",
		".mli":         "ocaml",
		".objdump":     "objdump",
		".odin":        "odin",
		".p":           "openscad",
		".scad":        "openscad",
		".ox":          "ox",
		".oxh":         "ox",
		".ozf":         "oz",
		".oz":          "oz",
		".pwn":         "pawn",
		".inc":         "pawn",
		".peg":         "peg",
		".pl":          "perl",
		".pm":          "perl",
		".t":           "perl",
		".php":         "php",
		".phtml":       "php",
		".php3":        "php",
		".php4":        "php",
		".php5":        "php",
		".phps":        "php",
		".pig":         "pig",
		".pike":        "pike",
		".pmod":        "pike",
		".pogo":        "pogoscript",
		".pony":        "pony",
		".ps1":         "powershell",
		".psm1":        "powershell",
		".psd1":        "powershell",
		".prolog":      "prolog",
		".proto":       "protobuf",
		".pp":          "puppet",
		".py":          "python",
		".pyw":         "python",
		".pyx":         "python",
		".pxd":         "python",
		".pxi":         "python",
		".q":           "q",
		".qml":         "qml",
		".r":           "r",
		".R":           "r",
		".rkt":         "racket",
		".rktl":        "racket",
		".raku":        "raku",
		".rakumod":     "raku",
		".re":          "reason",
		".rei":         "reason",
		".red":         "red",
		".reds":        "red",
		".rst":         "restructuredtext",
		".rest":        "restructuredtext",
		".rexx":        "rexx",
		".ring":        "ring",
		".robot":       "robotframework",
		".rb":          "ruby",
		".rbw":         "ruby",
		".rake":        "ruby",
		".rs":          "rust",
		".sas":         "sas",
		".sass":        "sass",
		".scala":       "scala",
		".sc":          "scala",
		".scm":         "scheme",
		".ss":          "scheme",
		".scss":        "scss",
		".sh":          "bash",
		".bash":        "bash",
		".zsh":         "bash",
		".ksh":         "bash",
		".csh":         "bash",
		".fish":        "fish",
		".sml":         "sml",
		".sol":         "solidity",
		".rq":          "sparql",
		".sparql":      "sparql",
		".sql":         "sql",
		".stan":        "stan",
		".do":          "stata",
		".ado":         "stata",
		".styl":        "stylus",
		".sv":          "systemverilog",
		".svh":         "systemverilog",
		".swift":       "swift",
		".tcl":         "tcl",
		".tex":         "latex",
		".textile":     "textile",
		".thrift":      "thrift",
		".toml":        "toml",
		".ts":          "typescript",
		".tsx":         "tsx",
		".ttl":         "turtle",
		".twig":        "twig",
		".txt":         "text",
		".vala":        "vala",
		".vapi":        "vala",
		".v":           "verilog",
		".vh":          "verilog",
		".vhdl":        "vhdl",
		".vhd":         "vhdl",
		".vim":         "vim",
		".vue":         "vue",
		".wast":        "webassembly",
		".wat":         "webassembly",
		".wgsl":        "wgsl",
		".x10":         "x10",
		".xc":          "xc",
		".xml":         "xml",
		".xsl":         "xml",
		".xsd":         "xml",
		".xpath":       "xpath",
		".xq":          "xquery",
		".xquery":      "xquery",
		".xslt":        "xslt",
		".xtend":       "xtend",
		".yaml":        "yaml",
		".yml":         "yaml",
		".yang":        "yang",
		".zig":         "zig",
		".clj":         "clojure",
		".cljs":        "clojure",
		".cljc":        "clojure",
		".edn":         "clojure",
	}

	if lang, ok := langMap[ext]; ok {
		return lang
	}

	return ""
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

	total := result.Summary.Total

	// Handle edge case: no findings
	if total == 0 {
		ew.write("✅ No security issues found.\n")
		return ew.err
	}

	// Build severity breakdown string
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
			parts = append(parts, fmt.Sprintf("%d %s", count, strings.ToLower(string(sev))))
		}
	}

	// Format: "Found N issues: X critical, Y high, Z medium"
	ew.write("⚠️  Found %d %s: %s\n", total, pluralize("issue", total), strings.Join(parts, ", "))

	return ew.err
}

func renderSummaryDashboard(w io.Writer, result *model.ScanResult) error {
	ew := &errWriter{w: w}
	width := 45

	ew.write("┌%s┐\n", strings.Repeat("─", width-2))

	headerLine := "│ 📊 SCAN SUMMARY"
	headerPadding := width - runewidth.StringWidth(headerLine) - 1
	ew.write("%s%s│\n", headerLine, strings.Repeat(" ", headerPadding))

	ew.write("├%s┤\n", strings.Repeat("─", width-2))

	totalLine := fmt.Sprintf("│ Total: %d", result.Summary.Total)
	totalPadding := width - runewidth.StringWidth(totalLine) - 1
	ew.write("%s%s│\n", totalLine, strings.Repeat(" ", totalPadding))

	if duration := scanDuration(result); duration != "" {
		durationLine := fmt.Sprintf("│ Duration: %s", duration)
		durationPadding := width - runewidth.StringWidth(durationLine) - 1
		ew.write("%s%s│\n", durationLine, strings.Repeat(" ", durationPadding))
	}

	if result.Summary.FilteredNonExploitable > 0 {
		filteredLine := fmt.Sprintf("│ Filtered (Non-Exploitable): %d", result.Summary.FilteredNonExploitable)
		filteredPadding := width - runewidth.StringWidth(filteredLine) - 1
		ew.write("%s%s│\n", filteredLine, strings.Repeat(" ", filteredPadding))
	}

	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	hasFindings := false
	for _, sev := range severities {
		if result.Summary.BySeverity[sev] > 0 {
			hasFindings = true
			break
		}
	}

	if hasFindings {
		ew.write("│%s│\n", strings.Repeat(" ", width-2))
	}

	for _, sev := range severities {
		count := result.Summary.BySeverity[sev]
		if count > 0 {
			icon := getSeverityIcon(sev)
			line := fmt.Sprintf("│ %s  %s: %d", icon, sev, count)
			padding := width - runewidth.StringWidth(line) - 1
			ew.write("%s%s│\n", line, strings.Repeat(" ", padding))
		}
	}

	if len(result.Summary.ByCategory) > 0 {
		ew.write("│%s│\n", strings.Repeat(" ", width-2))

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

		for _, cc := range categories {
			line := fmt.Sprintf("│ %s: %d", cc.category, cc.count)
			padding := width - runewidth.StringWidth(line) - 1
			ew.write("%s%s│\n", line, strings.Repeat(" ", padding))
		}
	}

	ew.write("└%s┘\n", strings.Repeat("─", width-2))
	return ew.err
}

func renderFindings(w io.Writer, findings []model.Finding, opts FormatOptions) {
	for i, finding := range findings {
		if i > 0 {
			_, _ = fmt.Fprintf(w, "\n")
		}

		renderFinding(w, finding, opts)

		if i < len(findings)-1 {
			_, _ = fmt.Fprintf(w, "\n───────────────────────────────────────────────────────────────\n")
		}
	}
	_, _ = fmt.Fprintf(w, "\n")
}

func renderFinding(w io.Writer, finding model.Finding, opts FormatOptions) {
	color := getSeverityColor(finding.Severity)
	icon := getSeverityIcon(finding.Severity)

	_, _ = fmt.Fprintf(w, "%s %s%s%s\n", icon, color, finding.Severity, colorReset)
	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(w, "%s\n", finding.Title)
	_, _ = fmt.Fprintf(w, "\n")

	if finding.FindingCategory != "" {
		_, _ = fmt.Fprintf(w, "Category:    %s\n", finding.FindingCategory)
	}

	if len(finding.CVEs) > 0 {
		_, _ = fmt.Fprintf(w, "CVE:         %s\n", strings.Join(finding.CVEs, ", "))
	}

	if len(finding.CWEs) > 0 {
		_, _ = fmt.Fprintf(w, "CWE:         %s\n", strings.Join(finding.CWEs, ", "))
	}

	if finding.File != "" {
		location := finding.File
		if finding.StartLine > 0 {
			if finding.EndLine > 0 && finding.EndLine != finding.StartLine {
				location = fmt.Sprintf("%s:%d-%d", location, finding.StartLine, finding.EndLine)
			} else {
				location = fmt.Sprintf("%s:%d", location, finding.StartLine)
			}
			if finding.StartColumn > 0 {
				location = fmt.Sprintf("%s:%d", location, finding.StartColumn)
			}
		}
		_, _ = fmt.Fprintf(w, "Location:    %s\n", location)

		if opts.RepoPath != "" && finding.StartLine > 0 {
			if blameInfo := getGitBlame(opts.RepoPath, finding.File, finding.StartLine, opts.Debug); blameInfo != nil {
				maskedEmail := maskEmail(blameInfo.Email)
				_, _ = fmt.Fprintf(w, "Git Blame:   %s <%s> (%s, %s)\n",
					blameInfo.Author, maskedEmail, blameInfo.Date, blameInfo.CommitSHA[:7])
			}
		}
	}

	if finding.CodeSnippet == "" && opts.RepoPath != "" && finding.StartLine > 0 {
		if snippet, snippetStart, err := loadSnippetFromFile(opts.RepoPath, finding); err == nil {
			finding.CodeSnippet = snippet
			finding.SnippetStartLine = snippetStart
		}
	}

	if finding.CodeSnippet != "" {
		_, _ = fmt.Fprintf(w, "\nCode:\n")
		_, _ = fmt.Fprintf(w, "%s\n", formatCodeSnippet(finding))
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
	for i, group := range groups {
		if i > 0 {
			_, _ = fmt.Fprintf(w, "\n")
		}

		header := fmt.Sprintf("📁 %s (%d findings)", group.Label, len(group.Findings))
		_, _ = fmt.Fprintf(w, "%s\n", header)
		_, _ = fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", len(header)))

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

	var groups []FindingGroup
	for key, findings := range groupMap {
		label := key
		if groupBy == "cwe" && key != "No CWE" {
			label = fmt.Sprintf("CWE: %s", key)
		} else if groupBy == "severity" {
			icon := getSeverityIcon(model.Severity(key))
			label = fmt.Sprintf("%s %s", icon, key)
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
	ranks := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	if rank, ok := ranks[sev]; ok {
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
			fmt.Printf("DEBUG: git blame skipped - %s is not a git repository\n", repoPath)
		}
		return nil
	}

	filePath, err := util.SafeJoinPath(repoPath, file)
	if err != nil {
		if debug {
			fmt.Printf("DEBUG: git blame skipped - invalid file path %q: %v\n", file, err)
		}
		return nil
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if debug {
			fmt.Printf("DEBUG: git blame skipped - file does not exist: %s\n", filePath)
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
			fmt.Printf("DEBUG: git blame failed for %s:%d - %v\n", file, line, err)
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

// formatFixSection formats the proposed fix section for display.
func formatFixSection(fix *model.Fix) string {
	if fix == nil {
		return ""
	}

	var sb strings.Builder

	// Display fix status header
	sb.WriteString("\n")
	if fix.IsValid {
		sb.WriteString(colorGreen + "✓ Proposed Fix Available" + colorReset + "\n")
	} else {
		sb.WriteString(colorYellow + "⚠ Proposed Fix (Unvalidated)" + colorReset + "\n")
	}

	// Display explanation
	if fix.Explanation != "" {
		sb.WriteString("\nExplanation:\n")
		sb.WriteString("  " + fix.Explanation + "\n")
	}

	// Display recommendations
	if fix.Recommendations != "" {
		sb.WriteString("\nRecommendations:\n")
		sb.WriteString("  " + fix.Recommendations + "\n")
	}

	// Display proposed fixes (code snippets)
	if len(fix.ProposedFixes) > 0 {
		sb.WriteString("\nProposed Code Changes:\n")
		for _, snippet := range fix.ProposedFixes {
			sb.WriteString(formatProposedSnippet(snippet))
		}
	}

	// Display patch if available
	if fix.Patch != nil && *fix.Patch != "" {
		sb.WriteString("\nUnified Diff:\n")
		sb.WriteString(formatDiffWithColors(*fix.Patch))
	}

	// Display feedback if available
	if fix.Feedback != "" {
		sb.WriteString("\nFeedback:\n")
		sb.WriteString("  " + fix.Feedback + "\n")
	}

	return sb.String()
}

// formatProposedSnippet formats a single code snippet for the proposed fix.
func formatProposedSnippet(snippet model.CodeSnippetFix) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  File: %s", snippet.FilePath))
	if snippet.StartLine != nil && snippet.EndLine != nil {
		sb.WriteString(fmt.Sprintf(" (lines %d-%d)", *snippet.StartLine, *snippet.EndLine))
	} else if snippet.StartLine != nil {
		sb.WriteString(fmt.Sprintf(" (line %d)", *snippet.StartLine))
	}
	sb.WriteString("\n")

	// Display the code content with indentation
	lines := strings.Split(snippet.Content, "\n")
	startLine := 1
	if snippet.StartLine != nil {
		startLine = *snippet.StartLine
	}
	for i, line := range lines {
		sb.WriteString(fmt.Sprintf("  %s%4d%s  %s\n", colorGray, startLine+i, colorReset, line))
	}

	return sb.String()
}

// formatDiffWithColors formats a unified diff with colored output.
func formatDiffWithColors(patch string) string {
	var sb strings.Builder
	lines := strings.Split(patch, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			sb.WriteString(colorGreen + "  " + line + colorReset + "\n")
		} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			sb.WriteString(colorRed + "  " + line + colorReset + "\n")
		} else if strings.HasPrefix(line, "@@") {
			sb.WriteString(colorBlue + "  " + line + colorReset + "\n")
		} else {
			sb.WriteString("  " + line + "\n")
		}
	}

	return sb.String()
}

// formatValidationSection formats the finding validation section for display.
func formatValidationSection(validation *model.FindingValidation) string {
	if validation == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\nValidation:\n")

	// Confidence
	sb.WriteString(fmt.Sprintf("  Confidence:     %d%%\n", validation.Confidence))

	// Validated severity (if different)
	if validation.ValidatedSeverity != nil {
		sb.WriteString(fmt.Sprintf("  AI Severity:    %s\n", *validation.ValidatedSeverity))
	}

	// Taint propagation
	if validation.TaintPropagation != "" {
		sb.WriteString(fmt.Sprintf("  Reachability:   %s\n", validation.TaintPropagation))
	}

	// Exposure level
	if validation.Exposure != nil {
		exposureDesc := getExposureDescription(*validation.Exposure)
		sb.WriteString(fmt.Sprintf("  Exposure:       %d (%s)\n", *validation.Exposure, exposureDesc))
	}

	// Explanation
	if validation.Explanation != "" {
		sb.WriteString(fmt.Sprintf("  Analysis:       %s\n", validation.Explanation))
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

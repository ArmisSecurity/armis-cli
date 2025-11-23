package output

import (
        "fmt"
        "io"
        "os"
        "os/exec"
        "path/filepath"
        "sort"
        "strings"
        "time"

        "github.com/silk-security/armis-cli/internal/model"
)

type HumanFormatter struct{}

type GitBlameInfo struct {
        Author    string
        Email     string
        Date      string
        CommitSHA string
}

type FindingGroup struct {
        Key      string
        Label    string
        Findings []model.Finding
}

func (f *HumanFormatter) Format(result *model.ScanResult, w io.Writer) error {
        return f.FormatWithOptions(result, w, FormatOptions{GroupBy: "none"})
}

func (f *HumanFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
        fmt.Fprintf(w, "  ARMIS SECURITY SCAN RESULTS\n")
        fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "Scan ID:     %s\n", result.ScanID)
        fmt.Fprintf(w, "Status:      %s\n", result.Status)
        fmt.Fprintf(w, "\n")

        renderSummaryDashboard(w, result)
        fmt.Fprintf(w, "\n")

        if len(result.Findings) > 0 {
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "  FINDINGS\n")
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "\n")

                if opts.GroupBy != "" && opts.GroupBy != "none" {
                        groups := groupFindings(result.Findings, opts.GroupBy)
                        renderGroupedFindings(w, groups, opts)
                } else {
                        sortedFindings := sortFindingsBySeverity(result.Findings)
                        renderFindings(w, sortedFindings, opts)
                }
        }

        fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
        fmt.Fprintf(w, "\n")

        return nil
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

const (
        colorReset     = "\033[0m"
        colorRed       = "\033[31m"
        colorOrange    = "\033[33m"
        colorYellow    = "\033[93m"
        colorBlue      = "\033[34m"
        colorGray      = "\033[90m"
        colorBgRed     = "\033[101m"
        colorBold      = "\033[1m"
        colorUnderline = "\033[4m"
)

func init() {
        if strings.Contains(strings.ToLower(fmt.Sprintf("%v", os.Getenv("TERM"))), "dumb") {
                disableColors()
        }
}

func disableColors() {
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
        } else {
                return colorBgRed + colorBold + line + colorReset
        }
}

func detectLanguage(filename string) string {
        if filename == "" {
                return ""
        }
        
        ext := strings.ToLower(filepath.Ext(filename))
        langMap := map[string]string{
                ".abap":      "abap",
                ".adb":       "ada",
                ".ads":       "ada",
                ".ada":       "ada",
                ".agda":      "agda",
                ".als":       "alloy",
                ".apib":      "apiblueprint",
                ".apl":       "apl",
                ".applescript": "applescript",
                ".scpt":      "applescript",
                ".arc":       "arc",
                ".ino":       "arduino",
                ".as":        "actionscript",
                ".asciidoc":  "asciidoc",
                ".adoc":      "asciidoc",
                ".asc":       "asciidoc",
                ".ash":       "ash",
                ".asm":       "assembly",
                ".s":         "assembly",
                ".nasm":      "assembly",
                ".au3":       "autoit",
                ".awk":       "awk",
                ".bal":       "ballerina",
                ".bat":       "batch",
                ".cmd":       "batch",
                ".befunge":   "befunge",
                ".bib":       "bibtex",
                ".bison":     "bison",
                ".blade":     "blade",
                ".bf":        "brainfuck",
                ".b":         "brainfuck",
                ".brs":       "brightscript",
                ".c":         "c",
                ".h":         "c",
                ".cats":      "c",
                ".idc":       "c",
                ".w":         "c",
                ".cs":        "csharp",
                ".csx":       "csharp",
                ".cpp":       "cpp",
                ".cc":        "cpp",
                ".cxx":       "cpp",
                ".hpp":       "cpp",
                ".hh":        "cpp",
                ".hxx":       "cpp",
                ".c++":       "cpp",
                ".h++":       "cpp",
                ".cmake":     "cmake",
                ".cbl":       "cobol",
                ".cob":       "cobol",
                ".cpy":       "cobol",
                ".coffee":    "coffeescript",
                ".cfm":       "coldfusion",
                ".cfc":       "coldfusion",
                ".lisp":      "commonlisp",
                ".lsp":       "commonlisp",
                ".cl":        "commonlisp",
                ".coq":       "coq",
                ".cr":        "crystal",
                ".css":       "css",
                ".cu":        "cuda",
                ".cuh":       "cuda",
                ".d":         "d",
                ".di":        "d",
                ".dart":      "dart",
                ".diff":      "diff",
                ".patch":     "diff",
                ".dockerfile": "dockerfile",
                ".dot":       "dot",
                ".gv":        "dot",
                ".dylan":     "dylan",
                ".e":         "eiffel",
                ".ex":        "elixir",
                ".exs":       "elixir",
                ".elm":       "elm",
                ".el":        "elisp",
                ".emacs":     "elisp",
                ".erl":       "erlang",
                ".hrl":       "erlang",
                ".fs":        "fsharp",
                ".fsi":       "fsharp",
                ".fsx":       "fsharp",
                ".factor":    "factor",
                ".fy":        "fancy",
                ".purs":      "purescript",
                ".f":         "fortran",
                ".f90":       "fortran",
                ".f95":       "fortran",
                ".for":       "fortran",
                ".fth":       "forth",
                ".4th":       "forth",
                ".ftl":       "freemarker",
                ".g4":        "antlr",
                ".gd":        "gdscript",
                ".glsl":      "glsl",
                ".vert":      "glsl",
                ".frag":      "glsl",
                ".geo":       "glsl",
                ".gml":       "gml",
                ".go":        "go",
                ".gql":       "graphql",
                ".graphql":   "graphql",
                ".groovy":    "groovy",
                ".gvy":       "groovy",
                ".gy":        "groovy",
                ".gsh":       "groovy",
                ".hack":      "hack",
                ".haml":      "haml",
                ".handlebars": "handlebars",
                ".hbs":       "handlebars",
                ".hs":        "haskell",
                ".lhs":       "haskell",
                ".hx":        "haxe",
                ".hxsl":      "haxe",
                ".hlsl":      "hlsl",
                ".html":      "html",
                ".htm":       "html",
                ".http":      "http",
                ".hy":        "hy",
                ".pro":       "idris",
                ".idr":       "idris",
                ".ni":        "inform7",
                ".i7x":       "inform7",
                ".iss":       "innosetup",
                ".io":        "io",
                ".ik":        "ioke",
                ".java":      "java",
                ".js":        "javascript",
                ".mjs":       "javascript",
                ".cjs":       "javascript",
                ".jsx":       "jsx",
                ".json":      "json",
                ".json5":     "json5",
                ".jsonnet":   "jsonnet",
                ".jl":        "julia",
                ".kt":        "kotlin",
                ".kts":       "kotlin",
                ".lean":      "lean",
                ".hlean":     "lean",
                ".less":      "less",
                ".ly":        "lilypond",
                ".ily":       "lilypond",
                ".lol":       "lolcode",
                ".lua":       "lua",
                ".m":         "objectivec",
                ".mm":        "objectivec",
                ".mk":        "makefile",
                ".mak":       "makefile",
                ".md":        "markdown",
                ".markdown":  "markdown",
                ".mkd":       "markdown",
                ".max":       "maxscript",
                ".ms":        "maxscript",
                ".mel":       "mel",
                ".moo":       "moocode",
                ".n":         "nemerle",
                ".nim":       "nim",
                ".nix":       "nix",
                ".nu":        "nushell",
                ".ml":        "ocaml",
                ".mli":       "ocaml",
                ".objdump":   "objdump",
                ".odin":      "odin",
                ".p":         "openscad",
                ".scad":      "openscad",
                ".ox":        "ox",
                ".oxh":       "ox",
                ".ozf":       "oz",
                ".oz":        "oz",
                ".pwn":       "pawn",
                ".inc":       "pawn",
                ".peg":       "peg",
                ".pl":        "perl",
                ".pm":        "perl",
                ".t":         "perl",
                ".php":       "php",
                ".phtml":     "php",
                ".php3":      "php",
                ".php4":      "php",
                ".php5":      "php",
                ".phps":      "php",
                ".pig":       "pig",
                ".pike":      "pike",
                ".pmod":      "pike",
                ".pogo":      "pogoscript",
                ".pony":      "pony",
                ".ps1":       "powershell",
                ".psm1":      "powershell",
                ".psd1":      "powershell",
                ".prolog":    "prolog",
                ".proto":     "protobuf",
                ".pp":        "puppet",
                ".py":        "python",
                ".pyw":       "python",
                ".pyx":       "python",
                ".pxd":       "python",
                ".pxi":       "python",
                ".q":         "q",
                ".qml":       "qml",
                ".r":         "r",
                ".R":         "r",
                ".rkt":       "racket",
                ".rktl":      "racket",
                ".raku":      "raku",
                ".rakumod":   "raku",
                ".re":        "reason",
                ".rei":       "reason",
                ".red":       "red",
                ".reds":      "red",
                ".rst":       "restructuredtext",
                ".rest":      "restructuredtext",
                ".rexx":      "rexx",
                ".ring":      "ring",
                ".robot":     "robotframework",
                ".rb":        "ruby",
                ".rbw":       "ruby",
                ".rake":      "ruby",
                ".rs":        "rust",
                ".sas":       "sas",
                ".sass":      "sass",
                ".scala":     "scala",
                ".sc":        "scala",
                ".scm":       "scheme",
                ".ss":        "scheme",
                ".scss":      "scss",
                ".sh":        "bash",
                ".bash":      "bash",
                ".zsh":       "bash",
                ".ksh":       "bash",
                ".csh":       "bash",
                ".fish":      "fish",
                ".sml":       "sml",
                ".sol":       "solidity",
                ".rq":        "sparql",
                ".sparql":    "sparql",
                ".sql":       "sql",
                ".stan":      "stan",
                ".do":        "stata",
                ".ado":       "stata",
                ".styl":      "stylus",
                ".sv":        "systemverilog",
                ".svh":       "systemverilog",
                ".swift":     "swift",
                ".tcl":       "tcl",
                ".tex":       "latex",
                ".textile":   "textile",
                ".thrift":    "thrift",
                ".toml":      "toml",
                ".ts":        "typescript",
                ".tsx":       "tsx",
                ".ttl":       "turtle",
                ".twig":      "twig",
                ".txt":       "text",
                ".vala":      "vala",
                ".vapi":      "vala",
                ".v":         "verilog",
                ".vh":        "verilog",
                ".vhdl":      "vhdl",
                ".vhd":       "vhdl",
                ".vim":       "vim",
                ".vue":       "vue",
                ".wast":      "webassembly",
                ".wat":       "webassembly",
                ".wgsl":      "wgsl",
                ".x10":       "x10",
                ".xc":        "xc",
                ".xml":       "xml",
                ".xsl":       "xml",
                ".xsd":       "xml",
                ".xpath":     "xpath",
                ".xq":        "xquery",
                ".xquery":    "xquery",
                ".xslt":      "xslt",
                ".xtend":     "xtend",
                ".yaml":      "yaml",
                ".yml":       "yaml",
                ".yang":      "yang",
                ".zig":       "zig",
                ".clj":       "clojure",
                ".cljs":      "clojure",
                ".cljc":      "clojure",
                ".edn":       "clojure",
        }
        
        if lang, ok := langMap[ext]; ok {
                return lang
        }
        
        return ""
}

func renderSummaryDashboard(w io.Writer, result *model.ScanResult) {
        width := 63
        
        fmt.Fprintf(w, "┌%s┐\n", strings.Repeat("─", width-2))
        fmt.Fprintf(w, "│  📊 SCAN SUMMARY%s│\n", strings.Repeat(" ", width-19))
        fmt.Fprintf(w, "├%s┤\n", strings.Repeat("─", width-2))
        
        fmt.Fprintf(w, "│  Total Findings: %-42d│\n", result.Summary.Total)
        
        if result.Summary.FilteredNonExploitable > 0 {
                fmt.Fprintf(w, "│  Filtered (Non-Exploitable): %-31d│\n", result.Summary.FilteredNonExploitable)
        }
        
        fmt.Fprintf(w, "│%s│\n", strings.Repeat(" ", width-2))
        
        severities := []model.Severity{
                model.SeverityCritical,
                model.SeverityHigh,
                model.SeverityMedium,
                model.SeverityLow,
                model.SeverityInfo,
        }
        
        for _, sev := range severities {
                count := result.Summary.BySeverity[sev]
                if count > 0 {
                        icon := getSeverityIcon(sev)
                        label := fmt.Sprintf("%s %s:", icon, sev)
                        padding := width - len(label) - len(fmt.Sprintf("%d", count)) - 4
                        fmt.Fprintf(w, "│  %-*s %d%s│\n", len(label)+padding, label, count, strings.Repeat(" ", 1))
                }
        }
        
        fmt.Fprintf(w, "└%s┘\n", strings.Repeat("─", width-2))
}

func renderFindings(w io.Writer, findings []model.Finding, opts FormatOptions) {
        for i, finding := range findings {
                if i > 0 {
                        fmt.Fprintf(w, "\n")
                }

                renderFinding(w, finding, opts)

                if i < len(findings)-1 {
                        fmt.Fprintf(w, "\n───────────────────────────────────────────────────────────────\n")
                }
        }
        fmt.Fprintf(w, "\n")
}

func renderFinding(w io.Writer, finding model.Finding, opts FormatOptions) {
        color := getSeverityColor(finding.Severity)
        icon := getSeverityIcon(finding.Severity)
        
        fmt.Fprintf(w, "%s %s%s%s\n", icon, color, finding.Severity, colorReset)
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "%s\n", finding.Title)
        fmt.Fprintf(w, "\n")

        if finding.FindingCategory != "" {
                fmt.Fprintf(w, "Category:    %s\n", finding.FindingCategory)
        }

        if len(finding.CVEs) > 0 {
                fmt.Fprintf(w, "CVE:         %s\n", strings.Join(finding.CVEs, ", "))
        }

        if len(finding.CWEs) > 0 {
                fmt.Fprintf(w, "CWE:         %s\n", strings.Join(finding.CWEs, ", "))
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
                fmt.Fprintf(w, "Location:    %s\n", location)

                if opts.RepoPath != "" && finding.StartLine > 0 {
                        if blameInfo := getGitBlame(opts.RepoPath, finding.File, finding.StartLine); blameInfo != nil {
                                maskedEmail := maskEmail(blameInfo.Email)
                                fmt.Fprintf(w, "Git Blame:   %s <%s> (%s, %s)\n", 
                                        blameInfo.Author, maskedEmail, blameInfo.Date, blameInfo.CommitSHA[:7])
                        }
                }
        }

        if finding.CodeSnippet != "" {
                fmt.Fprintf(w, "\nCode:\n")
                fmt.Fprintf(w, "%s\n", formatCodeSnippet(finding))
        }
}

func renderGroupedFindings(w io.Writer, groups []FindingGroup, opts FormatOptions) {
        for i, group := range groups {
                if i > 0 {
                        fmt.Fprintf(w, "\n")
                }

                fmt.Fprintf(w, "┌%s┐\n", strings.Repeat("─", 61))
                fmt.Fprintf(w, "│ %s%s│\n", group.Label, strings.Repeat(" ", 61-len(group.Label)-2))
                fmt.Fprintf(w, "│ Count: %-53d│\n", len(group.Findings))
                fmt.Fprintf(w, "└%s┘\n", strings.Repeat("─", 61))
                fmt.Fprintf(w, "\n")

                for j, finding := range group.Findings {
                        if j > 0 {
                                fmt.Fprintf(w, "\n")
                        }
                        renderFinding(w, finding, opts)
                        if j < len(group.Findings)-1 {
                                fmt.Fprintf(w, "\n───────────────────────────────────────────────────────────────\n")
                        }
                }

                if i < len(groups)-1 {
                        fmt.Fprintf(w, "\n\n")
                }
        }
        fmt.Fprintf(w, "\n")
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
                                key = "No CWE"
                        }
                case "severity":
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

func getGitBlame(repoPath, file string, line int) *GitBlameInfo {
        if !isGitRepo(repoPath) {
                return nil
        }

        filePath := filepath.Join(repoPath, file)
        if _, err := os.Stat(filePath); os.IsNotExist(err) {
                return nil
        }

        cmd := exec.Command("git", "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--porcelain", file)
        cmd.Dir = repoPath
        output, err := cmd.Output()
        if err != nil {
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
                        if ts, err := time.Parse("1136239445", timestamp); err == nil {
                                info.Date = ts.Format("2006-01-02")
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

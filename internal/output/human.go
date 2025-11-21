package output

import (
        "fmt"
        "io"
        "os"
        "path/filepath"
        "sort"
        "strings"

        "github.com/silk-security/Moose-CLI/internal/model"
)

type HumanFormatter struct{}

func (f *HumanFormatter) Format(result *model.ScanResult, w io.Writer) error {
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
        fmt.Fprintf(w, "  ARMIS SECURITY SCAN RESULTS\n")
        fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "Scan ID:     %s\n", result.ScanID)
        fmt.Fprintf(w, "Status:      %s\n", result.Status)
        fmt.Fprintf(w, "\n")

        fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
        fmt.Fprintf(w, "  SUMMARY\n")
        fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
        fmt.Fprintf(w, "\n")
        fmt.Fprintf(w, "Total Findings: %d\n", result.Summary.Total)
        fmt.Fprintf(w, "\n")

        fmt.Fprintf(w, "By Severity:\n")
        severities := []model.Severity{
                model.SeverityCritical,
                model.SeverityHigh,
                model.SeverityMedium,
                model.SeverityLow,
                model.SeverityInfo,
        }
        for _, sev := range severities {
                count := result.Summary.BySeverity[sev]
                icon := getSeverityIcon(sev)
                color := getSeverityColor(sev)
                fmt.Fprintf(w, "  %s %s%-8s%s %d\n", icon, color, sev, colorReset, count)
        }
        fmt.Fprintf(w, "\n")

        fmt.Fprintf(w, "By Type:\n")
        for findingType, count := range result.Summary.ByType {
                fmt.Fprintf(w, "  • %-15s %d\n", findingType, count)
        }
        fmt.Fprintf(w, "\n")

        if len(result.Findings) > 0 {
                sortedFindings := sortFindingsBySeverity(result.Findings)
                
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "  FINDINGS\n")
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "\n")

                for i, finding := range sortedFindings {
                        if i > 0 {
                                fmt.Fprintf(w, "\n")
                        }

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
                        }

                        if finding.CodeSnippet != "" {
                                fmt.Fprintf(w, "\nCode:\n")
                                fmt.Fprintf(w, "%s\n", formatCodeSnippet(finding))
                        }

                        if i < len(sortedFindings)-1 {
                                fmt.Fprintf(w, "\n───────────────────────────────────────────────────────────────\n")
                        }
                }
                fmt.Fprintf(w, "\n")
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
        colorBgRed     = "\033[41m"
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
        
        for i, line := range lines {
                lineNum := i + 1
                
                if finding.StartLine > 0 && finding.EndLine > 0 {
                        if lineNum >= finding.StartLine && lineNum <= finding.EndLine {
                                if finding.StartColumn > 0 && finding.EndColumn > 0 {
                                        highlighted := highlightColumns(line, finding.StartColumn, finding.EndColumn, lineNum, finding.StartLine, finding.EndLine)
                                        formatted = append(formatted, highlighted)
                                } else {
                                        formatted = append(formatted, colorBgRed+colorBold+line+colorReset)
                                }
                        } else {
                                formatted = append(formatted, line)
                        }
                } else {
                        formatted = append(formatted, line)
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

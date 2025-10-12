package output

import (
        "fmt"
        "io"
        "os"
        "strings"
        "text/tabwriter"

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
        fmt.Fprintf(w, "Started:     %s\n", result.StartedAt.Format("2006-01-02 15:04:05"))
        fmt.Fprintf(w, "Completed:   %s\n", result.EndedAt.Format("2006-01-02 15:04:05"))
        fmt.Fprintf(w, "Duration:    %s\n", result.EndedAt.Sub(result.StartedAt).Round(1))
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
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "  FINDINGS\n")
                fmt.Fprintf(w, "───────────────────────────────────────────────────────────────\n")
                fmt.Fprintf(w, "\n")

                tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
                fmt.Fprintf(tw, "SEVERITY\tTYPE\tTITLE\tFILE\tLINE\n")
                fmt.Fprintf(tw, "────────\t────\t─────\t────\t────\n")

                for _, finding := range result.Findings {
                        color := getSeverityColor(finding.Severity)
                        location := ""
                        if finding.File != "" {
                                location = finding.File
                                if finding.Line > 0 {
                                        location = fmt.Sprintf("%s:%d", location, finding.Line)
                                }
                        }

                        title := finding.Title
                        if len(title) > 50 {
                                title = title[:47] + "..."
                        }

                        fmt.Fprintf(tw, "%s%s%s\t%s\t%s\t%s\t\n",
                                color, finding.Severity, colorReset,
                                finding.Type,
                                title,
                                location,
                        )
                }
                tw.Flush()
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
        colorReset  = "\033[0m"
        colorRed    = "\033[31m"
        colorOrange = "\033[33m"
        colorYellow = "\033[93m"
        colorBlue   = "\033[34m"
        colorGray   = "\033[90m"
)

func init() {
        if strings.Contains(strings.ToLower(fmt.Sprintf("%v", os.Getenv("TERM"))), "dumb") {
                disableColors()
        }
}

func disableColors() {
}

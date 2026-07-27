package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/history"
	"github.com/spf13/cobra"
)

// statusFormat is the output format for `scan status`. Defaults to "human"
// but may be flipped to "json" to feed downstream tooling.
var statusFormat string

// statusFormats enumerates the accepted values for --format on the status
// subcommand. We keep the surface narrower than the sibling scan commands
// on purpose: SARIF/JUnit make no sense for a single status record.
var statusFormats = []string{statusFormatHuman, statusFormatJSON}

const (
	statusFormatHuman = "human"
	statusFormatJSON  = "json"

	// Status enum values worth branching on for terminal styling.
	statusValCompleted = "COMPLETED"
	statusValFailed    = "FAILED"
)

// scanStatusCmd is `armis-cli scan status [scan_id]`. It fetches the current
// state of a scan from `GET /api/v1/ingest/status/`.
//
// The scan_id argument is optional: with no argument, the command reads the
// most recently initiated scan for the current (base_url, tenant_id) out of
// the on-disk scan-history store (`~/.armis/scan-history.json`) that
// `scan repo`, `scan image`, and `scan sbom` populate. This lets developers
// re-check a scan without cutting and pasting the ID.
var scanStatusCmd = &cobra.Command{
	Use:   "status [scan_id]",
	Short: "Fetch the status of a scan",
	Long: `Fetch the current status of a scan initiated via 'armis-cli scan'.

When invoked without a scan_id, the command uses the most recent scan_id
recorded locally for the current (base URL, tenant) pair. Every successful
'scan repo', 'scan image', and 'scan sbom' automatically records its
scan_id in ~/.armis/scan-history.json (created 0600) so that this fallback
works out of the box.`,
	Example: `  # Look up a specific scan
  $ armis-cli scan status a1b2c3d4-...

  # Re-check the most recently initiated scan on this machine
  $ armis-cli scan status

  # Machine-readable output
  $ armis-cli scan status --format json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanStatus,
}

// runScanStatus is factored out of the cobra.Command struct so it can be
// exercised directly from tests without going through Execute().
func runScanStatus(cmd *cobra.Command, args []string) error {
	format := strings.ToLower(strings.TrimSpace(statusFormat))
	if !isValidStatusFormat(format) {
		return fmt.Errorf("invalid --format value %q: must be one of %v", statusFormat, statusFormats)
	}

	authProvider, err := getAuthProvider(cmd.Context())
	if err != nil {
		return err
	}
	if authProvider == nil {
		return fmt.Errorf("internal error: nil auth provider")
	}

	tid, err := authProvider.GetTenantID(cmd.Context())
	if err != nil {
		return err
	}

	baseURL := resolveDataPlaneURL(cmd.Context(), authProvider)
	client, err := api.NewClient(baseURL, authProvider, debug, time.Duration(uploadTimeout)*time.Minute,
		clientOptionsForBaseURL(baseURL)...)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	scanID, historyEntry, err := resolveScanID(args, baseURL, tid)
	if err != nil {
		return err
	}

	ctx, cancel := NewSignalContext()
	defer cancel()

	statusResp, err := client.GetIngestStatus(ctx, tid, scanID)
	if err != nil {
		return translateStatusError(err, scanID)
	}
	if statusResp == nil || len(statusResp.Data) == 0 {
		return fmt.Errorf("no status data returned for scan %s (check the scan_id and tenant)", scanID)
	}

	data := statusResp.Data[0]

	return renderStatus(cmd.OutOrStdout(), format, data, historyEntry)
}

// resolveScanID returns the scan_id the user wants status for. When one is
// supplied on the command line it wins; otherwise we fall back to the newest
// entry in the history store for the (baseURL, tenantID) pair. When the
// fallback fails we return a descriptive error so the user knows their
// options.
func resolveScanID(args []string, baseURL, tenantID string) (string, *history.Entry, error) {
	if len(args) == 1 {
		id := strings.TrimSpace(args[0])
		if id == "" {
			return "", nil, errors.New("scan_id argument is empty; pass a non-empty scan_id or omit the argument to use the last scan on this machine")
		}
		return id, nil, nil
	}

	entry, err := history.NewStore().Latest(baseURL, tenantID)
	if err != nil || entry == nil {
		return "", nil, fmt.Errorf(
			"no scan_id provided and no recent scan recorded for tenant %s on %s. "+
				"Run 'armis-cli scan repo|image|sbom' first, or pass an explicit scan_id",
			tenantID, baseURL)
	}
	return entry.ScanID, entry, nil
}

// translateStatusError wraps API errors from GetIngestStatus with more
// actionable text. The upstream error already carries the raw HTTP body,
// but a "check the scan_id" hint on 404 is worth a lot more than the body
// alone.
func translateStatusError(err error, scanID string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "status 404"):
		return fmt.Errorf("scan %s not found (check the scan_id and that the tenant matches)", scanID)
	case strings.Contains(msg, "status 403"):
		return fmt.Errorf("access denied for scan %s: your role is not permitted for this endpoint", scanID)
	case strings.Contains(msg, "status 422"):
		return fmt.Errorf("invalid scan_id %q: %w", scanID, err)
	default:
		return fmt.Errorf("failed to fetch scan status: %w", err)
	}
}

// isValidStatusFormat reports whether f is one of the values accepted by
// --format.
func isValidStatusFormat(f string) bool {
	for _, v := range statusFormats {
		if f == v {
			return true
		}
	}
	return false
}

// scanStatusJSON is the JSON envelope emitted when --format=json. It embeds
// the raw API record so downstream tools can rely on the same field names
// as the server response, plus a top-level `scan_id` for convenience.
type scanStatusJSON struct {
	ScanID     string                 `json:"scan_id"`
	FromCache  bool                   `json:"from_scan_history,omitempty"`
	StatusData model.IngestStatusData `json:"status"`
}

// renderStatus writes the status record in the requested format. Human
// output is the default; JSON mirrors the API record verbatim.
func renderStatus(w io.Writer, format string, data model.IngestStatusData, historyEntry *history.Entry) error {
	if format == statusFormatJSON {
		payload := scanStatusJSON{
			ScanID:     data.ScanID,
			FromCache:  historyEntry != nil,
			StatusData: data,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	renderHumanStatus(w, data, historyEntry)
	return nil
}

// renderHumanStatus prints the record as a small, labeled key/value block.
// The keys align to a fixed 18-column gutter so the values line up under
// each other in every terminal.
func renderHumanStatus(w io.Writer, d model.IngestStatusData, historyEntry *history.Entry) {
	styles := output.GetStyles()

	statusVal := strings.ToUpper(d.ScanStatus)
	statusRendered := styles.Bold.Render(statusVal)
	// Highlight terminal states in matching accent colors: green for
	// completed, red for failed. Anything else keeps the plain bold styling.
	switch statusVal {
	case statusValCompleted:
		statusRendered = styles.StatusComplete.Render(statusVal)
	case statusValFailed:
		statusRendered = styles.CriticalBadge.Render(" " + statusVal + " ")
	}

	writeLine := func(label, value string) {
		_, _ = fmt.Fprintf(w, "  %-18s %s\n", styles.MutedText.Render(label), value)
	}

	_, _ = fmt.Fprintln(w, styles.Bold.Render("Scan Status"))
	_, _ = fmt.Fprintln(w)
	writeLine("Scan ID:", styles.ScanID.Render(d.ScanID))
	writeLine("Status:", statusRendered)
	if d.ArtifactType != "" {
		writeLine("Artifact Type:", d.ArtifactType)
	}
	if d.ScanType != "" {
		writeLine("Scan Type:", d.ScanType)
	}
	if d.FileName != "" {
		writeLine("File:", d.FileName)
	}
	if d.FileBytes > 0 {
		writeLine("File Size:", formatBytes(d.FileBytes))
	}
	if d.StartedAt != "" {
		writeLine("Started:", d.StartedAt)
	}
	if d.UpdatedAt != "" {
		writeLine("Updated:", d.UpdatedAt)
	}
	if d.CompletedAt != nil && *d.CompletedAt != "" {
		writeLine("Completed:", *d.CompletedAt)
	}
	if d.ExpirationTime != "" {
		writeLine("Expires:", d.ExpirationTime)
	}
	if d.LastError != nil && *d.LastError != "" {
		writeLine("Last Error:", styles.CriticalBadge.Render(" ERROR ")+" "+*d.LastError)
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, styles.MutedText.Render(scanStatusHint(statusVal)))
	if historyEntry != nil {
		_, _ = fmt.Fprintln(w, styles.MutedText.Render(fmt.Sprintf("Resolved scan_id from local history (%s).", historyEntry.Artifact)))
	}
}

// scanStatusHint returns a one-line, user-facing description of the current
// state. It covers every ArtifactScanStatus enum value defined by the API
// so the caller always sees something useful (never an empty hint).
func scanStatusHint(status string) string {
	switch status {
	case "PENDING_UPLOAD":
		return "Waiting for the artifact upload to reach S3."
	case "UPLOADED":
		return "Upload complete; the API is preparing to dispatch the scan."
	case "INITIATED":
		return "Scan queued; analysis has not started yet."
	case "IN_PROGRESS":
		return "Analysis is running. Re-run this command to refresh."
	case "COMPLETED":
		return "Scan finished — retrieve findings with the scan command's output."
	case "FAILED":
		return "Scan failed. See Last Error above for details."
	case "STOPPED":
		return "Scan was stopped before it could complete."
	default:
		return "Unknown scan status."
	}
}

// formatBytes renders a byte count as a human-friendly size (KiB/MiB/...).
// Duplicated from internal/api rather than exported to keep the api
// package's surface small — this is a leaf-level presentation helper.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ensure the context.Context and time imports don't get pruned when the
// linter checks a stripped-down build. (Cobra pulls both indirectly, but
// keeping the reference explicit here documents that the RunE relies on
// cmd.Context()'s cancellation.)
var _ = context.TODO
var _ = time.Second

func init() {
	scanStatusCmd.Flags().StringVar(&statusFormat, "format", "human",
		"Output format: human, json (default: human)")
	_ = scanStatusCmd.RegisterFlagCompletionFunc("format", fixedCompletions(statusFormats, map[string]string{
		"human": "Human-readable status block",
		"json":  "Machine-readable JSON envelope",
	}))
	scanCmd.AddCommand(scanStatusCmd)
}

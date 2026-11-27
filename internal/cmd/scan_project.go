package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/project"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/spf13/cobra"
)

// validatePublishFlags checks --project, --report, --sync and --async before
// the scan does any I/O, and decides whether the scan is published. An invalid
// project name is rejected here, with the rule it breaks and a valid example,
// never trimmed or renamed.
func validatePublishFlags(cmd *cobra.Command) (project.Decision, error) {
	// cobra enforces this for parsed flags; repeat it for direct callers.
	if syncScan && asyncScan {
		return project.Decision{}, fmt.Errorf("--sync and --async cannot be used together")
	}

	// A flag that was passed but is empty (`--project "$UNSET_VAR"`) is still
	// validated, so it fails as an empty name instead of silently scanning
	// without a project.
	if projectName != "" || cmd.Flags().Changed("project") {
		if err := project.ValidateName(projectName); err != nil {
			return project.Decision{}, err
		}
	}

	if reportScan && projectName == "" {
		return project.Decision{}, fmt.Errorf("--report publishes the scan to a project, so it needs --project " +
			"(for example: --project my-service --report)")
	}

	if len(projectLabels) > 0 && projectName == "" {
		return project.Decision{}, fmt.Errorf("--project-label labels the project a scan creates, so it needs --project " +
			"(for example: --project my-service --project-label team-payments)")
	}
	labels, err := project.NormalizeLabels(projectLabels)
	if err != nil {
		return project.Decision{}, fmt.Errorf("invalid --project-label: %w", err)
	}
	projectLabels = labels

	// Like --project, a --branch that was passed but is empty still fails.
	if runBranch != "" || cmd.Flags().Changed("branch") {
		if projectName == "" {
			return project.Decision{}, fmt.Errorf("--branch names the branch a published run is filed under, so it " +
				"needs --project (for example: --project my-service --branch main)")
		}
		if err := repo.ValidateBranch(runBranch); err != nil {
			return project.Decision{}, fmt.Errorf("invalid --branch: %w", err)
		}
	}

	ci, ciVar := progress.DetectCI()
	decision := project.Decide(projectName, reportScan, ci, ciVar)

	// A partial scan would replace the project's findings with those of a few
	// files and under-report its risk, so it is not published.
	if decision.Publish && (len(includeFiles) > 0 || cmd.Flags().Changed("changed")) {
		return project.Decision{}, fmt.Errorf("--changed and --include-files scan only part of the codebase, "+
			"so the scan cannot be published to project %q: a partial run would under-report the project's findings. "+
			"Drop --project to gate on just those files, or scan the whole codebase to publish", projectName)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] project=%q publish=%v trigger=%q reason=%q\n",
			projectName, decision.Publish, decision.Trigger, decision.Reason)
	}
	return decision, nil
}

// projectRunsNote tells the user, when the server does not say whether the
// scan was recorded as a run of its project, that it was not: a server that
// predates project runs records none, so a CI log must not suggest the scan
// will show up under the project.
const projectRunsNote = "Note: Armis does not record CLI scans as runs of a project yet, " +
	"so this scan will not appear under it. It still runs and gates as usual."

// projectRunsDisabledNote is the note for a tenant that does not record CLI
// scans as project runs yet.
const projectRunsDisabledNote = "Note: Armis does not record CLI scans as runs of a project " +
	"for this tenant yet, so this scan will not appear under it. It still runs and gates as usual."

// announceProject tells the user which project the scan is published to. A
// project that cannot record the scan as one of its runs (archived, or not a
// CLI project) is announced as found, with a warning, rather than as used.
func announceProject(res *project.Resolution, decision project.Decision) {
	styles := output.GetStyles()
	name := styles.Bold.Render(res.Project.Name)
	detail := styles.MutedText.Render(fmt.Sprintf("(%s; %s)", res.Project.ProjectID, decision.Reason))
	warning := res.StatusWarning()
	verb := "Using project"
	switch {
	case res.Created:
		verb = "Created project"
	case warning != "":
		verb = "Found project"
	}
	withLabels := ""
	if len(res.Labels) > 0 {
		withLabels = " " + styles.MutedText.Render("with labels "+strings.Join(res.Labels, ", "))
	}
	fmt.Fprintf(os.Stderr, "%s %s %s%s\n", styles.MutedText.Render(verb), name, detail, withLabels)
	if warning != "" {
		cli.PrintWarning(warning)
	}
	if skipped := labelsSkippedWarning(res); skipped != "" {
		cli.PrintWarning(skipped)
	}
}

// reportProjectRun tells the user whether the scan was recorded as a run of
// its project, as /ingest/scan said: run is nil when the server predates
// project runs. What announceProject already warned of is not repeated.
func reportProjectRun(res *project.Resolution, run *model.ProjectRun) {
	styles := output.GetStyles()
	name := res.Project.Name
	warned := res.StatusWarning() != ""
	switch {
	case run == nil:
		if warned {
			return
		}
		fmt.Fprintln(os.Stderr, styles.MutedText.Render(projectRunsNote))
	case run.Recorded:
		fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
			styles.MutedText.Render("Recorded as run"),
			styles.ScanID.Render(util.StripControl(run.RunID)),
			styles.MutedText.Render("of project"),
			styles.Bold.Render(name))
		if res.Project.Status == model.ProjectStatusPaused {
			fmt.Fprintln(os.Stderr, styles.MutedText.Render(fmt.Sprintf(
				"Project %q is paused: its schedules are stopped, but runs that name it, "+
					"like this one, are still recorded.", name)))
		}
	case warned && (run.Reason == model.ProjectRunProjectArchived || run.Reason == model.ProjectRunProjectNotCLI):
		// announceProject warned of it.
		return
	case run.Reason == model.ProjectRunDisabled:
		fmt.Fprintln(os.Stderr, styles.MutedText.Render(projectRunsDisabledNote))
	default:
		cli.PrintWarning(projectRunWarning(name, run.Reason))
	}
	// Set off from the scan's progress, as "Scan initiated" is.
	fmt.Fprintln(os.Stderr)
}

// projectRunWarning explains why a scan was not recorded as a run of the
// project it names.
func projectRunWarning(name, reason string) string {
	const still = "It still runs and gates as usual."
	switch reason {
	case model.ProjectRunProjectArchived:
		return fmt.Sprintf("project %q is archived, so this scan is not recorded as a run of it. %s", name, still)
	case model.ProjectRunProjectNotCLI:
		return fmt.Sprintf("project %q is not a CLI project, so this scan is not recorded as a run of it. %s "+
			"Name a project of its own for CLI scans.", name, still)
	case model.ProjectRunProjectNotFound:
		return fmt.Sprintf("project %q was not found when the scan started (was it deleted?), "+
			"so this scan is not recorded as a run of it. %s", name, still)
	case model.ProjectRunInvalidBranch:
		return fmt.Sprintf("Armis refused the branch name this scan sent, so it is not recorded as a run of project %q. "+
			"%s Name the branch with --branch.", name, still)
	default:
		return fmt.Sprintf("Armis could not record this scan as a run of project %q (%s). %s",
			name, util.StripControl(reason), still)
	}
}

// warnOnAsyncIgnoredFlags flags options that need results an async scan does
// not wait for.
func warnOnAsyncIgnoredFlags(cmd *cobra.Command) {
	if f := cmd.Flag("fail-on"); f != nil && f.Changed {
		cli.PrintWarning("--fail-on is not evaluated with --async: the command exits 0 once the scan is accepted")
	}
	if generateSBOM || generateVEX {
		cli.PrintWarning("with --async the SBOM/VEX documents are generated but not downloaded")
	}
	if len(bomTypes) > 0 {
		cli.PrintWarning("with --async the BOMs are generated but not downloaded")
	}
}

// asyncScanRecord is the JSON written for an accepted --async scan.
type asyncScanRecord struct {
	ScanID  string                  `json:"scan_id"`
	Status  string                  `json:"status"`
	Project *model.PublishedProject `json:"project,omitempty"`
}

// publishedProject identifies the project a published scan named, and the run
// it was recorded as, for the scan's JSON: the --async record's project, and
// the results' (nil for a scan that isn't published). Recorded is absent when
// the server does not say, as one that predates project runs does not.
func publishedProject(published *project.Resolution, decision project.Decision, run *model.ProjectRun) *model.PublishedProject {
	if published == nil {
		return nil
	}
	p := &model.PublishedProject{
		ProjectID: published.Project.ProjectID,
		Name:      published.Project.Name,
		Created:   published.Created,
		Labels:    published.Labels,
		Trigger:   decision.Trigger,
	}
	if run != nil {
		recorded := run.Recorded
		p.Recorded, p.RunID, p.Reason = &recorded, run.RunID, run.Reason
	}
	return p
}

// renderAsyncAccepted reports an accepted --async scan. There are no findings
// yet, so only JSON output gets a record (the scan ID and project). Other
// formats write nothing: an empty SARIF upload would close every open
// code-scanning alert.
func renderAsyncAccepted(cmd *cobra.Command, result *model.ScanResult, published *project.Resolution,
	decision project.Decision, run *model.ProjectRun) error {
	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s\n%s %s\n",
		styles.MutedText.Render("Scan accepted (--async): not waiting for results, so --fail-on is not evaluated."),
		styles.MutedText.Render("Check its progress with:"),
		"armis-cli scan status "+result.ScanID)

	effectiveFormat := strings.ToLower(cmdutil.EffectiveFormat(cmd, outputFile, format))
	if effectiveFormat != statusFormatJSON {
		if effectiveFormat != statusFormatHuman || outputFile != "" {
			cli.PrintWarning(fmt.Sprintf("--format %s writes no results with --async (there are none yet); "+
				"use --format json for a record of the accepted scan", effectiveFormat))
		}
		return nil
	}

	record := asyncScanRecord{ScanID: result.ScanID, Status: result.Status,
		Project: publishedProject(published, decision, run)}

	outputCfg, err := cmdutil.ResolveOutput(cmd, outputFile, statusFormatJSON, colorFlag)
	if err != nil {
		return err
	}
	defer outputCfg.Cleanup()

	enc := json.NewEncoder(outputCfg.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(record); err != nil {
		return fmt.Errorf("failed to write the scan record: %w", err)
	}
	return nil
}

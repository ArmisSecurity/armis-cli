package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/project"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
)

// Seams for tests: whether the session can ask questions, the setup's
// questions themselves, and where they read and write (the terminal; stdout
// keeps the scan's results).
var (
	isInteractive = cli.IsInteractive
	runSetupForm  = askProjectSetup

	setupIn  io.Reader = os.Stdin
	setupOut io.Writer = os.Stderr
)

// setupAllowed reports whether this run may ask the first-time project
// setup's questions: a developer's terminal (stdin and stderr), not CI, and
// neither --no-input nor ARMIS_NO_INPUT.
func setupAllowed(decision project.Decision) bool {
	if decision.Trigger != project.TriggerCLIDev || noInput || envSet("ARMIS_NO_INPUT") {
		return false
	}
	return isInteractive()
}

// envSet reports whether an environment variable is set to something other
// than a false-like value (0, false, no, off).
func envSet(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// The answers to "Set it up now?".
const (
	setupNow      = "now"
	setupDefaults = "defaults"
	setupCancel   = "cancel"
)

// The answers to the summary's question.
const (
	setupCreate = "create"
	setupEdit   = "edit"
)

// setupQuestions are the filter questions a setup asks: those the scan's
// .armisignore doesn't already answer. Labels are always asked.
type setupQuestions struct {
	Severity, Paths, Categories, CWEs bool
}

// questionsFor skips what the .armisignore answers. A severity: directive
// answers both the minimum severity and the severities to suppress, which
// both write severity: lines.
func questionsFor(ignore repo.IgnoreSummary) setupQuestions {
	return setupQuestions{
		Severity:   !ignore.Severities,
		Paths:      !ignore.Paths,
		Categories: !ignore.Categories,
		CWEs:       !ignore.CWEs,
	}
}

// skipped names what the .armisignore answers, for the line that says so.
func (q setupQuestions) skipped() []string {
	var out []string
	if !q.Severity {
		out = append(out, "minimum severity and severity")
	}
	if !q.Paths {
		out = append(out, "path excludes")
	}
	if !q.Categories {
		out = append(out, "categories")
	}
	if !q.CWEs {
		out = append(out, "CWEs")
	}
	return out
}

// setupAnswers are the setup's answers, as the form holds them.
type setupAnswers struct {
	MinSeverity  string
	PathExcludes string
	Severities   []string
	Categories   []string
	CWEs         string
	Labels       string
}

// toSetup turns the answers into a Setup, with the checks the form's fields
// run, keeping only the questions asked.
func (a setupAnswers) toSetup(q setupQuestions) (*project.Setup, error) {
	labels, err := project.NormalizeLabels([]string{a.Labels})
	if err != nil {
		return nil, err
	}
	var f project.Filters
	if q.Severity {
		if a.MinSeverity != "" {
			if f.MinSeverity, err = project.ParseSeverity(a.MinSeverity); err != nil {
				return nil, err
			}
		}
		for _, s := range a.Severities {
			sev, err := project.ParseSeverity(s)
			if err != nil {
				return nil, err
			}
			f.Severities = append(f.Severities, sev)
		}
	}
	if q.Paths {
		if f.PathExcludes, err = project.ParsePathExcludes(a.PathExcludes); err != nil {
			return nil, err
		}
	}
	if q.Categories {
		for _, c := range a.Categories {
			cat, err := project.ParseCategory(c)
			if err != nil {
				return nil, err
			}
			f.Categories = append(f.Categories, cat)
		}
	}
	if q.CWEs {
		if f.CWEs, err = project.ParseCWEs(a.CWEs); err != nil {
			return nil, err
		}
	}
	return &project.Setup{Labels: labels, Filters: f}, nil
}

// askProjectSetup runs the first-time setup of the project name, which the
// lookup didn't find: Set up now (the AppSec UI's CLI wizard's Scan Filters,
// those the .armisignore doesn't answer, then labels), Use defaults, or
// Cancel. It renders on stderr (setupOut); stdout keeps the scan's results.
// Ctrl-C and a cancelled ctx (SIGINT, SIGTERM) cancel the setup.
func askProjectSetup(ctx context.Context, name string, ignore repo.IgnoreSummary, flagLabels []string) (*project.Setup, error) {
	theme := cmdutil.GetInstallTheme()
	accessible := !cli.ColorsEnabled()
	run := func(groups ...*huh.Group) error {
		form := huh.NewForm(groups...).WithTheme(theme).WithAccessible(accessible).WithInput(setupIn).WithOutput(setupOut)
		err := runForm(ctx, form, accessible)
		switch {
		case errors.Is(err, huh.ErrUserAborted), ctx.Err() != nil:
			return project.ErrSetupCancelled
		case err != nil:
			return fmt.Errorf("project setup: %w", err)
		}
		return nil
	}

	choice := setupNow
	if err := run(huh.NewGroup(huh.NewSelect[string]().
		Title(fmt.Sprintf("Project %q doesn't exist in this tenant yet. Set it up now?", name)).
		Options(
			huh.NewOption("Set up now", setupNow),
			huh.NewOption("Use defaults", setupDefaults),
			huh.NewOption("Cancel", setupCancel),
		).
		Value(&choice))); err != nil {
		return nil, err
	}
	switch choice {
	case setupDefaults:
		return &project.Setup{Labels: flagLabels}, nil
	case setupCancel:
		return nil, project.ErrSetupCancelled
	}

	q := questionsFor(ignore)
	if skipped := q.skipped(); len(skipped) > 0 {
		_, _ = fmt.Fprintf(setupOut, "Using .armisignore for: %s\n\n", strings.Join(skipped, ", "))
	}
	answers := setupAnswers{MinSeverity: project.DefaultMinSeverity, Labels: strings.Join(flagLabels, ", ")}
	for {
		if err := run(setupGroups(&answers, q)...); err != nil {
			return nil, err
		}
		setup, err := answers.toSetup(q)
		if err != nil {
			// The fields' validators already ran; this would be a bug.
			return nil, fmt.Errorf("project setup: %w", err)
		}
		printSetupSummary(setupOut, name, setup, ignore, time.Now())

		next := setupCreate
		if err := run(huh.NewGroup(huh.NewSelect[string]().
			Title("Create the project?").
			Options(
				huh.NewOption("Create the project", setupCreate),
				huh.NewOption("Edit", setupEdit),
				huh.NewOption("Cancel", setupCancel),
			).
			Value(&next))); err != nil {
			return nil, err
		}
		switch next {
		case setupCreate:
			return setup, nil
		case setupCancel:
			return nil, project.ErrSetupCancelled
		}
	}
}

// accessibleForms are the accessible forms still running, including one left
// blocked on its read when its ctx ended. Tests wait for them.
var accessibleForms sync.WaitGroup

// runForm runs form until it is done or ctx ends. The full-screen form
// watches ctx itself, and restores the terminal before it returns. An
// accessible form doesn't: it reads lines from a terminal in its normal mode,
// where Ctrl-C is a SIGINT that the scan's signal context takes, so its read
// would wait for Enter. When ctx ends first, the form is left blocked on that
// read, which is safe only because the run then exits (the cancelled setup
// exits 130).
func runForm(ctx context.Context, form *huh.Form, accessible bool) error {
	if !accessible {
		return form.RunWithContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	// armis:ignore cwe:401 reason:intended and bounded: a blocking read on a terminal stdin can't be interrupted, so when ctx ends (Ctrl-C at an accessible prompt) at most one form goroutine is left on its read, and the run exits 130 right after; done is buffered, so a form that finishes never blocks
	accessibleForms.Go(func() { done <- form.RunWithContext(ctx) })
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// setupGroups are the setup's questions, one per page, with the UI's copy.
func setupGroups(a *setupAnswers, q setupQuestions) []*huh.Group {
	var groups []*huh.Group
	if q.Severity {
		options := make([]huh.Option[string], 0, len(project.Severities))
		for _, s := range project.Severities {
			options = append(options, huh.NewOption(titleCase(s), s))
		}
		groups = append(groups,
			huh.NewGroup(huh.NewSelect[string]().
				Title("Minimum severity").
				Description("Findings below it are still scanned, but hidden from reports and --fail-on.").
				Options(options...).
				Value(&a.MinSeverity)),
		)
	}
	if q.Paths {
		groups = append(groups, huh.NewGroup(huh.NewInput().
			Title("Path excludes (optional)").
			Description("Gitignore syntax, comma-separated; prefix with ! to re-include a path. These files never reach the scan.").
			Placeholder("node_modules/, *.generated.go").
			Value(&a.PathExcludes).
			Validate(func(v string) error { _, err := project.ParsePathExcludes(v); return err })))
	}
	if q.Severity {
		options := make([]huh.Option[string], 0, len(project.Severities))
		for _, s := range project.Severities {
			options = append(options, huh.NewOption(titleCase(s), s))
		}
		groups = append(groups, huh.NewGroup(huh.NewMultiSelect[string]().
			Title("Suppress by severity (optional)").
			Description("Findings with these severities are still scanned, but hidden from reports and --fail-on.").
			Options(options...).
			Filterable(false).
			Value(&a.Severities)))
	}
	if q.Categories {
		labels := map[string]string{"sast": "SAST", "secrets": "Secrets", "iac": "IaC", "sca": "SCA", "license": "License"}
		options := make([]huh.Option[string], 0, len(project.Categories))
		for _, c := range project.Categories {
			options = append(options, huh.NewOption(labels[c], c))
		}
		groups = append(groups, huh.NewGroup(huh.NewMultiSelect[string]().
			Title("Suppress by scanner category (optional)").
			Description("Findings from these scanners are still scanned, but hidden from reports and --fail-on.").
			Options(options...).
			Filterable(false).
			Value(&a.Categories)))
	}
	if q.CWEs {
		groups = append(groups, huh.NewGroup(huh.NewInput().
			Title("Suppress by CWE ID (optional)").
			Description("Comma-separated, such as 79, CWE-1333. Still scanned, just hidden from reports and --fail-on.").
			Placeholder("79, CWE-1333").
			Value(&a.CWEs).
			Validate(func(v string) error { _, err := project.ParseCWEs(v); return err })))
	}
	groups = append(groups, huh.NewGroup(huh.NewInput().
		Title("Project labels (optional)").
		Description(fmt.Sprintf("Comma-separated, stored on the project; at most %d.", project.MaxLabels)).
		Placeholder("team-payments, pci").
		Value(&a.Labels).
		Validate(func(v string) error { _, err := project.NormalizeLabels([]string{v}); return err })))
	return groups
}

// printSetupSummary shows what Create will do: the project's labels, and the
// lines it adds to the .armisignore.
func printSetupSummary(w io.Writer, name string, setup *project.Setup, ignore repo.IgnoreSummary, now time.Time) {
	labels := "(none)"
	if len(setup.Labels) > 0 {
		labels = strings.Join(setup.Labels, ", ")
	}
	_, _ = fmt.Fprintf(w, "\n  %s, a CLI / CI-CD project\n    Labels   %s\n\n", name, labels)

	lines := setup.Filters.Lines(name, now.Format(time.DateOnly))
	path := filepath.Join(ignore.Root, ".armisignore")
	switch {
	case len(lines) == 0:
		_, _ = fmt.Fprintf(w, "  No filters to add to %s.\n\n", path)
		return
	case ignore.RootFile:
		_, _ = fmt.Fprintf(w, "  Adds to %s (appended; your lines are kept):\n", path)
	default:
		_, _ = fmt.Fprintf(w, "  Creates %s:\n", path)
	}
	for _, line := range lines {
		_, _ = fmt.Fprintf(w, "    %s\n", line)
	}
	_, _ = fmt.Fprintln(w)
}

// titleCase is "Medium" for MEDIUM.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return s[:1] + strings.ToLower(s[1:])
}

// writeSetupFilters writes a first-time setup's filters to the scanned
// folder's .armisignore and says so. It reports whether it wrote them, so the
// scan reloads its ignore rules. A write that fails leaves the scan as it
// was, with a warning that holds the lines to add by hand.
func writeSetupFilters(res *project.Resolution, ignore repo.IgnoreSummary, now time.Time) bool {
	if res == nil || res.Setup == nil {
		return false
	}
	lines := res.Setup.Filters.Lines(res.Project.Name, now.Format(time.DateOnly))
	if len(lines) == 0 {
		return false
	}
	path := filepath.Join(ignore.Root, ".armisignore")
	created, err := repo.WriteArmisignoreBlock(ignore.Root, lines)
	if err != nil {
		cli.PrintWarning(fmt.Sprintf("could not write %s (%v): this scan doesn't apply the setup's filters. "+
			"Add these lines to it:\n%s", path, err, strings.Join(lines, "\n")))
		return false
	}
	verb := "Added"
	if created {
		verb = "Wrote"
	}
	styles := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s\n", styles.MutedText.Render(fmt.Sprintf(
		"%s %d lines to %s (commit it, so CI scans apply the same filters)", verb, len(lines), path)))
	return true
}

// labelsSkippedWarning explains why the labels asked for were not applied,
// or returns "".
func labelsSkippedWarning(res *project.Resolution) string {
	asked := strings.Join(res.RequestedLabels, ", ")
	switch res.LabelsSkipped {
	case project.LabelsSkippedExists:
		if len(res.Project.Tags) == 0 {
			return fmt.Sprintf("project %q exists without labels: they were not changed to %s; edit them in AppSec",
				res.Project.Name, asked)
		}
		return fmt.Sprintf("project %q exists: its labels (%s) were not changed to %s; edit them in AppSec",
			res.Project.Name, strings.Join(res.Project.Tags, ", "), asked)
	case project.LabelsSkippedRace:
		return fmt.Sprintf("another run created project %q first: the labels %s were not applied", res.Project.Name, asked)
	case project.LabelsSkippedUnsupported:
		return fmt.Sprintf("this Armis server takes no labels on a new project: %q was created without %s",
			res.Project.Name, asked)
	default:
		return ""
	}
}

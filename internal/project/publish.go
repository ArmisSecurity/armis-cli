package project

import "fmt"

// Run triggers the CLI stamps on a published scan. They are values of the
// AppSec ScanTrigger enum, which reserves cli_ci and cli_dev for the CLI.
const (
	// TriggerCLICI marks a run published from a CI pipeline.
	TriggerCLICI = "cli_ci"
	// TriggerCLIDev marks a run a developer published with --report.
	TriggerCLIDev = "cli_dev"
)

// Decision says whether a scan is published as a run of its project.
type Decision struct {
	// Publish is true when the scan is recorded on the project.
	Publish bool
	// Trigger is the run's trigger (TriggerCLICI or TriggerCLIDev) when
	// Publish is true, and empty otherwise.
	Trigger string
	// Reason says why, for user-facing messages: "CI detected (GITHUB_ACTIONS)"
	// or "--report".
	Reason string
}

// Decide applies the publishing rules for a scan:
//
//   - without a project the scan is a local gate check and is never published;
//   - in CI a named project is published to (trigger cli_ci);
//   - on a developer machine it is published only with --report (trigger
//     cli_dev), so experimenting locally never adds runs to a project.
//
// ciVar names the environment variable that identified CI, for the reason.
func Decide(projectName string, report, ci bool, ciVar string) Decision {
	switch {
	case projectName == "":
		return Decision{}
	case ci:
		reason := "CI detected"
		if ciVar != "" {
			reason = fmt.Sprintf("CI detected (%s)", ciVar)
		}
		return Decision{Publish: true, Trigger: TriggerCLICI, Reason: reason}
	case report:
		return Decision{Publish: true, Trigger: TriggerCLIDev, Reason: "--report"}
	default:
		return Decision{}
	}
}

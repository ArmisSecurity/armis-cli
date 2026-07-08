package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

var scStatusJSON bool

var scStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current supply-chain policy and configuration",
	Long: `Display the current supply-chain policy and where enforcement is wired in.

The first line is the verdict — whether protection is on right now:
  Protected   wrappers are installed and ARMIS_SUPPLY_CHAIN is not off
  Disabled    ARMIS_SUPPLY_CHAIN=off overrides all enforcement
  Not active  no shell wrappers installed (run: armis-cli supply-chain init)

Sections:
  Policy            Active rules (min age, exclusions), from the nearest
                    .armis-supply-chain.yaml searched upward, or defaults.
  Ecosystems        Lockfiles found from the current directory upward — what an
                    install run here would audit. Empty does NOT mean unprotected:
                    wrapped commands still enforce in any project with a lockfile.
  Shell Integration Which shells have the wrappers installed, and the exact
                    commands each one guards (npm, pip, …). This is machine-wide.
  Environment       The ARMIS_SUPPLY_CHAIN* control variables.

Reads from .armis-supply-chain.yaml if present, otherwise shows defaults.`,
	Example: `  armis-cli supply-chain status`,
	Args:    cobra.NoArgs,
	RunE:    runSupplyChainStatus,
}

func init() {
	scStatusCmd.Flags().BoolVar(&scStatusJSON, "json", false, "Output status as JSON to stdout")
	supplyChainCmd.AddCommand(scStatusCmd)
}

// computeVerdict mirrors the wrap-time gate (supply_chain_wrap.go): an explicit
// ARMIS_SUPPLY_CHAIN=off disables everything regardless of how it is wired up;
// otherwise protection is live only if at least one shell has the wrappers
// installed. uniqueWrapped is the deduplicated command set across shells. The
// result feeds both the human headline and the --json `verdict` object, so the
// two can never disagree.
func computeVerdict(uniqueWrapped []string) statusVerdictJSON {
	// armis:ignore cwe:285 cwe:284 cwe:862 cwe:863 reason:this only *reports* protection state for `status` output and enforces nothing; the actual gate is supply_chain_wrap.go (envSCOff), and ARMIS_SUPPLY_CHAIN=off is a documented user-controlled master switch for the user's own machine, not a crossable authorization boundary
	if strings.EqualFold(os.Getenv("ARMIS_SUPPLY_CHAIN"), "off") {
		return statusVerdictJSON{
			State:    "disabled",
			Headline: "Disabled — ARMIS_SUPPLY_CHAIN=off overrides all enforcement",
		}
	}
	if len(uniqueWrapped) == 0 {
		return statusVerdictJSON{
			State:    "inactive",
			Headline: "Not active — no shell wrappers installed. Run: armis-cli supply-chain init",
		}
	}
	// Count the collapsed set (pip + its variants count as one manager) so the
	// headline number matches the "bun, npm, …, pip (+N variants)" detail; the
	// raw function count would say "16 commands" next to 8 visible names.
	managers := len(collapsePipVariants(uniqueWrapped))
	return statusVerdictJSON{
		State:        "protected",
		Headline:     fmt.Sprintf("Protected — %s wrapped (%s)", countNoun(managers, "command"), summarizePMs(uniqueWrapped)),
		WrappedCount: managers,
	}
}

// collapsePipVariants folds pip and its interpreter-specific variants (pip3,
// pip3.12, …) into a single "pip (+N variants)" token. Every non-pip command
// keeps its relative order; the collapsed pip token is appended once at the end
// regardless of where pip appeared in the input (so e.g. ["pip","npm"] renders
// as ["npm","pip"]). That trailing placement is intentional — pip is the noisy
// family and reads best grouped last — and the wrappers never emit pip first in
// practice. A machine with many Python interpreters wraps a dozen pip3.x names
// that otherwise bury the distinct managers (npm, pnpm, …); collapsing them
// keeps the wrapped set readable without losing the count.
func collapsePipVariants(pms []string) []string {
	var pipVariants int
	var out []string
	for _, pm := range pms {
		if supplychain.IsPipVariant(pm) {
			pipVariants++
			continue
		}
		out = append(out, pm)
	}
	if pipVariants > 0 {
		if extra := pipVariants - 1; extra > 0 {
			out = append(out, fmt.Sprintf("pip (+%s)", countNoun(extra, "variant")))
		} else {
			out = append(out, "pip")
		}
	}
	return out
}

// summarizePMs renders a wrapped-command list compactly for the one-line
// headline: pip variants are collapsed (collapsePipVariants), then at most the
// first few names are shown with a "+N more" tail so the verdict stays to one
// line even on a machine that wraps everything.
func summarizePMs(pms []string) string {
	const maxShown = 4

	display := collapsePipVariants(pms)
	if len(display) <= maxShown {
		return strings.Join(display, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(display[:maxShown], ", "), len(display)-maxShown)
}

// uniqueWrappedPMs returns the deduplicated command set wrapped across all
// detected shells, preserving first-seen order. Most machines wrap the same set
// in every shell, so this is what the headline counts (8 commands, not 16).
func uniqueWrappedPMs(shells []supplychain.Shell) []string {
	seen := make(map[string]bool)
	var all []string
	for _, sh := range shells {
		// WrappedPMs already returns nil for an unreadable file or one with no
		// injected block, so it is its own presence check — no separate
		// HasInjection read is needed (that would open each RC file twice).
		for _, pm := range supplychain.WrappedPMs(sh.RCFile) {
			if !seen[pm] {
				seen[pm] = true
				all = append(all, pm)
			}
		}
	}
	return all
}

func runSupplyChainStatus(_ *cobra.Command, _ []string) error {
	dir := "."

	if scStatusJSON {
		return runSupplyChainStatusJSON(dir)
	}

	s := output.GetStyles()

	fmt.Fprintf(os.Stderr, "%s\n", s.HeaderBanner.Render("Supply Chain Status"))
	fmt.Fprintf(os.Stderr, "%s\n\n", s.FooterSeparator.Render("═══════════════════"))

	// Lead with the verdict: the whole point of `status` is to answer "is
	// protection on right now?" without making the reader cross-reference the
	// sections below. Detect shells once and reuse the result for both the
	// headline and the Shell Integration section.
	shells := supplychain.DetectShells()
	verdict := computeVerdict(uniqueWrappedPMs(shells))
	switch verdict.State {
	case "protected":
		fmt.Fprintf(os.Stderr, "%s %s\n\n", s.SuccessText.Render(output.IconSuccess), s.Bold.Render(verdict.Headline))
	default:
		fmt.Fprintf(os.Stderr, "%s %s\n\n", s.WarningText.Render("⚠"), s.Bold.Render(verdict.Headline))
	}

	cfg, configDir, err := loadConfigUpward(dir)
	if err != nil {
		return err
	}

	var policy supplychain.Policy
	var configSource string

	if cfg != nil {
		policy, err = cfg.ToPolicy()
		if err != nil {
			return err
		}
		configSource = filepath.Join(configDir, supplychain.ConfigFileName)
	} else {
		policy = supplychain.DefaultPolicy()
		configSource = "defaults (no " + supplychain.ConfigFileName + " found)"
	}

	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Policy"))
	fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Source:      "), configSource)
	fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Min age:     "), formatDurationShort(policy.MinReleaseAge))
	if len(policy.Exclusions) > 0 {
		fmt.Fprintf(os.Stderr, "  %s %v\n", s.MutedText.Render("Exclusions:  "), policy.Exclusions)
	} else {
		fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Exclusions:  "), s.MutedText.Render("(none)"))
	}
	if cfg != nil && cfg.FailOpen {
		fmt.Fprintf(os.Stderr, "  %s yes\n", s.MutedText.Render("Fail-open:   "))
	}
	fmt.Fprintf(os.Stderr, "\n")

	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Ecosystems"))
	fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("Lockfiles found from here upward (what an install in this directory would audit)"))
	// Walk upward (not just the current directory) so the report matches what the
	// wrapper would actually enforce: lockfiles at a monorepo/project root are found
	// even when status runs from a nested subdirectory.
	ecosystems := supplychain.DetectEcosystemsUpward(dir)
	if len(ecosystems) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("(none here) — enforcement still applies when you run a wrapped command in a project that has a lockfile"))
	} else {
		for _, e := range ecosystems {
			fmt.Fprintf(os.Stderr, "  %-6s %s\n", s.Bold.Render(string(e.Ecosystem)), displayLockfilePath(e.LockfilePath))
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Shell Integration"))
	if len(shells) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("(no shells detected)"))
	} else {
		for _, sh := range shells {
			if !supplychain.HasInjection(sh.RCFile) {
				fmt.Fprintf(os.Stderr, "  %-6s %s (%s)\n", s.Bold.Render(sh.Name), sh.RCFile, s.MutedText.Render("not installed"))
				continue
			}
			fmt.Fprintf(os.Stderr, "  %-6s %s (%s)\n", s.Bold.Render(sh.Name), sh.RCFile, s.SuccessText.Render("active"))
			// Surface which commands the injected block actually wraps. status
			// already reads this RC file to test for the marker; showing the wrapped
			// set turns a bare "active" into "active, and these 9 commands are
			// guarded" — the single fact that tells a user enforcement is live even
			// when no lockfile sits in the current directory. pip variants are
			// collapsed so a dozen pip3.x names don't drown out the distinct managers.
			if pms := supplychain.WrappedPMs(sh.RCFile); len(pms) > 0 {
				fmt.Fprintf(os.Stderr, "         %s %s\n", s.MutedText.Render("wraps:"), s.MutedText.Render(strings.Join(collapsePipVariants(pms), ", ")))
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Environment"))
	printEnvStatus(s, "ARMIS_SUPPLY_CHAIN", "master switch")
	printEnvStatus(s, "ARMIS_SUPPLY_CHAIN_SKIP", "package bypass list")
	printEnvStatus(s, "ARMIS_SUPPLY_CHAIN_ACTIVE", "recursion guard")

	return nil
}

// printEnvStatus is only ever called with the three ARMIS_SUPPLY_CHAIN* control
// variables below — a master on/off switch, a package bypass list, and a
// recursion guard. None of them holds a credential or secret; their values are
// intentionally surfaced so users can diagnose why enforcement is (or isn't)
// active. Echoing them is the purpose of the `status` command, not a leak.
func printEnvStatus(s *output.Styles, key, desc string) {
	val := os.Getenv(key)
	if val != "" {
		// armis:ignore cwe:522 reason:key is one of the non-secret ARMIS_SUPPLY_CHAIN* control vars (switch/bypass-list/recursion-guard); diagnostic output by design, no credentials involved
		fmt.Fprintf(os.Stderr, "  %s=%s %s\n", s.Bold.Render(key), val, s.MutedText.Render("— "+desc))
	} else {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n", s.Bold.Render(key), s.MutedText.Render("(unset)"), s.MutedText.Render("— "+desc))
	}
}

// displayLockfilePath renders an absolute lockfile path for status output. When
// the file lives under (or above) the current working directory it is shown
// relative to the cwd, so an in-directory lockfile reads as "package-lock.json"
// (as before the upward walk) while a parent-directory one reads as
// "../package-lock.json" — making it obvious the enforced lockfile is not in the
// directory the user is standing in. Falls back to the absolute path when a
// relative form cannot be computed (e.g. a different volume on Windows).
func displayLockfilePath(abs string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return abs
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return abs
	}
	return rel
}

type statusJSON struct {
	Verdict     statusVerdictJSON     `json:"verdict"`
	Policy      statusPolicyJSON      `json:"policy"`
	Ecosystems  []statusEcosystemJSON `json:"ecosystems"`
	Shells      []statusShellJSON     `json:"shells"`
	Environment statusEnvJSON         `json:"environment"`
}

// statusVerdictJSON is the machine-readable headline: a stable `state` enum
// (protected | disabled | inactive) so CI can gate on protection with
// `jq -e '.verdict.state == "protected"'` instead of inferring it from the
// shells array, plus the human one-liner and the wrapped-command count.
type statusVerdictJSON struct {
	State        string `json:"state"`
	Headline     string `json:"headline"`
	WrappedCount int    `json:"wrapped_count"`
}

type statusPolicyJSON struct {
	Source     string   `json:"source"`
	MinAge     string   `json:"min_age"`
	Exclusions []string `json:"exclusions"`
	FailOpen   bool     `json:"fail_open"`
}

type statusEcosystemJSON struct {
	Name         string `json:"name"`
	LockfilePath string `json:"lockfile_path"`
}

type statusShellJSON struct {
	Name   string   `json:"name"`
	RCFile string   `json:"rc_file"`
	Active bool     `json:"active"`
	Wraps  []string `json:"wraps"`
}

type statusEnvJSON struct {
	SupplyChain       string `json:"ARMIS_SUPPLY_CHAIN"`
	SupplyChainSkip   string `json:"ARMIS_SUPPLY_CHAIN_SKIP"`
	SupplyChainActive string `json:"ARMIS_SUPPLY_CHAIN_ACTIVE"`
}

func runSupplyChainStatusJSON(dir string) error {
	cfg, configDir, err := loadConfigUpward(dir)
	if err != nil {
		return err
	}

	var policy supplychain.Policy
	var configSource string
	if cfg != nil {
		policy, err = cfg.ToPolicy()
		if err != nil {
			return err
		}
		configSource = filepath.Join(configDir, supplychain.ConfigFileName)
	} else {
		policy = supplychain.DefaultPolicy()
		configSource = "defaults"
	}

	result := statusJSON{
		Policy: statusPolicyJSON{
			Source: configSource,
			// Use the same human-readable formatter as the text output (Min age
			// line, :188) so JSON consumers see "3 days", not Go's internal
			// Duration.String() form "72h0m0s".
			MinAge:     formatDurationShort(policy.MinReleaseAge),
			Exclusions: policy.Exclusions,
			FailOpen:   cfg != nil && cfg.FailOpen,
		},
		// armis:ignore cwe:522 reason:these three ARMIS_SUPPLY_CHAIN* vars are non-secret control values (on/off switch, package bypass list, recursion guard); reporting them is the purpose of `status`, no credentials involved
		Environment: statusEnvJSON{
			SupplyChain:       os.Getenv("ARMIS_SUPPLY_CHAIN"),
			SupplyChainSkip:   os.Getenv("ARMIS_SUPPLY_CHAIN_SKIP"),
			SupplyChainActive: os.Getenv("ARMIS_SUPPLY_CHAIN_ACTIVE"),
		},
	}

	if result.Policy.Exclusions == nil {
		result.Policy.Exclusions = []string{}
	}

	// Walk upward so the JSON snapshot matches enforcement (and the human output):
	// a lockfile at a parent/monorepo root is reported even from a subdirectory.
	// An empty result is a valid "nothing enforceable from here" state.
	// armis:ignore cwe:770 reason:result bounded to one entry per known lockfile type; an empty result is a valid no-lockfile state for status output
	ecosystems := supplychain.DetectEcosystemsUpward(dir)
	for _, e := range ecosystems {
		result.Ecosystems = append(result.Ecosystems, statusEcosystemJSON{
			Name:         string(e.Ecosystem),
			LockfilePath: displayLockfilePath(e.LockfilePath),
		})
	}
	if result.Ecosystems == nil {
		result.Ecosystems = []statusEcosystemJSON{}
	}

	// armis:ignore cwe:770 reason:DetectShells returns at most one entry per known shell (bash/zsh/fish/powershell); the result set is bounded by a fixed allowlist, not by attacker input
	shells := supplychain.DetectShells()
	for _, sh := range shells {
		active := supplychain.HasInjection(sh.RCFile)
		// JSON keeps the full, uncollapsed command list (pip3.11, pip3.12, …) so
		// machine consumers get exact data; the human view collapses pip variants
		// for readability, but a script may want every name.
		wraps := []string{}
		if active {
			if pms := supplychain.WrappedPMs(sh.RCFile); len(pms) > 0 {
				wraps = pms
			}
		}
		result.Shells = append(result.Shells, statusShellJSON{
			Name:   sh.Name,
			RCFile: sh.RCFile,
			Active: active,
			Wraps:  wraps,
		})
	}
	if result.Shells == nil {
		result.Shells = []statusShellJSON{}
	}

	// Headline verdict, computed from the same signals as the human output so the
	// two never disagree.
	result.Verdict = computeVerdict(uniqueWrappedPMs(shells))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

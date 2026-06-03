package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

var scStatusJSON bool

var scStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current supply-chain policy and configuration",
	Long: `Display the current supply-chain policy configuration, detected ecosystems,
and shell injection status.

Reads from .armis-supply-chain.yaml if present, otherwise shows defaults.`,
	Example: `  armis-cli supply-chain status`,
	Args:    cobra.NoArgs,
	RunE:    runSupplyChainStatus,
}

func init() {
	scStatusCmd.Flags().BoolVar(&scStatusJSON, "json", false, "Output status as JSON to stdout")
	supplyChainCmd.AddCommand(scStatusCmd)
}

func runSupplyChainStatus(_ *cobra.Command, _ []string) error {
	dir := "."

	if scStatusJSON {
		return runSupplyChainStatusJSON(dir)
	}

	s := output.GetStyles()

	fmt.Fprintf(os.Stderr, "%s\n", s.HeaderBanner.Render("Supply Chain Status"))
	fmt.Fprintf(os.Stderr, "%s\n\n", s.FooterSeparator.Render("═══════════════════"))

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
	ecosystems, err := supplychain.DetectEcosystems(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("(none detected)"))
	} else {
		for _, e := range ecosystems {
			fmt.Fprintf(os.Stderr, "  %-6s %s\n", s.Bold.Render(string(e.Ecosystem)), e.LockfilePath)
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	fmt.Fprintf(os.Stderr, "%s\n", s.SectionTitle.Render("Shell Integration"))
	shells := supplychain.DetectShells()
	if len(shells) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("(no shells detected)"))
	} else {
		for _, sh := range shells {
			status := s.MutedText.Render("not installed")
			if supplychain.HasInjection(sh.RCFile) {
				status = s.SuccessText.Render("active")
			}
			fmt.Fprintf(os.Stderr, "  %-6s %s (%s)\n", s.Bold.Render(sh.Name), sh.RCFile, status)
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

type statusJSON struct {
	Policy      statusPolicyJSON      `json:"policy"`
	Ecosystems  []statusEcosystemJSON `json:"ecosystems"`
	Shells      []statusShellJSON     `json:"shells"`
	Environment statusEnvJSON         `json:"environment"`
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
	Name   string `json:"name"`
	RCFile string `json:"rc_file"`
	Active bool   `json:"active"`
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
			Source:     configSource,
			MinAge:     policy.MinReleaseAge.String(),
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

	// `status` reports a best-effort snapshot: a missing lockfile is a valid
	// empty state, and an unreadable one (permission/I/O) likewise just yields no
	// ecosystems here rather than failing the whole status read. Either way the
	// error is intentionally not surfaced — mirroring the human-output path.
	// armis:ignore cwe:770 cwe:253 reason:result bounded to one entry per known lockfile type (4); a no-lockfile or unreadable-lockfile error is a valid empty state for status output, deliberately ignored
	ecosystems, _ := supplychain.DetectEcosystems(dir) //nolint:errcheck // no-lockfile is a valid empty state for status
	for _, e := range ecosystems {
		result.Ecosystems = append(result.Ecosystems, statusEcosystemJSON{
			Name:         string(e.Ecosystem),
			LockfilePath: e.LockfilePath,
		})
	}
	if result.Ecosystems == nil {
		result.Ecosystems = []statusEcosystemJSON{}
	}

	// armis:ignore cwe:770 reason:DetectShells returns at most one entry per known shell (bash/zsh/fish); the result set is bounded by a fixed allowlist, not by attacker input
	shells := supplychain.DetectShells()
	for _, sh := range shells {
		result.Shells = append(result.Shells, statusShellJSON{
			Name:   sh.Name,
			RCFile: sh.RCFile,
			Active: supplychain.HasInjection(sh.RCFile),
		})
	}
	if result.Shells == nil {
		result.Shells = []statusShellJSON{}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

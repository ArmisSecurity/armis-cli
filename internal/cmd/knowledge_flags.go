package cmd

import (
	"fmt"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

// parseKnowledgeVariant maps the --variant flag string to a KnowledgeVariant,
// returning an actionable error for any unsupported value. Shared by the
// install and uninstall knowledge subcommands so the flag contract stays in one
// place (and is unit-testable without spawning the claude CLI).
func parseKnowledgeVariant(s string) (install.KnowledgeVariant, error) {
	switch s {
	case "skills":
		return install.KnowledgeVariantSkills, nil
	case "mcp":
		return install.KnowledgeVariantMCP, nil
	default:
		return "", fmt.Errorf("unknown --variant %q (want \"skills\" or \"mcp\")", s)
	}
}

// knowledgeEnvForDev maps the global --dev flag to the knowledge backend
// environment: prod by default, dev when --dev is set. (Stage is reachable via
// the installer API but not surfaced as a CLI flag today.)
func knowledgeEnvForDev(dev bool) install.KnowledgeEnv {
	if dev {
		return install.KnowledgeEnvDev
	}
	return install.KnowledgeEnvProd
}

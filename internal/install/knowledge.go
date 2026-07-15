package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The knowledge plugin ships as a Claude Code marketplace (no GitHub releases,
// unlike armis-appsec-mcp). A "github" marketplace source requires Claude Code
// to clone the repo and populate a sha-versioned plugin cache — state we cannot
// fabricate by hand-writing the registry JSON the way ClaudeInstaller does for
// its self-downloaded "directory" source. So we drive the official `claude`
// CLI, which performs the clone, cache population, and enablement correctly.
const (
	// knowledgeMarketplaceRepo is the GitHub repo Claude Code clones as a marketplace.
	knowledgeMarketplaceRepo = "ArmisSecurity/armis-knowledge-mcp"
	// knowledgeMarketplaceName is the marketplace's declared name (from marketplace.json),
	// used as the "@marketplace" suffix when installing a plugin from it.
	knowledgeMarketplaceName = "armis-knowledge"
)

// KnowledgeVariant selects which plugin flavor to install. The shell-skills
// variant is pure shell + curl (no Python); the MCP variant needs a Python venv
// but adds the agentic /ask command. Installing both variants of the same
// environment collides — they register identical slash commands.
type KnowledgeVariant string

const (
	// KnowledgeVariantSkills is the Claude-Code-only shell-skills variant (no Python).
	KnowledgeVariantSkills KnowledgeVariant = "skills"
	// KnowledgeVariantMCP is the MCP variant (needs Python; adds /ask).
	KnowledgeVariantMCP KnowledgeVariant = "mcp"
)

// KnowledgeEnv selects the backend environment. Each env registers suffixed
// slash commands so all three can coexist on one machine.
type KnowledgeEnv string

const (
	// KnowledgeEnvProd targets moose.armis.com (bare slash commands).
	KnowledgeEnvProd KnowledgeEnv = "prod"
	// KnowledgeEnvStage targets moose-stg.armis.com (-stage commands).
	KnowledgeEnvStage KnowledgeEnv = "stage"
	// KnowledgeEnvDev targets moose-dev.armis.com (-dev commands).
	KnowledgeEnvDev KnowledgeEnv = "dev"
)

// claudeCandidates is the allowlist of binary names probed for the Claude Code
// CLI. Restricting to these fixed names (never user input) is what makes the
// exec.LookPath + EvalSymlinks resolution below safe against PATH-hijack CWEs.
var claudeCandidates = []string{"claude"}

// ErrClaudeCLINotFound is returned when the Claude Code CLI is not on PATH.
var ErrClaudeCLINotFound = errors.New("Claude Code CLI not found on PATH") //nolint:staticcheck // "Claude Code" proper noun

// KnowledgeInstaller installs the Armis Knowledge plugin for Claude Code by
// driving the `claude` CLI.
type KnowledgeInstaller struct {
	Variant KnowledgeVariant
	Env     KnowledgeEnv

	// claudePath is the resolved path to the claude binary. Populated lazily by
	// resolveClaude; overridable in tests.
	claudePath string
	// runner executes the claude CLI with the given args and returns combined
	// output. Overridable in tests to avoid spawning a real process.
	runner func(claudePath string, args ...string) (string, error)
}

// NewKnowledgeInstaller returns an installer for the given variant and environment.
func NewKnowledgeInstaller(variant KnowledgeVariant, env KnowledgeEnv) *KnowledgeInstaller {
	return &KnowledgeInstaller{
		Variant: variant,
		Env:     env,
		runner:  runClaudeCLI,
	}
}

// PluginName returns the marketplace plugin name for this variant+env, matching
// the entries in the knowledge marketplace.json.
//
//	MCP:    prod=armis-knowledge, stage=armis-knowledge-stage, dev=armis-knowledge-dev
//	skills: prod=armis-knowledge-skills, stage=armis-knowledge-skills-stage, ...
func (ki *KnowledgeInstaller) PluginName() string {
	base := knowledgeMarketplaceName // "armis-knowledge" — the MCP prod name
	if ki.Variant == KnowledgeVariantSkills {
		base += "-skills"
	}
	switch ki.Env {
	case KnowledgeEnvStage:
		base += "-stage"
	case KnowledgeEnvDev:
		base += "-dev"
	}
	return base
}

// PluginRef returns the "plugin@marketplace" identifier passed to `claude plugin install`.
func (ki *KnowledgeInstaller) PluginRef() string {
	return ki.PluginName() + "@" + knowledgeMarketplaceName
}

// CheckClaudeCLI verifies the Claude Code CLI is available, returning an
// actionable error otherwise. It is a side-effect-free preflight.
func (ki *KnowledgeInstaller) CheckClaudeCLI() error {
	if err := ki.resolveClaude(); err != nil {
		return err
	}
	return nil
}

// Install adds the knowledge marketplace and installs the selected plugin via
// the Claude Code CLI. It is idempotent: re-adding an existing marketplace or
// re-installing an already-installed plugin is tolerated.
//
// The two variants (skills / mcp) of the same environment register identical
// slash commands and collide if both are present (see marketplace.json). To keep
// exactly one active per environment, Install first removes the sibling variant
// if it is installed and returns that variant's ref as replaced (empty when no
// swap occurred), so the caller can report the swap.
func (ki *KnowledgeInstaller) Install() (replaced string, err error) {
	if err := ki.resolveClaude(); err != nil {
		return "", err
	}

	// Swap out the conflicting sibling variant, if present. A query failure is
	// non-fatal — worst case a leftover sibling the user can remove explicitly —
	// so we only act on a definitive "installed" answer.
	sib := ki.sibling()
	if installed, qerr := sib.IsInstalled(); qerr == nil && installed {
		if uerr := sib.Uninstall(); uerr != nil {
			return "", fmt.Errorf("removing conflicting %s variant: %w", sib.Variant, uerr)
		}
		replaced = sib.PluginRef()
	}

	// Register (or refresh) the marketplace. `marketplace add` fails when the
	// marketplace is already registered; that is not fatal — the subsequent
	// install still resolves the plugin. We keep the output only to surface it
	// if the install itself then fails, so a genuine "add" problem isn't hidden.
	addOut, addErr := ki.runner(ki.claudePath, "plugin", "marketplace", "add", knowledgeMarketplaceRepo)

	installOut, installErr := ki.runner(ki.claudePath, "plugin", "install", ki.PluginRef())
	if installErr != nil {
		// If the plugin is already installed, `claude` reports success on most
		// versions; when it doesn't, treat an explicit "already installed"
		// signal as success so reinstall is idempotent.
		if isAlreadyInstalled(installOut) {
			return replaced, nil
		}
		msg := fmt.Sprintf("installing %s: %v", ki.PluginRef(), installErr)
		if strings.TrimSpace(installOut) != "" {
			msg += "\n" + strings.TrimSpace(installOut)
		}
		// Only surface the marketplace-add failure when the install also failed,
		// since a healthy "already registered" add is the common benign case.
		if addErr != nil && strings.TrimSpace(addOut) != "" {
			msg += "\n(marketplace add: " + strings.TrimSpace(addOut) + ")"
		}
		return "", errors.New(msg)
	}

	return replaced, nil
}

// sibling returns an installer for the other variant in the same environment,
// sharing the resolved claude path and runner so a swap reuses the same process
// plumbing (and test doubles).
func (ki *KnowledgeInstaller) sibling() *KnowledgeInstaller {
	other := KnowledgeVariantMCP
	if ki.Variant == KnowledgeVariantMCP {
		other = KnowledgeVariantSkills
	}
	return &KnowledgeInstaller{
		Variant:    other,
		Env:        ki.Env,
		claudePath: ki.claudePath,
		runner:     ki.runner,
	}
}

// IsInstalled reports whether this plugin is currently installed, per the Claude
// Code CLI's plugin list. A query failure returns (false, err).
func (ki *KnowledgeInstaller) IsInstalled() (bool, error) {
	if err := ki.resolveClaude(); err != nil {
		return false, err
	}
	out, err := ki.runner(ki.claudePath, "plugin", "list")
	if err != nil {
		return false, fmt.Errorf("listing installed plugins: %w", err)
	}
	// The plugin names are distinct enough that a full "name@marketplace" match
	// cannot false-positive across variants: every skills name carries a "-skills"
	// segment the mcp names lack, so neither ref is a substring of the other.
	return strings.Contains(out, ki.PluginRef()), nil
}

// Uninstall removes the selected knowledge plugin via the Claude Code CLI. It is
// idempotent: uninstalling a plugin that isn't installed is treated as success.
// The shared marketplace is left registered — other knowledge plugins (e.g. a
// different environment) may still depend on it, and re-adding it is cheap.
func (ki *KnowledgeInstaller) Uninstall() error {
	if err := ki.resolveClaude(); err != nil {
		return err
	}

	out, err := ki.runner(ki.claudePath, "plugin", "uninstall", "--yes", ki.PluginRef())
	if err != nil {
		if isNotInstalled(out) {
			return nil
		}
		msg := fmt.Sprintf("uninstalling %s: %v", ki.PluginRef(), err)
		if strings.TrimSpace(out) != "" {
			msg += "\n" + strings.TrimSpace(out)
		}
		return errors.New(msg)
	}
	return nil
}

// isAlreadyInstalled reports whether claude CLI output indicates the plugin was
// already present (so a non-zero exit can be treated as idempotent success).
func isAlreadyInstalled(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "already installed") || strings.Contains(l, "already exists")
}

// isNotInstalled reports whether claude CLI output indicates the plugin was not
// installed (so a non-zero exit from uninstall can be treated as idempotent).
func isNotInstalled(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "not installed") || strings.Contains(l, "not found")
}

// resolveClaude locates the claude binary once and caches the path.
func (ki *KnowledgeInstaller) resolveClaude() error {
	if ki.claudePath != "" {
		return nil
	}
	p := findClaude()
	if p == "" {
		return fmt.Errorf("%w — install Claude Code from https://claude.ai/download, then re-run", ErrClaudeCLINotFound)
	}
	ki.claudePath = p
	return nil
}

// findClaude resolves the Claude Code CLI from the fixed candidate allowlist,
// mirroring findPython's hardening: only hardcoded names are probed, and the
// resolved path is symlink-evaluated and required to be absolute.
func findClaude() string {
	for _, name := range claudeCandidates {
		// armis:ignore cwe:426 cwe:427 reason:name is from the hardcoded claudeCandidates allowlist (not user input); resolved path is validated via EvalSymlinks + IsAbs below
		resolved, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		resolved, err = filepath.EvalSymlinks(resolved)
		if err != nil || !filepath.IsAbs(resolved) {
			continue
		}
		return resolved
	}
	return ""
}

// runClaudeCLI executes the claude binary with the given args, streaming nothing
// but capturing combined stdout+stderr for the caller to inspect on failure.
func runClaudeCLI(claudePath string, args ...string) (string, error) {
	// armis:ignore cwe:78 reason:claudePath is resolved from the hardcoded claudeCandidates allowlist via findClaude (EvalSymlinks + IsAbs); args are hardcoded literals or fixed plugin identifiers, never user input
	cmd := exec.Command(claudePath, args...) //nolint:gosec // claudePath from findClaude allowlist; args are fixed literals
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// CredentialsPresent reports whether the client credentials the knowledge
// plugin needs are exported in the environment. The plugin reads these at
// runtime (env or its own .env); it does not accept a tenant identifier.
func CredentialsPresent() bool {
	return os.Getenv("ARMIS_CLIENT_ID") != "" && os.Getenv("ARMIS_CLIENT_SECRET") != ""
}

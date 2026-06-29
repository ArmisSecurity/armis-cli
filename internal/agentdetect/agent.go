package agentdetect

// AgentName is a typed string for agent identifiers.
type AgentName string

const (
	AgentClaudeCode        AgentName = "ClaudeCode"
	AgentWindsurf          AgentName = "Windsurf"
	AgentGoogleAntigravity AgentName = "GoogleAntigravity"
	AgentGitHubCopilot     AgentName = "GitHubCopilot"
	AgentCursor            AgentName = "Cursor"
	AgentCline             AgentName = "Cline"
	AgentRooCode           AgentName = "RooCode"
	AgentAider             AgentName = "Aider"
	AgentDevin             AgentName = "Devin"
	AgentOpenHands         AgentName = "OpenHands"
	AgentAmazonQ           AgentName = "AmazonQ"
	AgentJunie             AgentName = "Junie"
	AgentZed               AgentName = "Zed"
	AgentContinue          AgentName = "Continue"
	AgentGeminiCLI         AgentName = "GeminiCLI"
)

// AgentDetector detects the presence of a coding agent for a given user home directory.
// resolvedHome is the symlink-resolved, canonical path for homeDir (resolved once by Scanner).
//
// DetectVersion returns the installed version, or "" when no reliable on-disk
// source exists. Versions are read from files only (e.g. a VS Code/JetBrains
// extension's package.json). We deliberately never shell out to the agent's
// binary: the scanner can run as root over every user's home directory, where
// executing another user's binary would be unsafe and would not report that
// user's version anyway. Agents detected via dotfiles or app bundles (Claude
// Code, Cursor, Gemini CLI, Zed, Continue, Aider, Devin, OpenHands, Junie,
// Antigravity) carry no consistent version file, so their DetectVersion is an
// intentional "" stub rather than an oversight.
type AgentDetector interface {
	Name() AgentName
	Detect(resolvedHome, homeDir string, platform Platform) bool
	CheckMCP(resolvedHome, homeDir string, platform Platform) bool
	DetectVersion(resolvedHome, homeDir string, platform Platform) string
}

// Registry returns all registered agent detectors.
func Registry() []AgentDetector {
	return []AgentDetector{
		&claudeCodeDetector{},
		&windsurfDetector{},
		&antigravityDetector{},
		&copilotDetector{},
		&cursorDetector{},
		&clineDetector{},
		&rooCodeDetector{},
		&aiderDetector{},
		&devinDetector{},
		&openHandsDetector{},
		&amazonQDetector{},
		&junieDetector{},
		&zedDetector{},
		&continueDetector{},
		&geminiCLIDetector{},
	}
}

// displayNames maps internal agent identifiers to human-readable names for help text.
var displayNames = map[AgentName]string{
	AgentClaudeCode:        "Claude Code",
	AgentWindsurf:          "Windsurf",
	AgentGoogleAntigravity: "Google Antigravity",
	AgentGitHubCopilot:     "GitHub Copilot",
	AgentCursor:            "Cursor",
	AgentCline:             "Cline",
	AgentRooCode:           "Roo Code",
	AgentAider:             "Aider",
	AgentDevin:             "Devin",
	AgentOpenHands:         "OpenHands",
	AgentAmazonQ:           "Amazon Q",
	AgentJunie:             "Junie",
	AgentZed:               "Zed",
	AgentContinue:          "Continue",
	AgentGeminiCLI:         "Gemini CLI",
}

// RegisteredAgentDisplayNames returns the human-readable names of all registered
// detectors, in registry order. Used to keep help text in sync with Registry so
// the agent list never drifts when a detector is added.
func RegisteredAgentDisplayNames() []string {
	detectors := Registry()
	names := make([]string, 0, len(detectors))
	for _, d := range detectors {
		if display, ok := displayNames[d.Name()]; ok {
			names = append(names, display)
		} else {
			names = append(names, string(d.Name()))
		}
	}
	return names
}

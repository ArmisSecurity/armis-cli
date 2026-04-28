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
)

// AgentDetector detects the presence of a coding agent for a given user home directory.
// resolvedHome is the symlink-resolved, canonical path for homeDir (resolved once by Scanner).
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
	}
}

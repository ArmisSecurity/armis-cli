package agentdetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// resolvePath resolves symlinks and cleans the result.
// Returns an error if the path does not exist or cannot be resolved.
func resolvePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

// isUnderDir checks that target (after symlink resolution) is strictly under resolvedBase.
// Returns false if the target cannot be resolved (e.g. does not exist).
// Uses filepath.Rel instead of string prefix to handle case-insensitive paths on Windows.
func isUnderDir(resolvedBase, target string) bool {
	resolved, err := resolvePath(target)
	if err != nil {
		return false
	}

	baseVol := filepath.VolumeName(resolvedBase)
	resolvedVol := filepath.VolumeName(resolved)
	if baseVol != "" && resolvedVol != "" && strings.EqualFold(baseVol, resolvedVol) {
		resolved = baseVol + strings.TrimPrefix(resolved, resolvedVol)
	}

	rel, err := filepath.Rel(resolvedBase, resolved)
	if err != nil {
		return false
	}

	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// dirExists returns true if path exists, is a directory, and resolves under resolvedHome.
func dirExists(resolvedHome, path string) bool {
	if !isUnderDir(resolvedHome, path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExists returns true if path exists, is a regular file, and resolves under resolvedHome.
func fileExists(resolvedHome, path string) bool {
	if !isUnderDir(resolvedHome, path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// hasExtensionPrefix checks if any subdirectory in extDir starts with the given prefix.
// extDir must resolve under resolvedHome.
func hasExtensionPrefix(resolvedHome, extDir, prefix string) bool {
	if !isUnderDir(resolvedHome, extDir) {
		return false
	}
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return false
	}
	lower := strings.ToLower(prefix)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(strings.ToLower(entry.Name()), lower) {
			return true
		}
	}
	return false
}

// findExtensionVersion looks for a package.json in an extension directory matching the prefix
// and extracts the version field. extDir must resolve under resolvedHome.
func findExtensionVersion(resolvedHome, extDir, prefix string) string {
	if !isUnderDir(resolvedHome, extDir) {
		return ""
	}
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return ""
	}
	lower := strings.ToLower(prefix)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(strings.ToLower(entry.Name()), lower) {
			continue
		}
		pkgPath := filepath.Join(extDir, entry.Name(), "package.json")
		if !isUnderDir(resolvedHome, pkgPath) {
			continue
		}
		return readVersionFromPackageJSON(pkgPath)
	}
	return ""
}

func readVersionFromPackageJSON(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // path validated by caller via isUnderDir
	if err != nil {
		return ""
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}
	return pkg.Version
}

// hasJetBrainsPlugin checks JetBrains plugin directories for a plugin matching the prefix.
func hasJetBrainsPlugin(resolvedHome string, platform Platform, homeDir, prefix string) bool {
	for _, pluginDir := range platform.JetBrainsPluginDirs(homeDir) {
		if hasExtensionPrefix(resolvedHome, pluginDir, prefix) {
			return true
		}
	}
	return false
}

// --- Claude Code ---

type claudeCodeDetector struct{}

func (d *claudeCodeDetector) Name() AgentName { return AgentClaudeCode }

func (d *claudeCodeDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return dirExists(resolvedHome, filepath.Join(homeDir, ".claude")) ||
		fileExists(resolvedHome, filepath.Join(homeDir, ".claude.json"))
}

func (d *claudeCodeDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCPInClaudeSettings(resolvedHome, filepath.Join(homeDir, ".claude", "settings.json"))
}

func (d *claudeCodeDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Windsurf ---

type windsurfDetector struct{}

func (d *windsurfDetector) Name() AgentName { return AgentWindsurf }

func (d *windsurfDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".windsurf")) {
		return true
	}
	if hasExtensionPrefix(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "codeium.windsurf") {
		return true
	}
	return hasJetBrainsPlugin(resolvedHome, platform, homeDir, "windsurf")
}

func (d *windsurfDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json"))
}

func (d *windsurfDetector) DetectVersion(resolvedHome, homeDir string, platform Platform) string {
	return findExtensionVersion(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "codeium.windsurf")
}

// --- Google Antigravity ---

type antigravityDetector struct{}

func (d *antigravityDetector) Name() AgentName { return AgentGoogleAntigravity }

func (d *antigravityDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return dirExists(resolvedHome, filepath.Join(homeDir, ".gemini", "antigravity"))
}

func (d *antigravityDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".gemini", "antigravity", "mcp_config.json"))
}

func (d *antigravityDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- GitHub Copilot ---

type copilotDetector struct{}

func (d *copilotDetector) Name() AgentName { return AgentGitHubCopilot }

func (d *copilotDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if hasExtensionPrefix(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "github.copilot") {
		return true
	}
	if hasJetBrainsPlugin(resolvedHome, platform, homeDir, "github-copilot") {
		return true
	}
	return dirExists(resolvedHome, filepath.Join(homeDir, ".config", "github-copilot"))
}

func (d *copilotDetector) CheckMCP(resolvedHome, homeDir string, platform Platform) bool {
	mcpPath := filepath.Join(platform.VSCodeUserConfigDir(homeDir), "mcp.json")
	return HasArmisMCP(resolvedHome, mcpPath) || HasArmisMCPInVSCodeFormat(resolvedHome, mcpPath)
}

func (d *copilotDetector) DetectVersion(resolvedHome, homeDir string, platform Platform) string {
	return findExtensionVersion(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "github.copilot")
}

// --- Cursor ---

type cursorDetector struct{}

func (d *cursorDetector) Name() AgentName { return AgentCursor }

func (d *cursorDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".cursor")) {
		return true
	}
	return platform.CursorAppExists(homeDir)
}

func (d *cursorDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".cursor", "mcp.json"))
}

func (d *cursorDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Cline ---

type clineDetector struct{}

func (d *clineDetector) Name() AgentName { return AgentCline }

func (d *clineDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".cline")) {
		return true
	}
	return hasExtensionPrefix(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "saoudrizwan.claude-dev")
}

func (d *clineDetector) CheckMCP(resolvedHome, homeDir string, platform Platform) bool {
	vsCodePath := filepath.Join(platform.VSCodeUserConfigDir(homeDir), "globalStorage",
		"saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
	return HasArmisMCP(resolvedHome, vsCodePath)
}

func (d *clineDetector) DetectVersion(resolvedHome, homeDir string, platform Platform) string {
	return findExtensionVersion(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "saoudrizwan.claude-dev")
}

// --- Roo Code ---

type rooCodeDetector struct{}

func (d *rooCodeDetector) Name() AgentName { return AgentRooCode }

func (d *rooCodeDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".roo-cline")) {
		return true
	}
	return hasExtensionPrefix(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "rooveterinaryinc.roo-cline")
}

func (d *rooCodeDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".roo-cline", "mcp_settings.json"))
}

func (d *rooCodeDetector) DetectVersion(resolvedHome, homeDir string, platform Platform) string {
	return findExtensionVersion(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "rooveterinaryinc.roo-cline")
}

// --- Aider ---

type aiderDetector struct{}

func (d *aiderDetector) Name() AgentName { return AgentAider }

func (d *aiderDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".aider")) {
		return true
	}
	return fileExists(resolvedHome, filepath.Join(homeDir, ".aider.conf.yml"))
}

func (d *aiderDetector) CheckMCP(_, _ string, _ Platform) bool {
	return false
}

func (d *aiderDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Devin ---

type devinDetector struct{}

func (d *devinDetector) Name() AgentName { return AgentDevin }

func (d *devinDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return dirExists(resolvedHome, filepath.Join(homeDir, ".devin"))
}

func (d *devinDetector) CheckMCP(_, _ string, _ Platform) bool {
	return false
}

func (d *devinDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- OpenHands ---

type openHandsDetector struct{}

func (d *openHandsDetector) Name() AgentName { return AgentOpenHands }

func (d *openHandsDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return dirExists(resolvedHome, filepath.Join(homeDir, ".openhands"))
}

func (d *openHandsDetector) CheckMCP(_, _ string, _ Platform) bool {
	return false
}

func (d *openHandsDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Amazon Q ---

type amazonQDetector struct{}

func (d *amazonQDetector) Name() AgentName { return AgentAmazonQ }

func (d *amazonQDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".aws", "amazonq")) {
		return true
	}
	if hasExtensionPrefix(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "amazonwebservices.amazon-q-vscode") {
		return true
	}
	return hasJetBrainsPlugin(resolvedHome, platform, homeDir, "amazon-q")
}

func (d *amazonQDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".aws", "amazonq", "mcp.json"))
}

func (d *amazonQDetector) DetectVersion(resolvedHome, homeDir string, platform Platform) string {
	return findExtensionVersion(resolvedHome, platform.VSCodeExtensionsDir(homeDir), "amazonwebservices.amazon-q-vscode")
}

// --- Junie ---

type junieDetector struct{}

func (d *junieDetector) Name() AgentName { return AgentJunie }

func (d *junieDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	if dirExists(resolvedHome, filepath.Join(homeDir, ".junie")) {
		return true
	}
	if hasJetBrainsPlugin(resolvedHome, platform, homeDir, "junie") {
		return true
	}
	for _, binPath := range platform.JunieBinaryPaths(homeDir) {
		if _, err := os.Stat(binPath); err == nil {
			return true
		}
	}
	return false
}

func (d *junieDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".junie", "mcp", "mcp.json"))
}

func (d *junieDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Zed ---

type zedDetector struct{}

func (d *zedDetector) Name() AgentName { return AgentZed }

func (d *zedDetector) Detect(resolvedHome, homeDir string, platform Platform) bool {
	zedDir := platform.ZedConfigDir(homeDir)
	if zedDir == "" {
		return false
	}
	return dirExists(resolvedHome, zedDir)
}

func (d *zedDetector) CheckMCP(resolvedHome, homeDir string, platform Platform) bool {
	zedDir := platform.ZedConfigDir(homeDir)
	if zedDir == "" {
		return false
	}
	return HasArmisMCPInZedSettings(resolvedHome, filepath.Join(zedDir, "settings.json"))
}

func (d *zedDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Continue ---

type continueDetector struct{}

func (d *continueDetector) Name() AgentName { return AgentContinue }

func (d *continueDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return dirExists(resolvedHome, filepath.Join(homeDir, ".continue"))
}

func (d *continueDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	mcpDir := filepath.Join(homeDir, ".continue", "mcpServers")
	if !isUnderDir(resolvedHome, mcpDir) {
		return false
	}
	entries, err := os.ReadDir(mcpDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		if HasArmisMCP(resolvedHome, filepath.Join(mcpDir, entry.Name())) {
			return true
		}
	}
	return false
}

func (d *continueDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

// --- Gemini CLI ---

type geminiCLIDetector struct{}

func (d *geminiCLIDetector) Name() AgentName { return AgentGeminiCLI }

func (d *geminiCLIDetector) Detect(resolvedHome, homeDir string, _ Platform) bool {
	return fileExists(resolvedHome, filepath.Join(homeDir, ".gemini", "settings.json"))
}

func (d *geminiCLIDetector) CheckMCP(resolvedHome, homeDir string, _ Platform) bool {
	return HasArmisMCP(resolvedHome, filepath.Join(homeDir, ".gemini", "settings.json"))
}

func (d *geminiCLIDetector) DetectVersion(_, _ string, _ Platform) string {
	return ""
}

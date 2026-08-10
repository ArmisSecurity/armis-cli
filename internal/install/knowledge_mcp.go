package install

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
)

// The knowledge plugin ships one directory per backend environment in a repo
// with no GitHub releases, so it is versioned by the branch head commit SHA
// rather than a semver tag. That is why this installer does not reuse
// PluginInstaller: the version-resolution half differs entirely, while the
// download/extract/venv half is shared via package-level helpers.
const (
	knowledgeRepo       = "ArmisSecurity/armis-knowledge-mcp"
	knowledgeBranch     = "main"
	knowledgeCommitURL  = "https://api.github.com/repos/" + knowledgeRepo + "/commits/" + knowledgeBranch
	knowledgeTarballURL = "https://api.github.com/repos/" + knowledgeRepo + "/tarball/" + knowledgeBranch
	knowledgeSHAFile    = ".installed-sha"
	// maxCommitResponseBytes caps the commit metadata read. The response carries
	// full commit details we don't need; we only want the "sha" field.
	maxCommitResponseBytes = 1 << 20 // 1 MB
	// knowledgeClaudeMarketplace is the marketplace name written into Claude
	// Code's registry. It matches the name in the plugin's own marketplace.json
	// so a later `claude plugin` command recognizes the same identity.
	knowledgeClaudeMarketplace = "armis-knowledge"
)

// KnowledgeMCPInstaller downloads the Armis Knowledge MCP bridge and registers
// it as a local stdio MCP server. The bridge exchanges ARMIS_CLIENT_ID /
// ARMIS_CLIENT_SECRET for a short-lived JWT itself and refreshes it before
// expiry, so every editor that can launch a stdio server gets working auth —
// no static token to keep fresh.
type KnowledgeMCPInstaller struct {
	env       KnowledgeEnv
	pluginDir string
	claudeDir string

	httpClient *http.Client
	commitURL  string
	tarballURL string

	installedSHA string

	// Test seams.
	skipURLValidation bool
	skipVenv          bool
}

// NewKnowledgeMCPInstaller returns an installer for the given backend environment.
func NewKnowledgeMCPInstaller(env KnowledgeEnv) *KnowledgeMCPInstaller {
	// armis:ignore cwe:253 reason:UserHomeDir error results in empty string which fails gracefully downstream
	home, _ := os.UserHomeDir() //nolint:errcheck // armis:ignore cwe:253
	return &KnowledgeMCPInstaller{
		env:        env,
		pluginDir:  filepath.Join(home, ".armis", "plugins", "armis-knowledge-mcp"),
		claudeDir:  filepath.Join(home, ".claude"),
		httpClient: &http.Client{Timeout: downloadTimeout, Transport: httpclient.ProxyAwareTransport()},
		commitURL:  knowledgeCommitURL,
		tarballURL: knowledgeTarballURL,
	}
}

// PluginDir returns the knowledge plugin installation directory.
func (ki *KnowledgeMCPInstaller) PluginDir() string { return ki.pluginDir }

// EnvFilePath returns the path to the knowledge plugin's .env credentials file.
// It sits beside the bridge, since bridge.py and the shell-skills lib both load
// it relative to their own directory.
func (ki *KnowledgeMCPInstaller) EnvFilePath() string {
	return filepath.Join(ki.EnvDir(), ".env")
}

// envSubdir names the repo subdirectory holding this environment's MCP plugin.
func (ki *KnowledgeMCPInstaller) envSubdir() string {
	switch ki.env {
	case KnowledgeEnvStage:
		return "stage"
	case KnowledgeEnvDev:
		return "dev"
	default:
		return "prod"
	}
}

// EnvDir returns the directory holding this environment's bridge and venv.
//
// The whole repo is extracted rather than just this subdirectory: Claude Code
// resolves a "directory" marketplace by reading .claude-plugin/marketplace.json
// at the path it is pointed at, and that file exists only at the repo root —
// where its "pluginRoot": ".." and "./prod/"-style plugin sources are authored
// to work. Extracting a lone subtree yields .claude-plugin/plugin.json instead,
// which Claude Code cannot resolve as a marketplace, so the plugin silently
// never loads.
func (ki *KnowledgeMCPInstaller) EnvDir() string {
	return filepath.Join(ki.pluginDir, ki.envSubdir())
}

// envSuffix returns the naming suffix for non-prod environments, so several
// environments can be registered side by side without colliding.
func (ki *KnowledgeMCPInstaller) envSuffix() string {
	switch ki.env {
	case KnowledgeEnvStage:
		return "-stage"
	case KnowledgeEnvDev:
		return "-dev"
	default:
		return ""
	}
}

// ServerName returns the MCP server key used in JSON editor configs.
func (ki *KnowledgeMCPInstaller) ServerName() string {
	return "armis-knowledge" + ki.envSuffix()
}

// CodexServerName returns the server name for Codex CLI's TOML config, which
// uses underscores (matching the existing armis_scanner section).
func (ki *KnowledgeMCPInstaller) CodexServerName() string {
	return strings.ReplaceAll(ki.ServerName(), "-", "_")
}

// entry builds the MCP registration for the knowledge bridge. Both the
// interpreter and the script live in the environment subdirectory, which is also
// where run.sh expects its .venv.
func (ki *KnowledgeMCPInstaller) entry() mcpEntry {
	return mcpEntry{
		name:    ki.ServerName(),
		command: venvPython(ki.EnvDir()),
		args:    []string{filepath.Join(ki.EnvDir(), "bridge.py")},
		envFile: ki.EnvFilePath(),
	}
}

// codexEntry is entry() with the underscore-separated Codex server name.
func (ki *KnowledgeMCPInstaller) codexEntry() mcpEntry {
	e := ki.entry()
	e.name = ki.CodexServerName()
	return e
}

// InstalledSHA returns the commit SHA recorded for the installed bridge, or ""
// when nothing is installed.
func (ki *KnowledgeMCPInstaller) InstalledSHA() string {
	if ki.installedSHA != "" {
		return ki.installedSHA
	}
	b, err := os.ReadFile(filepath.Clean(filepath.Join(ki.pluginDir, knowledgeSHAFile)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ShortSHA returns the installed SHA abbreviated for display.
func (ki *KnowledgeMCPInstaller) ShortSHA() string {
	sha := ki.InstalledSHA()
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// LatestSHA returns the current head commit SHA of the knowledge repo branch.
func (ki *KnowledgeMCPInstaller) LatestSHA() (string, error) {
	if !ki.skipURLValidation {
		if err := validateGitHubURL(ki.commitURL); err != nil {
			return "", fmt.Errorf("invalid commit URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", ki.commitURL, nil) //nolint:gosec // URL validated by validateGitHubURL above
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := ki.httpClient.Do(req) //nolint:gosec // URL validated by validateGitHubURL above
	if err != nil {
		return "", fmt.Errorf("querying knowledge repo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	// armis:ignore cwe:502 cwe:770 reason:decodes a size-capped response from the validated api.github.com host into a fixed struct; no polymorphic deserialization
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCommitResponseBytes)).Decode(&commit); err != nil {
		return "", fmt.Errorf("parsing commit response: %w", err)
	}
	if commit.SHA == "" {
		return "", fmt.Errorf("commit response is missing sha")
	}
	return commit.SHA, nil
}

// Fetch downloads the knowledge bridge for this environment, builds its Python
// venv, and writes credentials from the environment.
//
// Returns ErrAlreadyCurrent when the recorded SHA matches the branch head and
// force is false, so callers can report "up to date" without re-downloading.
func (ki *KnowledgeMCPInstaller) Fetch(force bool) error {
	latest, err := ki.LatestSHA()
	if err != nil {
		return err
	}

	if !force && ki.InstalledSHA() == latest {
		ki.installedSHA = latest
		return ErrAlreadyCurrent
	}

	if err := os.MkdirAll(ki.pluginDir, 0o750); err != nil {
		return fmt.Errorf("creating knowledge plugin directory: %w", err)
	}

	// Extract the entire repo, not just this environment's subdirectory: the
	// marketplace manifest Claude Code needs lives at the repo root. See EnvDir.
	if err := downloadAndExtractTarball(
		ki.httpClient, ki.tarballURL, ki.pluginDir, "", ki.skipURLValidation,
	); err != nil {
		return fmt.Errorf("downloading knowledge bridge: %w", err)
	}

	if _, err := os.Stat(filepath.Join(ki.EnvDir(), "bridge.py")); err != nil {
		return fmt.Errorf("knowledge archive is missing %s/bridge.py: %w", ki.envSubdir(), err)
	}

	if !ki.skipVenv {
		// run.sh resolves .venv relative to its own directory, so the venv must
		// live in the environment subdirectory alongside the bridge.
		if err := createPluginVenv(ki.EnvDir()); err != nil {
			return fmt.Errorf("setting up knowledge Python environment: %w", err)
		}
	}

	// armis:ignore cwe:522 reason:delegates to writeEnvFromEnvironment which writes with 0600 permissions
	if err := writeEnvFromEnvironment(ki.EnvFilePath()); err != nil {
		return fmt.Errorf("writing knowledge credentials: %w", err)
	}

	ki.installedSHA = latest
	// armis:ignore cwe:253 reason:best-effort version tracking; a write failure only costs a redundant re-download next run
	_ = os.WriteFile(filepath.Clean(filepath.Join(ki.pluginDir, knowledgeSHAFile)), []byte(latest), 0o600)

	return nil
}

// PluginKey returns the "plugin@marketplace" key Claude Code uses to identify
// the knowledge plugin in its registry and settings.
func (ki *KnowledgeMCPInstaller) PluginKey() string {
	return ki.ServerName() + "@" + knowledgeClaudeMarketplace
}

// ClaudeCacheDir returns the plugin directory recorded for Claude Code. We point
// it at our own download rather than copying into Claude's cache, so one
// download serves every agent.
func (ki *KnowledgeMCPInstaller) ClaudeCacheDir() string {
	return ki.EnvDir()
}

// RegisterEditor adds the knowledge bridge to one editor's MCP config.
func (ki *KnowledgeMCPInstaller) RegisterEditor(e Editor) error {
	return e.RegisterEntry(ki.entry())
}

// RegisterCodex adds the knowledge bridge to Codex CLI's config.toml.
func (ki *KnowledgeMCPInstaller) RegisterCodex() error {
	return RegisterCodexEntry(ki.codexEntry())
}

// RegisterClaude registers the knowledge plugin with Claude Code by writing its
// plugin registry directly — the same approach ClaudeInstaller uses for the
// scanner.
//
// We deliberately do not shell out to `claude plugin install` here: driving the
// CLI would make Claude Code a hard dependency of a flow that otherwise has
// none, and would fetch a second copy of the plugin. Because the extracted
// subtree contains .claude-plugin/plugin.json, .mcp.json, and skills/, pointing
// a "directory" marketplace at it gives Claude Code the full plugin — MCP server
// plus the knowledge slash commands.
func (ki *KnowledgeMCPInstaller) RegisterClaude() error {
	if _, err := os.Stat(ki.claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("Claude Code directory not found at %s — is Claude Code installed?", ki.claudeDir) //nolint:staticcheck // proper noun
	}

	if err := ki.registerClaudeMarketplace(); err != nil {
		return fmt.Errorf("registering knowledge marketplace: %w", err)
	}
	if err := ki.registerClaudePlugin(); err != nil {
		return fmt.Errorf("registering knowledge plugin: %w", err)
	}
	if err := ki.enableClaudePlugin(); err != nil {
		return fmt.Errorf("enabling knowledge plugin: %w", err)
	}
	return nil
}

func (ki *KnowledgeMCPInstaller) registerClaudeMarketplace() error {
	return registerDirectoryMarketplace(ki.claudeDir, knowledgeClaudeMarketplace, ki.pluginDir)
}

func (ki *KnowledgeMCPInstaller) registerClaudePlugin() error {
	// The marketplace is the repo root, but the plugin itself is the environment
	// subdirectory — matching the "./prod/"-style source in marketplace.json.
	return registerInstalledPlugin(ki.claudeDir, ki.PluginKey(), ki.EnvDir(), ki.InstalledSHA())
}

func (ki *KnowledgeMCPInstaller) enableClaudePlugin() error {
	return enableInstalledPlugin(ki.claudeDir, ki.PluginKey())
}

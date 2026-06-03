package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const manifestSchemaVersion = 1

// Manifest records what was installed so uninstall is deterministic.
type Manifest struct {
	SchemaVersion int                        `json:"schemaVersion"`
	InstalledAt   string                     `json:"installedAt"`
	PluginVersion string                     `json:"pluginVersion"`
	PluginDir     string                     `json:"pluginDir"`
	Editors       map[EditorID]ManifestEntry `json:"editors,omitempty"`
	Claude        *ManifestClaude            `json:"claude,omitempty"`
	Codex         *ManifestCodex             `json:"codex,omitempty"`
}

// ManifestEntry records where an editor was registered.
type ManifestEntry struct {
	ConfigFile string `json:"configFile"`
	Format     string `json:"format"`
}

// ManifestClaude records Claude Code installation details.
type ManifestClaude struct {
	CacheDir string `json:"cacheDir"`
}

// ManifestCodex records Codex CLI MCP registration details.
type ManifestCodex struct {
	ConfigFile string `json:"configFile"`
}

// ManifestPath returns the path to the manifest file for the given plugin directory.
// It validates that the resolved path stays within pluginDir to prevent path traversal,
// resolving symlinks to prevent bypass via symlinked components.
func ManifestPath(pluginDir string) string {
	if pluginDir == "" || !filepath.IsAbs(pluginDir) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(pluginDir))
	if err != nil {
		resolved = filepath.Clean(pluginDir)
	}
	clean := filepath.Join(resolved, ".manifest.json")
	base := resolved + string(filepath.Separator)
	if !strings.HasPrefix(clean, base) {
		return ""
	}
	return clean
}

// ReadManifest loads an existing manifest, returning nil if none exists or it cannot be parsed.
func ReadManifest(pluginDir string) *Manifest {
	path := ManifestPath(pluginDir)
	if path == "" {
		return nil
	}
	// armis:ignore cwe:770 cwe:22 cwe:23 cwe:73 reason:path validated by ManifestPath (abs + EvalSymlinks + prefix check); fixed .manifest.json in the user's own plugin dir
	b, err := os.ReadFile(path) //nolint:gosec // path validated by ManifestPath against traversal
	if err != nil {             // armis:ignore cwe:770 reason:os.ReadFile above reads a bounded, path-validated local .manifest.json
		return nil
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return &m
}

// WriteManifest persists the manifest to the plugin directory atomically.
func WriteManifest(m *Manifest) error {
	path := ManifestPath(m.PluginDir)
	if path == "" {
		return fmt.Errorf("invalid plugin directory path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeJSONAtomic(path, m)
}

// NewManifest creates a fresh manifest for the given plugin directory and version.
func NewManifest(pluginDir, version string) *Manifest {
	return &Manifest{
		SchemaVersion: manifestSchemaVersion,
		InstalledAt:   time.Now().UTC().Format(time.RFC3339),
		PluginVersion: version,
		PluginDir:     pluginDir,
		Editors:       make(map[EditorID]ManifestEntry),
	}
}

// AddEditor records an editor registration in the manifest.
func (m *Manifest) AddEditor(id EditorID, configFile, format string) {
	if m.Editors == nil {
		m.Editors = make(map[EditorID]ManifestEntry)
	}
	m.Editors[id] = ManifestEntry{ConfigFile: configFile, Format: format}
}

// RemoveEditor removes an editor from the manifest.
func (m *Manifest) RemoveEditor(id EditorID) {
	delete(m.Editors, id)
}

// SetClaude records Claude Code installation in the manifest.
func (m *Manifest) SetClaude(cacheDir string) {
	m.Claude = &ManifestClaude{CacheDir: cacheDir}
}

// SetCodex records Codex CLI MCP registration in the manifest.
func (m *Manifest) SetCodex(configFile string) {
	m.Codex = &ManifestCodex{ConfigFile: configFile}
}

// ConfigFormat returns the JSON format identifier for a given editor.
func ConfigFormat(id EditorID) string {
	switch id {
	case EditorVSCode:
		return "vscode-servers"
	case EditorZed:
		return "zed-context_servers"
	default:
		return "mcpServers"
	}
}

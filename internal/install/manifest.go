package install

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// ManifestPath returns the path to the manifest file for the given plugin directory.
func ManifestPath(pluginDir string) string {
	return filepath.Join(pluginDir, ".manifest.json")
}

// ReadManifest loads an existing manifest, returning nil if none exists or it cannot be parsed.
func ReadManifest(pluginDir string) *Manifest {
	path := ManifestPath(pluginDir)
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return &m
}

// WriteManifest persists the manifest to the plugin directory.
func WriteManifest(m *Manifest) error {
	return writeJSON(ManifestPath(m.PluginDir), m)
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

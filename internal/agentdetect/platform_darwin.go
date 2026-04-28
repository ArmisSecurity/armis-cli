//go:build darwin

package agentdetect

import (
	"os"
	"path/filepath"
)

type darwinPlatform struct{}

// NewPlatform returns the macOS platform implementation.
func NewPlatform() Platform {
	return &darwinPlatform{}
}

func (p *darwinPlatform) UserHomeDirs() ([]UserHome, error) {
	if p.IsRoot() {
		return enumerateUserDirs("/Users", darwinSkipDirs)
	}
	return currentUserOnly()
}

func (p *darwinPlatform) VSCodeExtensionsDir(homeDir string) string {
	return filepath.Join(homeDir, ".vscode", "extensions")
}

func (p *darwinPlatform) JetBrainsPluginDirs(homeDir string) []string {
	return globJetBrainsPluginDirs(filepath.Join(homeDir, "Library", "Application Support", "JetBrains"))
}

func (p *darwinPlatform) VSCodeUserConfigDir(homeDir string) string {
	return filepath.Join(homeDir, "Library", "Application Support", "Code", "User")
}

func (p *darwinPlatform) CursorAppExists(_ string) bool {
	_, err := os.Stat("/Applications/Cursor.app")
	return err == nil
}

func (p *darwinPlatform) JunieBinaryPaths(homeDir string) []string {
	return []string{
		"/usr/local/bin/junie",
		filepath.Join(homeDir, ".local", "bin", "junie"),
	}
}

func (p *darwinPlatform) IsRoot() bool {
	return os.Getuid() == 0
}

var darwinSkipDirs = map[string]bool{
	"Shared":     true,
	".localized": true,
	"Guest":      true,
}

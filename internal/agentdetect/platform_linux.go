//go:build linux

package agentdetect

import (
	"os"
	"path/filepath"
)

type linuxPlatform struct{}

// NewPlatform returns the Linux platform implementation.
func NewPlatform() Platform {
	return &linuxPlatform{}
}

func (p *linuxPlatform) UserHomeDirs() ([]UserHome, error) {
	if p.IsRoot() {
		return enumerateUserDirs("/home", linuxSkipDirs)
	}
	return currentUserOnly()
}

func (p *linuxPlatform) VSCodeExtensionsDir(homeDir string) string {
	return filepath.Join(homeDir, ".vscode", "extensions")
}

func (p *linuxPlatform) JetBrainsPluginDirs(homeDir string) []string {
	return globJetBrainsPluginDirs(filepath.Join(homeDir, ".local", "share", "JetBrains"))
}

func (p *linuxPlatform) VSCodeUserConfigDir(homeDir string) string {
	return filepath.Join(homeDir, ".config", "Code", "User")
}

func (p *linuxPlatform) CursorAppExists(_ string) bool {
	return false
}

func (p *linuxPlatform) JunieBinaryPaths(homeDir string) []string {
	return []string{
		"/usr/local/bin/junie",
		filepath.Join(homeDir, ".local", "bin", "junie"),
	}
}

func (p *linuxPlatform) IsRoot() bool {
	return os.Getuid() == 0
}

var linuxSkipDirs = map[string]bool{}

//go:build windows

package agentdetect

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type windowsPlatform struct{}

// NewPlatform returns the Windows platform implementation.
func NewPlatform() Platform {
	return &windowsPlatform{}
}

func (p *windowsPlatform) UserHomeDirs() ([]UserHome, error) {
	if p.IsRoot() {
		return enumerateUserDirs(`C:\Users`, windowsSkipDirs)
	}
	return currentUserOnly()
}

func (p *windowsPlatform) VSCodeExtensionsDir(homeDir string) string {
	return filepath.Join(homeDir, ".vscode", "extensions")
}

func (p *windowsPlatform) JetBrainsPluginDirs(homeDir string) []string {
	return globJetBrainsPluginDirs(filepath.Join(homeDir, "AppData", "Roaming", "JetBrains"))
}

func (p *windowsPlatform) VSCodeUserConfigDir(homeDir string) string {
	return filepath.Join(homeDir, "AppData", "Roaming", "Code", "User")
}

func (p *windowsPlatform) CursorAppExists(homeDir string) bool {
	cursorPath := filepath.Join(homeDir, "AppData", "Local", "Programs", "Cursor", "Cursor.exe")
	_, err := os.Stat(cursorPath)
	return err == nil
}

func (p *windowsPlatform) JunieBinaryPaths(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, "AppData", "Local", "Programs", "Junie", "junie.exe"),
	}
}

func (p *windowsPlatform) IsRoot() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

var windowsSkipDirs = map[string]bool{
	"Default":      true,
	"Default User": true,
	"Public":       true,
	"All Users":    true,
}

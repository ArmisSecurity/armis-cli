package agentdetect

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// enumerateUserDirs lists user home directories under baseDir, skipping entries in skipSet.
// Hidden directories (starting with ".") are always skipped.
func enumerateUserDirs(baseDir string, skipSet map[string]bool) ([]UserHome, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	var users []UserHome
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if skipSet[name] {
			continue
		}
		users = append(users, UserHome{
			Username: name,
			HomeDir:  filepath.Join(baseDir, name),
		})
	}
	return users, nil
}

// currentUserOnly returns a single-element slice with the current user's home directory.
func currentUserOnly() ([]UserHome, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return []UserHome{{Username: u.Username, HomeDir: homeDir}}, nil
}

// globJetBrainsPluginDirs finds plugin directories across JetBrains product versions.
// The baseDir is the JetBrains config root (e.g., ~/Library/Application Support/JetBrains).
func globJetBrainsPluginDirs(baseDir string) []string {
	pattern := filepath.Join(baseDir, "*", "plugins")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

package agentdetect

// Platform provides OS-specific paths and operations.
type Platform interface {
	// UserHomeDirs returns home directories for all local users.
	// When running as root/SYSTEM, returns all user profiles.
	// When running as regular user, returns only the current user's home.
	UserHomeDirs() ([]UserHome, error)

	// VSCodeExtensionsDir returns the VS Code extensions directory for a given home.
	VSCodeExtensionsDir(homeDir string) string

	// JetBrainsPluginDirs returns JetBrains plugin directories for a given home.
	JetBrainsPluginDirs(homeDir string) []string

	// VSCodeUserConfigDir returns the VS Code user config directory (for mcp.json, settings.json).
	VSCodeUserConfigDir(homeDir string) string

	// CursorAppExists returns true if the Cursor application is installed at a platform-standard location.
	CursorAppExists(homeDir string) bool

	// JunieBinaryPaths returns platform-specific paths where the Junie binary may be installed.
	JunieBinaryPaths(homeDir string) []string

	// ZedConfigDir returns the Zed editor config directory for a given home.
	ZedConfigDir(homeDir string) string

	// IsRoot returns true if the current process has elevated privileges.
	IsRoot() bool
}

// UserHome represents a discovered user profile.
type UserHome struct {
	Username string
	HomeDir  string
}

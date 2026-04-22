// Package install provides installation logic for Armis integrations.
package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const githubAPIHost = "api.github.com"

const (
	pluginRepo       = "ArmisSecurity/armis-appsec-mcp"
	marketplaceName  = "armis-appsec-mcp"
	pluginName       = "armis-appsec"
	releasesURL      = "https://api.github.com/repos/" + pluginRepo + "/releases/latest"
	downloadTimeout  = 60 * time.Second
	maxArchiveBytes  = 50 * 1024 * 1024  // 50 MB safety limit
	maxExtractedSize = 100 * 1024 * 1024 // 100 MB total extracted size
	maxFileSize      = 10 * 1024 * 1024  // 10 MB per file
	maxArchiveEntries = 10000            // max tar entries to prevent resource exhaustion
)

// githubRelease is the minimal structure from the GitHub releases API.
type githubRelease struct {
	TagName    string `json:"tag_name"`
	TarballURL string `json:"tarball_url"`
}

// ClaudeInstaller installs the Armis AppSec MCP plugin for Claude Code.
type ClaudeInstaller struct {
	claudeDir        string
	httpClient       *http.Client
	releasesURL      string
	installedVersion string
	skipURLValidation bool // testing only: skip GitHub URL enforcement
}

// NewClaudeInstaller creates an installer with the default Claude directory.
func NewClaudeInstaller() *ClaudeInstaller {
	home, _ := os.UserHomeDir()
	return &ClaudeInstaller{
		claudeDir:   filepath.Join(home, ".claude"),
		httpClient:  &http.Client{Timeout: downloadTimeout},
		releasesURL: releasesURL,
	}
}

// InstalledVersion returns the version that was installed (available after Install).
func (ci *ClaudeInstaller) InstalledVersion() string {
	return ci.installedVersion
}

// Install downloads and installs the MCP plugin.
func (ci *ClaudeInstaller) Install() error {
	if _, err := os.Stat(ci.claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("Claude Code directory not found at %s — is Claude Code installed?", ci.claudeDir) //nolint:staticcheck // proper noun
	}

	release, err := ci.fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	ci.installedVersion = strings.TrimPrefix(release.TagName, "v")

	pluginDir := ci.pluginCacheDir()
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	if err := ci.downloadAndExtract(release.TarballURL, pluginDir); err != nil {
		return fmt.Errorf("failed to download plugin: %w", err)
	}

	if err := ci.createVenv(pluginDir); err != nil {
		return fmt.Errorf("failed to set up Python environment: %w", err)
	}

	if err := ci.registerMarketplace(pluginDir); err != nil {
		return fmt.Errorf("failed to register marketplace: %w", err)
	}

	if err := ci.registerPlugin(pluginDir); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	if err := ci.enablePlugin(); err != nil {
		return fmt.Errorf("failed to enable plugin: %w", err)
	}

	return nil
}

// pluginCacheDir returns the install target directory.
func (ci *ClaudeInstaller) pluginCacheDir() string {
	return filepath.Join(ci.claudeDir, "plugins", "cache", marketplaceName, pluginName, "latest")
}

// GetInstalledVersion reads the installed plugin version from the registry.
// Returns empty string if the plugin is not installed.
func (ci *ClaudeInstaller) GetInstalledVersion() string {
	instFile := filepath.Join(ci.claudeDir, "plugins", "installed_plugins.json")
	b, err := os.ReadFile(filepath.Clean(instFile))
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return ""
	}
	plugins, ok := data["plugins"].(map[string]interface{})
	if !ok {
		return ""
	}
	key := pluginName + "@" + marketplaceName
	entries, ok := plugins[key].([]interface{})
	if !ok || len(entries) == 0 {
		return ""
	}
	entry, ok := entries[0].(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := entry["version"].(string)
	if v == "latest" {
		return ""
	}
	return v
}

// HasExistingEnv checks whether credentials are already configured.
func (ci *ClaudeInstaller) HasExistingEnv() bool {
	envPath := filepath.Join(ci.pluginCacheDir(), ".env")
	_, err := os.Stat(envPath)
	return err == nil
}

func (ci *ClaudeInstaller) fetchLatestRelease() (*githubRelease, error) {
	if !ci.skipURLValidation {
		if err := validateGitHubURL(ci.releasesURL); err != nil {
			return nil, fmt.Errorf("invalid releases URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", ci.releasesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := ci.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying GitHub releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d — is there a published release?", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	if release.TagName == "" || release.TarballURL == "" {
		return nil, fmt.Errorf("release is missing tag or tarball URL")
	}

	return &release, nil
}

func (ci *ClaudeInstaller) downloadAndExtract(tarballURL, destDir string) error {
	if !ci.skipURLValidation {
		if err := validateGitHubURL(tarballURL); err != nil {
			return fmt.Errorf("invalid tarball URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", tarballURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := ci.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	reader := io.LimitReader(resp.Body, maxArchiveBytes)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("decompressing archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var totalExtracted int64
	var entryCount int
	var prefix string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}

		entryCount++
		if entryCount > maxArchiveEntries {
			return fmt.Errorf("archive exceeds %d entry limit", maxArchiveEntries)
		}

		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		// GitHub tarballs have a top-level directory like "org-repo-sha/"
		// Strip it to extract files directly into destDir.
		if prefix == "" {
			parts := strings.SplitN(header.Name, "/", 2)
			if len(parts) > 0 {
				prefix = parts[0] + "/"
			}
		}

		name := strings.TrimPrefix(header.Name, prefix)
		if name == "" || name == "." {
			continue
		}

		// CWE-22: reject any entry containing path traversal sequences before cleaning
		if strings.Contains(name, "..") {
			continue
		}

		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) {
			continue
		}

		target := filepath.Join(destDir, clean)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			continue
		}
		absDestDir, err := filepath.Abs(destDir)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(absTarget, absDestDir+string(os.PathSeparator)) && absTarget != absDestDir {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(absTarget, 0o750); err != nil {
				return fmt.Errorf("creating directory %s: %w", name, err)
			}
		case tar.TypeReg:
			if header.Size > maxFileSize {
				continue
			}
			totalExtracted += header.Size
			if totalExtracted > maxExtractedSize {
				return fmt.Errorf("extracted archive exceeds %d MB safety limit", maxExtractedSize/1024/1024)
			}
			if err := os.MkdirAll(filepath.Dir(absTarget), 0o750); err != nil {
				return fmt.Errorf("creating parent directory: %w", err)
			}
			perm := os.FileMode(0o644)
			if header.Mode&0o100 != 0 {
				perm = 0o750
			}
			if err := extractFile(absTarget, tr, perm); err != nil {
				return fmt.Errorf("writing file %s: %w", name, err)
			}
		}
	}

	if prefix == "" {
		return fmt.Errorf("archive appears to be empty")
	}

	return nil
}

// allowedPythonDirs contains trusted directories for Python interpreter lookup (CWE-426).
var allowedPythonDirs = []string{
	"/usr/bin",
	"/usr/local/bin",
	"/opt/homebrew/bin",
}

func (ci *ClaudeInstaller) createVenv(pluginDir string) error {
	python := findPython()
	if python == "" {
		return fmt.Errorf("Python 3.11+ is required but not found in PATH") //nolint:staticcheck // proper noun
	}

	venvDir := filepath.Join(pluginDir, ".venv")
	venvCmd := exec.Command(python, "-m", "venv", venvDir) //nolint:gosec // python validated by findPython allowlist
	venvCmd.Stdout = os.Stderr
	venvCmd.Stderr = os.Stderr
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("creating venv: %w", err)
	}

	pip := filepath.Join(venvDir, "bin", "pip")
	if runtime.GOOS == "windows" {
		pip = filepath.Join(venvDir, "Scripts", "pip.exe")
	}
	reqsFile := filepath.Join(pluginDir, "requirements.txt")
	pipCmd := exec.Command(pip, "install", "-q", "-r", reqsFile) //nolint:gosec // pip path derived from our own venv
	pipCmd.Stdout = os.Stderr
	pipCmd.Stderr = os.Stderr
	if err := pipCmd.Run(); err != nil {
		return fmt.Errorf("installing dependencies: %w", err)
	}

	return nil
}

func (ci *ClaudeInstaller) registerMarketplace(pluginDir string) error {
	mktsFile := filepath.Join(ci.claudeDir, "plugins", "known_marketplaces.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(filepath.Clean(mktsFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	data[marketplaceName] = map[string]interface{}{
		"source":          map[string]interface{}{"source": "directory", "path": pluginDir},
		"installLocation": pluginDir,
		"lastUpdated":     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	return writeJSON(mktsFile, data)
}

func (ci *ClaudeInstaller) registerPlugin(pluginDir string) error {
	instFile := filepath.Join(ci.claudeDir, "plugins", "installed_plugins.json")
	data := map[string]interface{}{"version": 2, "plugins": map[string]interface{}{}}
	if b, err := os.ReadFile(filepath.Clean(instFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	plugins, ok := data["plugins"].(map[string]interface{})
	if !ok {
		plugins = make(map[string]interface{})
		data["plugins"] = plugins
	}

	key := pluginName + "@" + marketplaceName
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	plugins[key] = []interface{}{
		map[string]interface{}{
			"scope":       "user",
			"installPath": pluginDir,
			"version":     ci.installedVersion,
			"installedAt": now,
			"lastUpdated": now,
		},
	}

	return writeJSON(instFile, data)
}

func (ci *ClaudeInstaller) enablePlugin() error {
	settingsFile := filepath.Join(ci.claudeDir, "settings.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(filepath.Clean(settingsFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	enabled, ok := data["enabledPlugins"].(map[string]interface{})
	if !ok {
		enabled = make(map[string]interface{})
		data["enabledPlugins"] = enabled
	}

	key := pluginName + "@" + marketplaceName
	enabled[key] = true

	return writeJSON(settingsFile, data)
}

func validateGitHubURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be https, got %q", u.Scheme)
	}
	if u.Host != githubAPIHost {
		return fmt.Errorf("URL host must be %s, got %q", githubAPIHost, u.Host)
	}
	return nil
}

func extractFile(target string, r io.Reader, perm os.FileMode) error {
	f, err := os.OpenFile(filepath.Clean(target), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm) //nolint:gosec // target validated by caller
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(r, maxFileSize)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writeJSON(path string, data interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(path), append(b, '\n'), 0o600)
}

func findPython() string {
	for _, name := range []string{"python3", "python"} {
		resolved, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		resolved, err = filepath.EvalSymlinks(resolved)
		if err != nil || !filepath.IsAbs(resolved) {
			continue
		}
		if !isInAllowedDir(resolved) {
			continue
		}
		out, err := exec.Command(resolved, "-c", "import sys; print(sys.version_info >= (3, 11))").Output() //nolint:gosec // resolved path validated above
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(out)) == "True" {
			return resolved
		}
	}
	return ""
}

func isInAllowedDir(resolved string) bool {
	dir := filepath.Dir(resolved)
	for _, allowed := range allowedPythonDirs {
		if dir == allowed {
			return true
		}
	}
	return false
}


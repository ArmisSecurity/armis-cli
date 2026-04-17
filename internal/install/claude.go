// Package install provides installation logic for Armis integrations.
package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	pluginRepo       = "silk-security/armis-appsec-mcp"
	marketplaceName  = "armis-appsec-mcp"
	pluginName       = "armis-appsec"
	archiveURL       = "https://api.github.com/repos/" + pluginRepo + "/tarball/main"
	downloadTimeout  = 60 * time.Second
	maxArchiveBytes  = 50 * 1024 * 1024 // 50 MB safety limit
	maxExtractedSize = 100 * 1024 * 1024 // 100 MB total extracted size
	maxFileSize      = 10 * 1024 * 1024  // 10 MB per file
)

// ClaudeInstaller installs the Armis AppSec MCP plugin for Claude Code.
type ClaudeInstaller struct {
	claudeDir string
	httpClient *http.Client
}

// NewClaudeInstaller creates an installer with the default Claude directory.
func NewClaudeInstaller() *ClaudeInstaller {
	home, _ := os.UserHomeDir()
	return &ClaudeInstaller{
		claudeDir: filepath.Join(home, ".claude"),
		httpClient: &http.Client{Timeout: downloadTimeout},
	}
}

// Install downloads and installs the MCP plugin.
func (ci *ClaudeInstaller) Install() error {
	if _, err := os.Stat(ci.claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("Claude Code directory not found at %s — is Claude Code installed?", ci.claudeDir)
	}

	pluginDir := ci.pluginCacheDir()
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	if err := ci.downloadAndExtract(pluginDir); err != nil {
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

// HasExistingEnv checks whether credentials are already configured.
func (ci *ClaudeInstaller) HasExistingEnv() bool {
	envPath := filepath.Join(ci.pluginCacheDir(), ".env")
	_, err := os.Stat(envPath)
	return err == nil
}

func (ci *ClaudeInstaller) downloadAndExtract(destDir string) error {
	req, err := http.NewRequest("GET", archiveURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := ci.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	reader := io.LimitReader(resp.Body, maxArchiveBytes)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("decompressing archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var totalExtracted int64
	var prefix string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
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

		// CWE-22: reject entries with path traversal components
		clean := filepath.Clean(filepath.FromSlash(name))
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}

		target := filepath.Join(destDir, clean)
		if !strings.HasPrefix(target, destDir+string(os.PathSeparator)) && target != destDir {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
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
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("creating parent directory: %w", err)
			}
			perm := os.FileMode(header.Mode) & 0o755
			if perm == 0 {
				perm = 0o644
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", name, err)
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxFileSize)); err != nil {
				f.Close()
				return fmt.Errorf("writing file %s: %w", name, err)
			}
			f.Close()
		}
	}

	if prefix == "" {
		return fmt.Errorf("archive appears to be empty")
	}

	return nil
}

func (ci *ClaudeInstaller) createVenv(pluginDir string) error {
	python := findPython()
	if python == "" {
		return fmt.Errorf("Python 3.11+ is required but not found in PATH")
	}

	venvDir := filepath.Join(pluginDir, ".venv")
	if err := runCommand(python, "-m", "venv", venvDir); err != nil {
		return fmt.Errorf("creating venv: %w", err)
	}

	pip := filepath.Join(venvDir, "bin", "pip")
	if runtime.GOOS == "windows" {
		pip = filepath.Join(venvDir, "Scripts", "pip.exe")
	}
	reqsFile := filepath.Join(pluginDir, "requirements.txt")
	if err := runCommand(pip, "install", "-q", "-r", reqsFile); err != nil {
		return fmt.Errorf("installing dependencies: %w", err)
	}

	return nil
}

func (ci *ClaudeInstaller) registerMarketplace(pluginDir string) error {
	mktsFile := filepath.Join(ci.claudeDir, "plugins", "known_marketplaces.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(mktsFile); err == nil {
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
	if b, err := os.ReadFile(instFile); err == nil {
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
			"version":     "latest",
			"installedAt": now,
			"lastUpdated": now,
		},
	}

	return writeJSON(instFile, data)
}

func (ci *ClaudeInstaller) enablePlugin() error {
	settingsFile := filepath.Join(ci.claudeDir, "settings.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(settingsFile); err == nil {
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

func writeJSON(path string, data interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func findPython() string {
	for _, name := range []string{"python3", "python"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "-c", "import sys; print(sys.version_info >= (3, 11))").Output()
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(out)) == "True" {
			return path
		}
	}
	return ""
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
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
	osWindows = "windows"
	osDarwin  = "darwin"
	osLinux   = "linux"
)

const (
	pluginRepo        = "ArmisSecurity/armis-appsec-mcp"
	releasesURL       = "https://api.github.com/repos/" + pluginRepo + "/releases/latest"
	downloadTimeout   = 60 * time.Second
	maxArchiveBytes   = 50 * 1024 * 1024  // 50 MB safety limit
	maxExtractedSize  = 100 * 1024 * 1024 // 100 MB total extracted size
	maxFileSize       = 10 * 1024 * 1024  // 10 MB per file
	maxArchiveEntries = 10000             // max tar entries to prevent resource exhaustion
)

type githubRelease struct {
	TagName    string `json:"tag_name"`
	TarballURL string `json:"tarball_url"`
}

// PluginInstaller handles downloading and setting up the Armis AppSec MCP plugin.
type PluginInstaller struct {
	httpClient        *http.Client
	releasesURL       string
	installedVersion  string
	skipURLValidation bool
}

func newPluginInstaller() *PluginInstaller {
	return &PluginInstaller{
		httpClient:  &http.Client{Timeout: downloadTimeout},
		releasesURL: releasesURL,
	}
}

// InstalledVersion returns the version that was installed (available after FetchAndInstall).
func (pi *PluginInstaller) InstalledVersion() string {
	return pi.installedVersion
}

// FetchAndInstall downloads the latest release and sets up the plugin in destDir.
func (pi *PluginInstaller) FetchAndInstall(destDir string) error {
	release, err := pi.fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	pi.installedVersion = strings.TrimPrefix(release.TagName, "v")

	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	if err := pi.downloadAndExtract(release.TarballURL, destDir); err != nil {
		return fmt.Errorf("failed to download plugin: %w", err)
	}

	if err := pi.createVenv(destDir); err != nil {
		return fmt.Errorf("failed to set up Python environment: %w", err)
	}

	if err := writeHelperScript(destDir); err != nil {
		return fmt.Errorf("failed to write helper script: %w", err)
	}

	return nil
}

func (pi *PluginInstaller) fetchLatestRelease() (*githubRelease, error) {
	if !pi.skipURLValidation {
		if err := validateGitHubURL(pi.releasesURL); err != nil {
			return nil, fmt.Errorf("invalid releases URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", pi.releasesURL, nil) //nolint:gosec // URL validated by validateGitHubURL above
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := pi.httpClient.Do(req) //nolint:gosec // URL validated by validateGitHubURL above
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

func (pi *PluginInstaller) downloadAndExtract(tarballURL, destDir string) error {
	if !pi.skipURLValidation {
		if err := validateGitHubURL(tarballURL); err != nil {
			return fmt.Errorf("invalid tarball URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", tarballURL, nil) //nolint:gosec // URL validated by validateGitHubURL above
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := pi.httpClient.Do(req) //nolint:gosec // URL validated by validateGitHubURL above
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

		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
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

func (pi *PluginInstaller) createVenv(pluginDir string) error {
	python := findPython()
	if python == "" {
		return fmt.Errorf("Python 3.11+ is required but not found in PATH") //nolint:staticcheck // proper noun
	}

	venvDir := filepath.Join(pluginDir, ".venv")
	// armis:ignore cwe:94 reason:python path from findPython allowlist (python3/python only); args are hardcoded
	venvCmd := exec.Command(python, "-m", "venv", venvDir) //nolint:gosec // python validated by findPython allowlist
	venvCmd.Stdout = os.Stderr
	venvCmd.Stderr = os.Stderr
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("creating venv: %w", err)
	}

	pip := filepath.Join(venvDir, "bin", "pip")
	if runtime.GOOS == osWindows {
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

// writeEnvFromEnvironment writes ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET to a .env
// file if both are set in the current process environment. Returns nil if the file
// was written or if there is nothing to do (file exists or env vars unset).
// Returns an error if the file's existence cannot be determined or if the write fails.
func writeEnvFromEnvironment(envPath string) error {
	if _, err := os.Stat(envPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking env file: %w", err)
	}

	clientID := os.Getenv("ARMIS_CLIENT_ID")
	clientSecret := os.Getenv("ARMIS_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return nil
	}

	// armis:ignore cwe:522 reason:CLI writes credentials to .env file with 0600 permissions for local auth config
	content := fmt.Sprintf("ARMIS_CLIENT_ID=%s\nARMIS_CLIENT_SECRET=%s\n", clientID, clientSecret)
	// armis:ignore cwe:73 reason:envPath constructed from pluginDir (known cache dir) + hardcoded ".env" filename
	if err := os.MkdirAll(filepath.Dir(envPath), 0o750); err != nil {
		return fmt.Errorf("creating env directory: %w", err)
	}
	// armis:ignore cwe:73 reason:envPath constructed from pluginDir (known cache dir) + hardcoded ".env" filename
	if err := os.WriteFile(filepath.Clean(envPath), []byte(content), 0o600); err != nil { // #nosec G703 - envPath is constructed from pluginDir + ".env"
		return fmt.Errorf("writing env file: %w", err)
	}
	return nil
}

// writeHelperScript writes a standalone scan script that editors without
// native MCP support (e.g. Copilot) can invoke to scan files directly.
func writeHelperScript(pluginDir string) error {
	scriptPath := filepath.Join(pluginDir, "scan_file.py")
	script := `#!/usr/bin/env python3
"""Scan a file for security vulnerabilities using the Armis AppSec scanner.

Usage: python3 scan_file.py <file_path>

This script calls the same scanning engine as the MCP server but can be
invoked directly from editors that cannot call MCP tools natively.
"""
import os
import sys

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _plugin_dir)

from dotenv import load_dotenv

_env_file = os.path.join(_plugin_dir, ".env")
if os.path.isfile(_env_file):
    load_dotenv(_env_file, override=False)

from auth import init_auth
from scanner_core import call_appsec_api, format_findings, parse_findings

if len(sys.argv) != 2:
    print("Usage: python3 scan_file.py <file_path>", file=sys.stderr)
    sys.exit(1)

file_path = os.path.abspath(sys.argv[1])
if not os.path.isfile(file_path):
    print(f"Error: {file_path} not found", file=sys.stderr)
    sys.exit(1)

init_auth()
with open(file_path) as f:
    code = f.read()

raw = call_appsec_api(code)
findings = parse_findings(raw)
print(format_findings(findings, os.path.basename(file_path)))
`
	return os.WriteFile(filepath.Clean(scriptPath), []byte(script), 0o750) // #nosec G306 - script needs execute permission
}

// venvPython returns the path to the Python interpreter inside a venv.
func venvPython(pluginDir string) string {
	if runtime.GOOS == osWindows {
		return filepath.Join(pluginDir, ".venv", "Scripts", "python.exe")
	}
	return filepath.Join(pluginDir, ".venv", "bin", "python")
}

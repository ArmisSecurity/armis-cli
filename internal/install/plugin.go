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

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
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

var pythonCandidates = []string{"python3.13", "python3.12", "python3.11", "python3", "python"}

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
		httpClient:  &http.Client{Timeout: downloadTimeout, Transport: httpclient.ProxyAwareTransport()},
		releasesURL: releasesURL,
	}
}

// InstalledVersion returns the version that was installed (available after FetchAndInstall).
func (pi *PluginInstaller) InstalledVersion() string {
	return pi.installedVersion
}

// LatestVersion checks GitHub for the latest release version without downloading.
func (pi *PluginInstaller) LatestVersion() (string, error) {
	release, err := pi.fetchLatestRelease()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
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
		return fmt.Errorf("Python 3.11+ is required but not found in PATH (tried %s)", strings.Join(pythonCandidates, ", ")) //nolint:staticcheck // proper noun
	}

	venvDir := filepath.Join(pluginDir, ".venv")
	// armis:ignore cwe:94 reason:python path from findPython allowlist (python3/python only); args are hardcoded
	// armis:ignore cwe:78 reason:python binary from findPython allowlist; all args are hardcoded literals
	venvCmd := exec.Command(python, "-m", "venv", venvDir) //nolint:gosec // python validated by findPython allowlist
	venvCmd.Stdout = os.Stderr                             // armis:ignore cwe:78 reason:part of venvCmd above
	venvCmd.Stderr = os.Stderr
	if err := venvCmd.Run(); err != nil {
		return fmt.Errorf("creating venv: %w", err)
	}

	pip := filepath.Join(venvDir, "bin", "pip")
	if runtime.GOOS == osWindows {
		pip = filepath.Join(venvDir, "Scripts", "pip.exe")
	}
	reqsFile := filepath.Join(pluginDir, "requirements.txt")
	// --prefer-binary makes pip favor the newest dependency version that ships a
	// usable wheel over a newer source-only release, instead of pip's default of
	// "newest version wins, build from source if needed". This matters for the
	// transitive cryptography dep (mcp[cli] -> pyjwt[crypto] -> cryptography):
	// when its latest release lacks a matching wheel, a source build pulls in a
	// Rust toolchain via a rustup-init download — which fails behind corporate
	// TLS-inspecting proxies (e.g. Zscaler) with CERTIFICATE_VERIFY_FAILED. A
	// prior wheeled version exists, so this avoids the build entirely without
	// pinning anything. pip falls back to a source build only if no version has
	// a compatible wheel, so machines that already worked are unaffected.
	// armis:ignore cwe:78 reason:pip binary from our own venv directory; args are hardcoded literals
	// armis:ignore cwe:94 reason:pip binary from our own venv; reqsFile is hardcoded "requirements.txt"
	pipCmd := exec.Command(pip, "install", "-q", "--prefer-binary", "-r", reqsFile) //nolint:gosec // pip path derived from our own venv
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
	for _, name := range pythonCandidates {
		resolved, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		resolved, err = filepath.EvalSymlinks(resolved)
		if err != nil || !filepath.IsAbs(resolved) {
			continue
		}
		// armis:ignore cwe:94 reason:resolved path from hardcoded allowlist (python3/python); -c arg is a hardcoded literal
		// armis:ignore cwe:78 reason:resolved path from hardcoded allowlist; args are hardcoded literals
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
	// armis:ignore cwe:522 reason:credentials written to 0600 file in user-local plugin dir; required for MCP server auth
	if err := os.WriteFile(filepath.Clean(envPath), []byte(content), 0o600); err != nil { // #nosec G703 - envPath is constructed from pluginDir + ".env"
		return fmt.Errorf("writing env file: %w", err)
	}
	return nil
}

// WriteEnvFromValues writes client credentials to a .env file at envPath.
// If the file already exists, it is backed up to .env.bak before overwriting.
// The write is atomic (temp file + rename) to prevent corruption on interrupt.
// armis:ignore cwe:73 reason:envPath derived from known plugin dir + ".env"; callers are internal install functions
func WriteEnvFromValues(envPath, clientID, clientSecret string) error {
	if strings.ContainsAny(clientID, "\n\r") || strings.ContainsAny(clientSecret, "\n\r") {
		return fmt.Errorf("credentials must not contain newline characters")
	}

	cleanPath := filepath.Clean(envPath)

	// Back up existing file via copy (not rename) so the original remains if a later step fails
	if _, err := os.Stat(cleanPath); err == nil {
		bakPath := cleanPath + ".bak"
		// armis:ignore cwe:73 reason:bakPath derived from cleanPath which is constructed from known plugin dir + ".env"
		if err := copyFile(cleanPath, bakPath); err != nil {
			return fmt.Errorf("could not back up %s: %w", filepath.Base(cleanPath), err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking existing env file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return fmt.Errorf("creating env directory: %w", err)
	}

	// armis:ignore cwe:522 reason:CLI writes credentials to .env file with 0600 permissions for local auth config
	content := fmt.Sprintf("ARMIS_CLIENT_ID=%s\nARMIS_CLIENT_SECRET=%s\n", clientID, clientSecret)

	// Atomic write: randomized temp file + rename
	// armis:ignore cwe:73 reason:temp file created in same directory as target, derived from known plugin dir
	tmpFile, err := os.CreateTemp(filepath.Dir(cleanPath), ".env.tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp env file: %w", err)
	}
	tmpPath := tmpFile.Name() //nolint:gosec // G703: temp file created in same dir as target via os.CreateTemp
	closed := false
	defer func() {
		if !closed {
			_ = tmpFile.Close()
		}
	}()
	if _, err := tmpFile.WriteString(content); err != nil {
		_ = os.Remove(tmpPath) //nolint:gosec // G703: tmpPath from os.CreateTemp in known plugin dir
		return fmt.Errorf("writing temp env file: %w", err)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = os.Remove(tmpPath) //nolint:gosec // G703: tmpPath from os.CreateTemp in known plugin dir
		return fmt.Errorf("setting env file permissions: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath) //nolint:gosec // G703: tmpPath from os.CreateTemp in known plugin dir
		return fmt.Errorf("closing temp env file: %w", err)
	}
	closed = true
	// armis:ignore cwe:22 reason:cleanPath derived from known plugin dir + ".env", not external input
	if err := os.Rename(tmpPath, cleanPath); err != nil { //nolint:gosec // G703: both paths from known plugin dir
		if runtime.GOOS != osWindows {
			_ = os.Remove(tmpPath) //nolint:gosec // G703: tmpPath from os.CreateTemp in known plugin dir
			return fmt.Errorf("finalizing env file: %w", err)
		}
		// On Windows, Rename fails if destination exists; remove and retry.
		_ = os.Remove(cleanPath) //nolint:gosec // G703: cleanPath from known plugin dir; already backed up above
		if retryErr := os.Rename(tmpPath, cleanPath); retryErr != nil {
			_ = os.Remove(tmpPath) //nolint:gosec // G703: tmpPath from os.CreateTemp in known plugin dir
			return fmt.Errorf("finalizing env file: %w", retryErr)
		}
	}
	return nil
}

// armis:ignore cwe:73 reason:called only from WriteEnvFromValues with paths from known plugin dir
func copyFile(src, dst string) error {
	in, err := os.Open(filepath.Clean(src)) //nolint:gosec // src from known plugin dir
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only file, close error is informational

	out, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // dst from known plugin dir
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// venvPython returns the path to the Python interpreter inside a venv.
func venvPython(pluginDir string) string {
	if runtime.GOOS == osWindows {
		return filepath.Join(pluginDir, ".venv", "Scripts", "python.exe")
	}
	return filepath.Join(pluginDir, ".venv", "bin", "python")
}

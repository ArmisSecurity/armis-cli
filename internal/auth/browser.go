// Package auth provides authentication for the Armis API.
// This file opens the system browser for the device-flow verification page.
package auth

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// browserOpener is overridable so the device-login flow can be exercised
// without spawning a real browser. See SetBrowserOpener.
var browserOpener = openBrowserCmd

// SetBrowserOpener replaces the function used to launch the browser and returns
// a function that restores the previous opener. It is intended for tests (which
// must not spawn a real browser); production code uses the default opener.
func SetBrowserOpener(fn func(string) error) (restore func()) {
	prev := browserOpener
	browserOpener = fn
	return func() { browserOpener = prev }
}

// OpenBrowser attempts to open the given URL in the user's default browser.
// It returns an error when no opener is available (headless server, SSH, locked
// down terminal); callers fall back to printing the URL and user_code.
//
// Only http(s) URLs are accepted, so a malformed verification URI cannot be
// turned into the execution of an arbitrary local handler.
func OpenBrowser(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != schemeHTTP && parsed.Scheme != schemeHTTPS {
		return fmt.Errorf("refusing to open non-http(s) URL")
	}
	return browserOpener(rawURL)
}

// openBrowserCmd launches the platform-specific browser opener.
//
// armis:ignore cwe:78 reason:URL is validated as http(s) by OpenBrowser and passed as a single argv element (no shell), not interpolated into a command string
func openBrowserCmd(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// #nosec G204 -- rawURL is validated as http(s) by OpenBrowser and passed as a separate argv element (no shell)
		cmd = exec.Command("open", rawURL)
	case "windows":
		// #nosec G204 -- rawURL is validated as http(s) by OpenBrowser and passed as a separate argv element (no shell)
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default: // linux, *bsd, etc.
		// #nosec G204 -- rawURL is validated as http(s) by OpenBrowser and passed as a separate argv element (no shell)
		cmd = exec.Command("xdg-open", rawURL)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}
	// Reap the child so it does not become a zombie; the browser detaches itself.
	go func() { _ = cmd.Wait() }() //nolint:errcheck // fire-and-forget
	return nil
}

package install

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// DefaultBundleName returns the file name used when --bundle is given without
// a path.
func DefaultBundleName() string {
	return "armis-mcp-doctor-" + time.Now().Format("20060102-150405") + ".zip"
}

// WriteSupportBundle writes report and its collected artifacts to a zip at
// path for the user to attach to a support request. Credentials are never
// included: .env files contribute only variable names, editor entries omit env
// values, every credential value seen during the run is scrubbed verbatim,
// and all text passes through the CLI's secret masker as a second layer.
func WriteSupportBundle(report *DoctorReport, path, cliVersion string) error {
	// armis:ignore cwe:22 cwe:73 reason:path is the user's own --bundle argument for a file they are creating
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // user-chosen output path
	if err != nil {
		return fmt.Errorf("creating bundle: %w", err)
	}
	zw := zip.NewWriter(f)

	scrub := func(s string) string {
		for _, secret := range report.secrets {
			if len(secret) >= 4 {
				s = strings.ReplaceAll(s, secret, "***")
			}
		}
		return util.MaskSecretInMultiLineString(s)
	}
	write := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(scrub(content)))
		return err
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_ = zw.Close()
		_ = f.Close()
		return fmt.Errorf("encoding report: %w", err)
	}
	files := map[string]string{
		"report.json": string(reportJSON) + "\n",
		"README.txt": "Armis MCP doctor support bundle.\n" +
			"armis-cli version: " + cliVersion + "\n" +
			"Credentials are not included: .env files contribute only variable names.\n",
	}
	for k, v := range report.Artifacts {
		files[k] = v
	}
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := write(name, files[name]); err != nil {
			_ = zw.Close()
			_ = f.Close()
			return fmt.Errorf("writing %s to bundle: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("finalizing bundle: %w", err)
	}
	return f.Close()
}

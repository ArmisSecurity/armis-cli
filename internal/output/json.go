package output

import (
	"encoding/json"
	"io"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// JSONFormatter formats scan results as JSON.
type JSONFormatter struct{}

// Format formats the scan result as JSON.
func (f *JSONFormatter) Format(result *model.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// FormatWithOptions formats the scan result as JSON with custom options.
func (f *JSONFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
	if opts.Debug {
		return f.formatWithDebug(result, w, opts)
	}
	return f.Format(result, w)
}

// formatWithDebug outputs JSON with additional debug metadata.
func (f *JSONFormatter) formatWithDebug(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
	type debugOutput struct {
		*model.ScanResult
		FormatOptions struct {
			GroupBy  string `json:"groupBy,omitempty"`
			RepoPath string `json:"repoPath,omitempty"`
			Debug    bool   `json:"debug"`
		} `json:"_formatOptions"`
	}

	out := debugOutput{ScanResult: result}
	out.FormatOptions.GroupBy = opts.GroupBy
	out.FormatOptions.RepoPath = opts.RepoPath
	out.FormatOptions.Debug = opts.Debug

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

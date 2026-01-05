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
func (f *JSONFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, _ FormatOptions) error {
	return f.Format(result, w)
}

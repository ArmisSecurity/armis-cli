package output

import (
	"encoding/json"
	"io"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(result *model.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (f *JSONFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
	return f.Format(result, w)
}

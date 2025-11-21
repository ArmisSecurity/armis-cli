package output

import (
	"encoding/json"
	"io"

	"github.com/silk-security/armis-cli/internal/model"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(result *model.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

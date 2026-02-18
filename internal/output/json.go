package output

import (
	"encoding/json"
	"io"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// JSONFormatter formats scan results as JSON.
type JSONFormatter struct{}

// Format formats the scan result as JSON.
func (f *JSONFormatter) Format(result *model.ScanResult, w io.Writer) error {
	// Defense-in-depth: mask secrets before JSON serialization
	masked := maskScanResultForOutput(result)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(masked)
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
	// Defense-in-depth: mask secrets before JSON serialization
	masked := maskScanResultForOutput(result)

	type debugOutput struct {
		*model.ScanResult
		FormatOptions struct {
			GroupBy  string `json:"groupBy,omitempty"`
			RepoPath string `json:"repoPath,omitempty"`
			Debug    bool   `json:"debug"`
		} `json:"_formatOptions"`
	}

	out := debugOutput{ScanResult: masked}
	out.FormatOptions.GroupBy = opts.GroupBy
	out.FormatOptions.RepoPath = opts.RepoPath
	out.FormatOptions.Debug = opts.Debug

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// maskScanResultForOutput creates a shallow copy of ScanResult with secrets
// masked in code-containing fields. This provides defense-in-depth against
// secret leakage through JSON output.
func maskScanResultForOutput(result *model.ScanResult) *model.ScanResult {
	if result == nil {
		return nil
	}

	// Shallow copy the ScanResult
	masked := *result

	// Deep copy and mask the findings slice
	if len(result.Findings) > 0 {
		masked.Findings = make([]model.Finding, len(result.Findings))
		for i, f := range result.Findings {
			masked.Findings[i] = maskFindingSecrets(f)
		}
	}

	return &masked
}

// maskFindingSecrets returns a copy of the Finding with secrets masked in code fields.
func maskFindingSecrets(f model.Finding) model.Finding {
	// Mask CodeSnippet
	if f.CodeSnippet != "" {
		f.CodeSnippet = util.MaskSecretInMultiLineString(f.CodeSnippet)
	}

	// Mask Fix data
	if f.Fix != nil {
		fixCopy := *f.Fix

		if fixCopy.Patch != nil && *fixCopy.Patch != "" {
			masked := util.MaskSecretInMultiLineString(*fixCopy.Patch)
			fixCopy.Patch = &masked
		}

		if fixCopy.VulnerableCode != nil {
			vcCopy := *fixCopy.VulnerableCode
			vcCopy.Content = util.MaskSecretInMultiLineString(vcCopy.Content)
			fixCopy.VulnerableCode = &vcCopy
		}

		if len(fixCopy.ProposedFixes) > 0 {
			maskedFixes := make([]model.CodeSnippetFix, len(fixCopy.ProposedFixes))
			for i, pf := range fixCopy.ProposedFixes {
				maskedFixes[i] = pf
				maskedFixes[i].Content = util.MaskSecretInMultiLineString(pf.Content)
			}
			fixCopy.ProposedFixes = maskedFixes
		}

		if len(fixCopy.PatchFiles) > 0 {
			fixCopy.PatchFiles = util.MaskSecretsInStringMap(fixCopy.PatchFiles)
		}

		f.Fix = &fixCopy
	}

	return f
}

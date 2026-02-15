// Package scan provides shared utilities for scanning operations.
package scan

import (
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// MaskFixSecrets masks potential secrets in all code-containing fields of a Fix struct.
// Returns a new Fix with masked content; the original is not modified.
// This prevents secrets from leaking through proposed fix code, patches, and patch files.
//
// The following fields are masked:
//   - Patch: unified diff content (multi-line)
//   - VulnerableCode.Content: source code snippet
//   - ProposedFixes[].Content: proposed code changes
//   - PatchFiles: map of file paths to patch content
//
// Text fields (Explanation, Recommendations, Feedback) are NOT masked as they contain
// human-readable analysis, not raw code.
func MaskFixSecrets(fix *model.Fix) *model.Fix {
	if fix == nil {
		return nil
	}

	// Create a shallow copy of the Fix struct
	fixCopy := *fix

	// Mask the Patch field (unified diff format, multi-line)
	if fixCopy.Patch != nil && *fixCopy.Patch != "" {
		masked := util.MaskSecretInMultiLineString(*fixCopy.Patch)
		fixCopy.Patch = &masked
	}

	// Mask VulnerableCode.Content
	if fixCopy.VulnerableCode != nil {
		vcCopy := *fixCopy.VulnerableCode
		vcCopy.Content = util.MaskSecretInMultiLineString(vcCopy.Content)
		fixCopy.VulnerableCode = &vcCopy
	}

	// Mask each ProposedFixes[].Content
	if len(fixCopy.ProposedFixes) > 0 {
		maskedFixes := make([]model.CodeSnippetFix, len(fixCopy.ProposedFixes))
		for i, pf := range fixCopy.ProposedFixes {
			maskedFixes[i] = pf
			maskedFixes[i].Content = util.MaskSecretInMultiLineString(pf.Content)
		}
		fixCopy.ProposedFixes = maskedFixes
	}

	// Mask PatchFiles map values
	if len(fixCopy.PatchFiles) > 0 {
		fixCopy.PatchFiles = util.MaskSecretsInStringMap(fixCopy.PatchFiles)
	}

	return &fixCopy
}

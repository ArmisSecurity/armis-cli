package cmdutil

import (
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Brand colors matching internal/output/styles.go. The exported colors are
// referenced by interactive flows outside this package (install, uninstall);
// the unexported ones are used only by armisTheme below.
var (
	BrandAccent    = lipgloss.AdaptiveColor{Light: "#7c3aed", Dark: "#7c3aed"} // purple-600 (Armis brand)
	BrandSuccess   = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#22C55E"} // green-600/500 (completion ✓)
	BrandError     = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#EF4444"} // red-600/500
	BrandMuted     = lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#6B7280"} // gray-600/500
	BrandSeparator = lipgloss.AdaptiveColor{Light: "#C4B5FD", Dark: "#4C1D95"} // purple-300/900 (title underline)
	BrandWarn      = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#F59E0B"} // amber-600/500

	brandSelected    = lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34D399"} // emerald-600/400 (multi-select [+])
	brandBright      = lipgloss.AdaptiveColor{Light: "#1F2937", Dark: "#FFFFFF"} // gray-800/white
	brandBorder      = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#374151"} // gray-300/700 (buttons)
	brandPanelBorder = lipgloss.AdaptiveColor{Light: "#6366F1", Dark: "#818CF8"} // indigo-500/400 (interactive panels)
	brandDim         = lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#4B5563"} // gray-400/600
)

func armisTheme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Base = t.Focused.Base.BorderForeground(brandPanelBorder)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(brandBright).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(BrandAccent).Bold(true).MarginBottom(1)
	t.Focused.Description = t.Focused.Description.Foreground(BrandMuted)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(BrandError)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(BrandError)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(BrandAccent)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(BrandAccent)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(BrandAccent)
	t.Focused.Option = t.Focused.Option.Foreground(brandBright)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(BrandAccent)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(brandSelected)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(brandSelected).SetString("[+] ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(brandDim).SetString("[ ] ")
	t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(brandBright)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.Color("#FFFFFF")).Background(BrandAccent).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(brandBright).Background(brandBorder)

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(BrandAccent)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(brandDim)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(BrandAccent)

	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description

	return t
}

// GetInstallTheme returns the Armis-branded huh theme, or the plain base theme
// when colors are disabled (NO_COLOR, non-TTY, --color=never).
func GetInstallTheme() *huh.Theme {
	if !cli.ColorsEnabled() {
		return huh.ThemeBase()
	}
	return armisTheme()
}

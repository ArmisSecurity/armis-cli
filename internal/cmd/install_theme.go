package cmd

import (
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Brand colors matching internal/output/styles.go
var (
	brandAccent      = lipgloss.AdaptiveColor{Light: "#7c3aed", Dark: "#7c3aed"} // purple-600 (Armis brand)
	brandSuccess     = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#22C55E"} // green-600/500 (completion ✓)
	brandSelected    = lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34D399"} // emerald-600/400 (multi-select [+])
	brandError       = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#EF4444"} // red-600/500
	brandMuted       = lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#6B7280"} // gray-600/500
	brandBright      = lipgloss.AdaptiveColor{Light: "#1F2937", Dark: "#FFFFFF"} // gray-800/white
	brandBorder      = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#374151"} // gray-300/700 (buttons)
	brandSeparator   = lipgloss.AdaptiveColor{Light: "#C4B5FD", Dark: "#4C1D95"} // purple-300/900 (title underline)
	brandPanelBorder = lipgloss.AdaptiveColor{Light: "#6366F1", Dark: "#818CF8"} // indigo-500/400 (interactive panels)
	brandDim         = lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#4B5563"} // gray-400/600
)

func armisTheme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Base = t.Focused.Base.BorderForeground(brandPanelBorder)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(brandBright).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(brandAccent).Bold(true).MarginBottom(1)
	t.Focused.Description = t.Focused.Description.Foreground(brandMuted)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(brandError)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(brandError)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(brandAccent)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(brandAccent)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(brandAccent)
	t.Focused.Option = t.Focused.Option.Foreground(brandBright)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(brandAccent)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(brandSelected)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(brandSelected).SetString("[+] ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(brandDim).SetString("[ ] ")
	t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(brandBright)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.Color("#FFFFFF")).Background(brandAccent).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(brandBright).Background(brandBorder)

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(brandAccent)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(brandDim)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(brandAccent)

	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description

	return t
}

func getInstallTheme() *huh.Theme {
	if !cli.ColorsEnabled() {
		return huh.ThemeBase()
	}
	return armisTheme()
}

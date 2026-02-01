package util

import "strings"

// FormatCategory converts a SCREAMING_SNAKE_CASE category like "CODE_VULNERABILITY"
// to a human-readable "Code Vulnerability" format.
func FormatCategory(category string) string {
	if category == "" {
		return ""
	}
	words := strings.Split(strings.ToLower(category), "_")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

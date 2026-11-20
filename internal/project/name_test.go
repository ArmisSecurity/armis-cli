package project

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidateName_Valid(t *testing.T) {
	valid := []string{
		"a",
		"7",
		"my-service",
		"my_service",
		"MyService",
		"service.v2",
		"team/checkout",
		"org/team/service-1.2_rc",
		"a--b", // repeated separators are allowed in the middle
		"a//b",
		"1589",
		"Null-project", // a reserved word inside a longer name is fine
		"nullable",
		strings.Repeat("a", MaxNameLength),
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateName(name); err != nil {
				t.Fatalf("ValidateName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestValidateName_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantRules   []Rule
		wantInMsg   []string // substrings the message must carry
		wantExample string
	}{
		{
			name:        "empty",
			input:       "",
			wantRules:   []Rule{RuleEmpty},
			wantInMsg:   []string{"it is empty", "1 to 64 characters"},
			wantExample: fallbackExample,
		},
		{
			name:        "only whitespace",
			input:       "   ",
			wantRules:   []Rule{RuleEmpty},
			wantInMsg:   []string{"only whitespace"},
			wantExample: fallbackExample,
		},
		{
			name:        "too long",
			input:       strings.Repeat("a", MaxNameLength+1),
			wantRules:   []Rule{RuleTooLong},
			wantInMsg:   []string{"65 characters long", "maximum is 64"},
			wantExample: strings.Repeat("a", MaxNameLength),
		},
		{
			name:        "space",
			input:       "my project",
			wantRules:   []Rule{RuleCharset},
			wantInMsg:   []string{"a character that is not allowed", "' ' (space)", "'.', '_', '-' and '/'"},
			wantExample: "my-project",
		},
		{
			// The API trims surrounding whitespace and silently renames the
			// project; the CLI must reject it instead.
			name:        "surrounding whitespace is rejected, not trimmed",
			input:       "  padded  ",
			wantRules:   []Rule{RuleCharset},
			wantExample: "padded",
		},
		{
			name:        "several disallowed characters",
			input:       "bad@name!#",
			wantRules:   []Rule{RuleCharset},
			wantInMsg:   []string{"characters that are not allowed", "'@'", "'!'", "'#'"},
			wantExample: "bad-name",
		},
		{
			name:        "non-ASCII letter",
			input:       "café-1589",
			wantRules:   []Rule{RuleCharset},
			wantInMsg:   []string{"'é'"},
			wantExample: "caf-1589",
		},
		{
			name:        "CJK",
			input:       "名前1589",
			wantRules:   []Rule{RuleCharset},
			wantExample: "1589",
		},
		{
			name:      "invisible zero-width space is shown escaped",
			input:     "a\u200bb",
			wantRules: []Rule{RuleCharset},
			wantInMsg: []string{`'\u200b'`, `"a\u200bb"`},
		},
		{
			name:      "listed characters are capped",
			input:     "a!b@c#d$e%f^g",
			wantRules: []Rule{RuleCharset},
			wantInMsg: []string{"and 1 more"},
		},
		{
			name:        "flag swallowed as the value",
			input:       "--sync",
			wantRules:   []Rule{RuleBoundary},
			wantInMsg:   []string{"must start with a letter or digit, not '-'", "did --project miss its value?"},
			wantExample: fallbackExample,
		},
		{
			name:        "short flag swallowed as the value",
			input:       "-o",
			wantRules:   []Rule{RuleBoundary},
			wantInMsg:   []string{"did --project miss its value?"},
			wantExample: fallbackExample,
		},
		{
			name:        "leading dash typo is not called a flag",
			input:       "-my-service",
			wantRules:   []Rule{RuleBoundary},
			wantExample: "my-service",
		},
		{
			name:        "dot",
			input:       ".",
			wantRules:   []Rule{RuleBoundary},
			wantExample: fallbackExample,
		},
		{
			name:        "dot dot",
			input:       "..",
			wantRules:   []Rule{RuleBoundary},
			wantExample: fallbackExample,
		},
		{
			name:        "leading slash",
			input:       "/src",
			wantRules:   []Rule{RuleBoundary},
			wantInMsg:   []string{"start with a letter or digit, not '/'"},
			wantExample: "src",
		},
		{
			name:        "leading underscore",
			input:       "_internal",
			wantRules:   []Rule{RuleBoundary},
			wantExample: "internal",
		},
		{
			name:        "trailing slash",
			input:       "team/",
			wantRules:   []Rule{RuleBoundary},
			wantInMsg:   []string{"must end with a letter or digit, not '/'"},
			wantExample: "team",
		},
		{
			name:        "trailing dot",
			input:       "v1.",
			wantRules:   []Rule{RuleBoundary},
			wantExample: "v1",
		},
		{
			name:        "reserved null",
			input:       "null",
			wantRules:   []Rule{RuleReserved},
			wantInMsg:   []string{`"null" is a reserved word`, "unset CI or template variable"},
			wantExample: fallbackExample,
		},
		{
			name:      "reserved words ignore case",
			input:     "None",
			wantRules: []Rule{RuleReserved},
		},
		{
			name:      "reserved undefined",
			input:     "UNDEFINED",
			wantRules: []Rule{RuleReserved},
		},
		{
			name:      "reserved nil",
			input:     "nil",
			wantRules: []Rule{RuleReserved},
		},
		{
			name:        "every applicable rule is reported",
			input:       strings.Repeat("x", 70) + " /",
			wantRules:   []Rule{RuleTooLong, RuleCharset, RuleBoundary},
			wantInMsg:   []string{"3 problems:", "\n  - it is 72 characters long", "\n  - it contains", "\n  - it must end"},
			wantExample: strings.Repeat("x", MaxNameLength),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			if err == nil {
				t.Fatalf("ValidateName(%q) = nil, want an error", tt.input)
			}
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("errors.Is(err, ErrInvalidName) = false for %v", err)
			}
			var nameErr *NameError
			if !errors.As(err, &nameErr) {
				t.Fatalf("error is %T, want *NameError", err)
			}

			gotRules := make([]Rule, 0, len(nameErr.Violations))
			for _, v := range nameErr.Violations {
				gotRules = append(gotRules, v.Rule)
			}
			if strings.Join(rulesToStrings(gotRules), ",") != strings.Join(rulesToStrings(tt.wantRules), ",") {
				t.Errorf("rules = %v, want %v", gotRules, tt.wantRules)
			}
			for _, r := range tt.wantRules {
				if !nameErr.Broken(r) {
					t.Errorf("Broken(%q) = false, want true", r)
				}
			}

			msg := err.Error()
			if !strings.HasPrefix(msg, "invalid --project name ") {
				t.Errorf("message should start by naming the flag, got %q", msg)
			}
			for _, want := range tt.wantInMsg {
				if !strings.Contains(msg, want) {
					t.Errorf("message missing %q:\n%s", want, msg)
				}
			}
			if !strings.Contains(msg, "Example of a valid name: --project "+nameErr.Example) {
				t.Errorf("message should end with the example, got:\n%s", msg)
			}
			if tt.wantExample != "" && nameErr.Example != tt.wantExample {
				t.Errorf("example = %q, want %q", nameErr.Example, tt.wantExample)
			}
			if exErr := ValidateName(nameErr.Example); exErr != nil {
				t.Errorf("suggested example %q is itself invalid: %v", nameErr.Example, exErr)
			}
		})
	}
}

// TestValidateName_LongInputIsShortenedInMessage keeps a pasted blob from
// flooding the terminal.
func TestValidateName_LongInputIsShortenedInMessage(t *testing.T) {
	err := ValidateName(strings.Repeat("a", 500))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), strings.Repeat("a", maxDisplayedNameRunes+1)) {
		t.Errorf("message echoes more than %d characters of the name", maxDisplayedNameRunes)
	}
	if !strings.Contains(err.Error(), `..." `) && !strings.Contains(err.Error(), `...:`) {
		t.Errorf("message should mark the name as shortened, got %q", err.Error())
	}
}

// TestValidateName_HugeInputIsBounded: a pasted multi-megabyte value is
// rejected with its real length, a bounded message and a valid example, while
// the character rules only look at its first maxInspectedBytes.
func TestValidateName_HugeInputIsBounded(t *testing.T) {
	huge := strings.Repeat("a", 4<<20) + "!"
	err := ValidateName(huge)
	var nameErr *NameError
	if !errors.As(err, &nameErr) || !nameErr.Broken(RuleTooLong) {
		t.Fatalf("err = %v, want a too-long error", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("it is %d characters long", 4<<20+1)) {
		t.Errorf("the real length should be reported: %.200s", err.Error())
	}
	if nameErr.Broken(RuleCharset) {
		t.Error("a disallowed character past maxInspectedBytes should not be looked for")
	}
	if len(err.Error()) > 1024 || nameErr.Example != strings.Repeat("a", MaxNameLength) {
		t.Errorf("message length %d, example %q", len(err.Error()), nameErr.Example)
	}
}

func TestInspectedPrefix(t *testing.T) {
	if got := inspectedPrefix("short"); got != "short" {
		t.Errorf("short input changed: %q", got)
	}
	// A 4-byte rune straddling the cut is dropped whole, not split.
	s := strings.Repeat("a", maxInspectedBytes-2) + "😀" + "tail"
	if got := inspectedPrefix(s); got != strings.Repeat("a", maxInspectedBytes-2) || !utf8.ValidString(got) {
		t.Errorf("prefix = %.20q (len %d), want the runes before the cut", got, len(got))
	}
	// Input that is not UTF-8 still yields a non-empty prefix.
	if got := inspectedPrefix(strings.Repeat("\x80", 2*maxInspectedBytes)); len(got) == 0 || len(got) > maxInspectedBytes {
		t.Errorf("non-UTF-8 prefix length = %d", len(got))
	}
}

// FuzzValidateName checks that validation never panics, that a rejected name
// always comes with an example that is itself valid, and that an accepted name
// really satisfies the rules.
func FuzzValidateName(f *testing.F) {
	for _, seed := range []string{
		"", " ", "a", "my-service", "--sync", "-o", ".", "..", "/x", "x/", "null",
		"café", "名前", "a\u200bb", "\xff\xfe", strings.Repeat("a", 65), "  padded  ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := ValidateName(name)
		if err == nil {
			if n := utf8.RuneCountInString(name); n < 1 || n > MaxNameLength {
				t.Fatalf("accepted %q with %d characters", name, n)
			}
			for _, r := range name {
				if !isAllowed(r) {
					t.Fatalf("accepted %q with disallowed rune %q", name, r)
				}
			}
			return
		}
		var nameErr *NameError
		if !errors.As(err, &nameErr) {
			t.Fatalf("error is %T, want *NameError", err)
		}
		if len(nameErr.Violations) == 0 {
			t.Fatalf("rejected %q without naming a rule", name)
		}
		if exErr := ValidateName(nameErr.Example); exErr != nil {
			t.Fatalf("example %q for %q is invalid: %v", nameErr.Example, name, exErr)
		}
	})
}

func rulesToStrings(rules []Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = string(r)
	}
	return out
}

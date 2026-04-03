// Package rules contains different rules for password validation
package rules

import (
	"fmt"
)

// PasswordRule defines a single password validation rule.
type PasswordRule interface {
	String() string
	Validate(string) bool
}

func Minimum(min int) passwordRule {
	return passwordRule{
		description: fmt.Sprintf("at least %d characters", min),
		validator:   func(p string) bool { return len(p) >= min },
	}
}

var (
	HasLower = passwordRule{
		description: "one lowercase letter",
		validator:   func(p string) bool { return hasLower.MatchString(p) },
	}
	HasUpper = passwordRule{
		description: "one uppercase letter",
		validator:   func(p string) bool { return hasUpper.MatchString(p) },
	}
	HasDigit = passwordRule{
		description: "one digit",
		validator:   func(p string) bool { return hasDigit.MatchString(p) },
	}
)

// DefaultPasswordRules requires at least 8 characters, one uppercase letter,
// one lowercase letter, and one digit.
var DefaultPasswordRules = []PasswordRule{
	Minimum(defaultMinimumCharacters),
	HasLower,
	HasUpper,
	HasDigit,
}

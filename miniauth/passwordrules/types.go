package rules

import "regexp"

const defaultMinimumCharacters = 8

type validationFn func(string) bool

var (
	hasLower = regexp.MustCompile(`[a-z]`)
	hasUpper = regexp.MustCompile(`[A-Z]`)
	hasDigit = regexp.MustCompile(`[0-9]`)
)

type passwordRule struct {
	description string
	validator   validationFn
}

func (p passwordRule) Validate(s string) bool {
	return p.validator(s)
}

func (p passwordRule) String() string {
	return p.description
}

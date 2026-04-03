package rules

import (
	"testing"
)

func TestDefaultPasswordRules(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		wantValid  bool
		wantFailed []string
	}{
		{
			name:      "valid password",
			password:  "Abcdefg1",
			wantValid: true,
		},
		{
			name:      "long valid password",
			password:  "MyStr0ngPassword!",
			wantValid: true,
		},
		{
			name:       "empty password",
			password:   "",
			wantValid:  false,
			wantFailed: []string{"at least 8 characters", "one lowercase letter", "one uppercase letter", "one digit"},
		},
		{
			name:       "too short",
			password:   "Abc1",
			wantValid:  false,
			wantFailed: []string{"at least 8 characters"},
		},
		{
			name:       "no uppercase",
			password:   "abcdefg1",
			wantValid:  false,
			wantFailed: []string{"one uppercase letter"},
		},
		{
			name:       "no lowercase",
			password:   "ABCDEFG1",
			wantValid:  false,
			wantFailed: []string{"one lowercase letter"},
		},
		{
			name:       "no digit",
			password:   "Abcdefgh",
			wantValid:  false,
			wantFailed: []string{"one digit"},
		},
		{
			name:       "only digits",
			password:   "12345678",
			wantValid:  false,
			wantFailed: []string{"one lowercase letter", "one uppercase letter"},
		},
		{
			name:       "only lowercase",
			password:   "abcdefgh",
			wantValid:  false,
			wantFailed: []string{"one uppercase letter", "one digit"},
		},
		{
			name:       "only uppercase",
			password:   "ABCDEFGH",
			wantValid:  false,
			wantFailed: []string{"one lowercase letter", "one digit"},
		},
		{
			name:      "exactly 8 characters",
			password:  "Abcdef1x",
			wantValid: true,
		},
		{
			name:       "7 characters with all classes",
			password:   "Abcde1x",
			wantValid:  false,
			wantFailed: []string{"at least 8 characters"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failed []string
			for _, rule := range DefaultPasswordRules {
				if !rule.Validate(tt.password) {
					failed = append(failed, rule.String())
				}
			}

			got := len(failed) == 0
			if got != tt.wantValid {
				t.Errorf("valid = %v, want %v (failed: %v)", got, tt.wantValid, failed)
			}

			if !tt.wantValid {
				if len(failed) != len(tt.wantFailed) {
					t.Fatalf("failed rules = %v, want %v", failed, tt.wantFailed)
				}
				for i, desc := range tt.wantFailed {
					if failed[i] != desc {
						t.Errorf("failed[%d] = %q, want %q", i, failed[i], desc)
					}
				}
			}
		})
	}
}

func TestMinimumCustomLength(t *testing.T) {
	rule := Minimum(12)

	if rule.String() != "at least 12 characters" {
		t.Errorf("description = %q, want %q", rule.String(), "at least 12 characters")
	}

	if rule.Validate("short") {
		t.Error("expected 5-char string to fail minimum 12 rule")
	}

	if !rule.Validate("longpassword") {
		t.Error("expected 12-char string to pass minimum 12 rule")
	}
}

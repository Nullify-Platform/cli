package output

import (
	"testing"
)

func TestIsArray(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"array", `[{"id": 1}]`, true},
		{"object", `{"id": 1}`, false},
		{"empty array", `[]`, true},
		{"empty object", `{}`, false},
		{"invalid", `not json`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isArray([]byte(tt.data)); got != tt.want {
				t.Errorf("isArray(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"int float", float64(42), "42"},
		{"float", float64(3.14), "3.14"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"array", []any{1, 2, 3}, "[3 items]"},
		{"object", map[string]any{"a": 1}, "{1 keys}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatValue(tt.val); got != tt.want {
				t.Errorf("formatValue(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

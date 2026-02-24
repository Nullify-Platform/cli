package mcp

import (
	"strings"
	"testing"
)

func TestBuildQueryString(t *testing.T) {
	tests := []struct {
		name         string
		queryParams  map[string]string
		extra        []string
		wantEmpty    bool
		wantContains []string
	}{
		{
			name:        "empty params",
			queryParams: map[string]string{},
			extra:       nil,
			wantEmpty:   true,
		},
		{
			name:         "base params only",
			queryParams:  map[string]string{"orgId": "org-123"},
			wantContains: []string{"orgId=org-123"},
		},
		{
			name:         "extra params",
			queryParams:  map[string]string{"orgId": "org-123"},
			extra:        []string{"severity", "critical"},
			wantContains: []string{"orgId=org-123", "severity=critical"},
		},
		{
			name:        "skip empty extra",
			queryParams: map[string]string{},
			extra:       []string{"key", ""},
			wantEmpty:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildQueryString(tt.queryParams, tt.extra...)
			if tt.wantEmpty {
				if result != "" {
					t.Errorf("expected empty, got %q", result)
				}
				return
			}
			for _, s := range tt.wantContains {
				if !strings.Contains(result, s) {
					t.Errorf("expected %q to contain %q", result, s)
				}
			}
		})
	}
}

func TestGetStringArg(t *testing.T) {
	args := map[string]any{
		"name":  "test",
		"count": float64(42),
	}

	if got := getStringArg(args, "name"); got != "test" {
		t.Errorf("getStringArg(name) = %q, want %q", got, "test")
	}
	if got := getStringArg(args, "missing"); got != "" {
		t.Errorf("getStringArg(missing) = %q, want empty", got)
	}
	if got := getStringArg(args, "count"); got != "" {
		t.Errorf("getStringArg(count) = %q, want empty (wrong type)", got)
	}
}

func TestGetIntArg(t *testing.T) {
	args := map[string]any{
		"limit": float64(50),
		"page":  float64(3),
		"name":  "test",
	}

	if got := getIntArg(args, "limit", 20); got != 50 {
		t.Errorf("getIntArg(limit) = %d, want 50", got)
	}
	if got := getIntArg(args, "missing", 20); got != 20 {
		t.Errorf("getIntArg(missing) = %d, want 20 (default)", got)
	}
	if got := getIntArg(args, "name", 10); got != 10 {
		t.Errorf("getIntArg(name) = %d, want 10 (default for wrong type)", got)
	}
}

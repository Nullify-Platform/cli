package mcp

import (
	"sort"
	"testing"
)

func TestResolveFindingType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid sast", "sast", false},
		{"valid sca_dependency", "sca_dependency", false},
		{"valid sca_container", "sca_container", false},
		{"valid secrets", "secrets", false},
		{"valid pentest", "pentest", false},
		{"valid bughunt", "bughunt", false},
		{"valid cspm", "cspm", false},
		{"unknown type", "invalid", true},
		{"empty type", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := resolveFindingType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for type %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for type %q: %v", tt.input, err)
				return
			}
			if cfg.basePath == "" {
				t.Errorf("expected non-empty basePath for type %q", tt.input)
			}
		})
	}
}

func TestFilterTypesByCapability(t *testing.T) {
	tests := []struct {
		name     string
		capFn    func(findingTypeConfig) bool
		expected []string
	}{
		{
			name:     "triage support",
			capFn:    func(c findingTypeConfig) bool { return c.triage },
			expected: []string{"pentest", "sast", "sca_container", "sca_dependency", "secrets"},
		},
		{
			name:     "autofix support",
			capFn:    func(c findingTypeConfig) bool { return c.autofix },
			expected: []string{"sast", "sca_dependency"},
		},
		{
			name:     "ticket support",
			capFn:    func(c findingTypeConfig) bool { return c.ticket },
			expected: []string{"pentest", "sast", "sca_dependency", "secrets"},
		},
		{
			name:     "events support",
			capFn:    func(c findingTypeConfig) bool { return c.events },
			expected: []string{"pentest", "sast", "sca_dependency", "secrets"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterTypesByCapability(tt.capFn)
			sort.Strings(got)
			sort.Strings(tt.expected)

			if len(got) != len(tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("got %v, want %v", got, tt.expected)
					return
				}
			}
		})
	}
}

func TestAllFindingTypeNames(t *testing.T) {
	names := allFindingTypeNames()
	if len(names) != 7 {
		t.Errorf("expected 7 finding types, got %d: %v", len(names), names)
	}
}

func TestValidToolSets(t *testing.T) {
	sets := ValidToolSets()
	if len(sets) != 5 {
		t.Errorf("expected 5 tool sets, got %d: %v", len(sets), sets)
	}

	expected := map[string]bool{"default": true, "all": true, "minimal": true, "findings": true, "admin": true}
	for _, s := range sets {
		if !expected[s] {
			t.Errorf("unexpected tool set %q", s)
		}
	}
}

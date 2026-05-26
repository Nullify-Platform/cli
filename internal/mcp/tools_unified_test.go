package mcp

import (
	"reflect"
	"testing"
)

func TestResolveFindingType(t *testing.T) {
	for _, name := range []string{"sast", "sca_dependencies", "sca_containers", "secrets", "pentest", "bughunt", "cspm"} {
		ft, err := resolveFindingType(name)
		if err != nil {
			t.Errorf("unexpected error for type %q: %v", name, err)
			continue
		}
		if ft.apiType == "" {
			t.Errorf("expected non-empty apiType for %q", name)
		}
		if ft.get == nil {
			t.Errorf("expected a get method for %q", name)
		}
	}
	for _, bad := range []string{"invalid", ""} {
		if _, err := resolveFindingType(bad); err == nil {
			t.Errorf("expected error for type %q, got nil", bad)
		}
	}
}

func TestTypesWithCapability(t *testing.T) {
	cases := []struct {
		name string
		pick func(findingType) bool
		want []string
	}{
		{
			name: "allowlist",
			pick: func(ft findingType) bool { return ft.allowlist != nil },
			want: []string{"bughunt", "pentest", "sast", "sca_containers", "sca_dependencies", "secrets"},
		},
		{
			name: "autofix",
			pick: func(ft findingType) bool { return ft.autofixFix != nil },
			want: []string{"cspm", "pentest", "sast", "sca_containers", "sca_dependencies"},
		},
		{
			name: "ticket",
			pick: func(ft findingType) bool { return ft.ticket != nil },
			want: []string{"cspm", "pentest", "sast", "sca_containers", "sca_dependencies", "secrets"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := typesWith(tc.pick); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("typesWith(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestAllFindingTypeNames(t *testing.T) {
	if names := allFindingTypeNames(); len(names) != 7 {
		t.Errorf("expected 7 finding types, got %d: %v", len(names), names)
	}
}

func TestValidToolSets(t *testing.T) {
	sets := ValidToolSets()
	expected := map[string]bool{"default": true, "all": true, "minimal": true, "findings": true, "admin": true}
	if len(sets) != len(expected) {
		t.Errorf("expected %d tool sets, got %d: %v", len(expected), len(sets), sets)
	}
	for _, s := range sets {
		if !expected[s] {
			t.Errorf("unexpected tool set %q", s)
		}
	}
}

package commands

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestCheckSurface(t *testing.T) {
	base := SurfaceEntry{Command: "nullify api cspm list-scans", Route: "GET /cspm/scans", Args: "<id>", Flags: []string{"limit", "region"}}

	tests := []struct {
		name      string
		live      []SurfaceEntry
		decisions SurfaceDecisions
		want      error
	}{
		{name: "unchanged", live: []SurfaceEntry{base}},
		{
			name: "new flag and new command are allowed",
			live: []SurfaceEntry{
				{Command: base.Command, Route: base.Route, Args: base.Args, Flags: []string{"limit", "offset", "region"}},
				{Command: "nullify api cspm get-triage"},
			},
		},
		{name: "command gone", live: nil, want: ErrCommandDisappeared},
		{name: "command renamed", live: []SurfaceEntry{{Command: "nullify api cspm list-cspm-scans", Route: base.Route, Args: base.Args, Flags: base.Flags}}, want: ErrCommandDisappeared},
		{name: "command gone with a decision", live: nil, decisions: SurfaceDecisions{RemovedCommands: []RemovedCommand{{Command: base.Command}}}},
		{name: "flag gone", live: []SurfaceEntry{{Command: base.Command, Route: base.Route, Args: base.Args, Flags: []string{"limit"}}}, want: ErrFlagDisappeared},
		{name: "route changed", live: []SurfaceEntry{{Command: base.Command, Route: "GET /cspm/other", Args: base.Args, Flags: base.Flags}}, want: ErrRouteChanged},
		{
			name:      "route changed with a move",
			live:      []SurfaceEntry{{Command: base.Command, Route: "GET /context/scans", Args: base.Args, Flags: base.Flags}},
			decisions: SurfaceDecisions{Moved: []MovedCommand{{From: base.Command, To: "nullify api context list-scans"}}},
		},
		{name: "arguments changed", live: []SurfaceEntry{{Command: base.Command, Route: base.Route, Args: "<id> <other>", Flags: base.Flags}}, want: ErrArgsChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSurface([]SurfaceEntry{base}, tt.live, tt.decisions)

			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestCheckSnapshotComplete(t *testing.T) {
	listed := SurfaceEntry{Command: "nullify findings"}

	tests := []struct {
		name string
		live []SurfaceEntry
		want error
	}{
		{name: "all listed", live: []SurfaceEntry{listed}},
		{name: "new command not listed", live: []SurfaceEntry{listed, {Command: "nullify new"}}, want: ErrNotInSnapshot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, CheckSnapshotComplete([]SurfaceEntry{listed}, tt.live), tt.want)
		})
	}
}

func TestSurfaceFormatRoundTrip(t *testing.T) {
	entries := []SurfaceEntry{
		{Command: "nullify", Flags: []string{"host"}},
		{Command: "nullify api old", Args: "<id>", Route: "GET /new/{id}", Deprecated: true, Flags: []string{"data", "limit"}},
	}

	parsed, err := ParseSurface(FormatSurface(entries))

	require.ErrorIs(t, err, nil)
	require.Equal(t, entries, parsed)
}

func TestApplySurfaceDecisions(t *testing.T) {
	var ran []string
	target := &cobra.Command{
		Use:         "list-search <id>",
		Annotations: map[string]string{routeAnnotation: "GET /context/asset-graph/search"},
		RunE: func(_ *cobra.Command, args []string) error {
			ran = args
			return nil
		},
	}
	target.Flags().String("limit", "", "")

	api := &cobra.Command{Use: "api"}
	api.AddCommand(&cobra.Command{Use: "context"})
	api.Commands()[0].AddCommand(target)
	root := &cobra.Command{Use: "nullify"}
	root.AddCommand(api)

	ApplySurfaceDecisions(root, SurfaceDecisions{
		Moved:        []MovedCommand{{From: "nullify api asset-graph list-search", To: "nullify api context list-search"}},
		RetiredFlags: []RetiredFlag{{Command: "nullify api asset-graph list-search", Flag: "account-id", Evidence: "no effect"}},
	})

	root.SetArgs([]string{"api", "asset-graph", "list-search", "n1", "--limit", "5", "--account-id", "a1"})
	require.ErrorIs(t, root.Execute(), nil)

	alias, _, err := root.Find([]string{"api", "asset-graph", "list-search"})
	require.ErrorIs(t, err, nil)
	require.Equal(t, []string{"n1"}, ran)
	require.NotEmpty(t, alias.Deprecated)
	require.Equal(t, "GET /context/asset-graph/search", Route(alias))
	require.Equal(t, SurfaceEntry{
		Command:    "nullify api asset-graph list-search",
		Args:       "<id>",
		Route:      "GET /context/asset-graph/search",
		Deprecated: true,
		Flags:      []string{"account-id", "limit"},
	}, surfaceEntry(alias))
}

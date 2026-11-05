package commands

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Errors for a change to the command surface with no recorded decision.
var (
	ErrCommandDisappeared = errors.New("command disappeared without a recorded decision")
	ErrFlagDisappeared    = errors.New("flag disappeared without a recorded decision")
	ErrArgsChanged        = errors.New("positional arguments changed")
	ErrRouteChanged       = errors.New("route changed without a recorded move")
	ErrNotInSnapshot      = errors.New("command is not in the snapshot")
)

// SurfaceEntry is one line of the command surface snapshot.
type SurfaceEntry struct {
	Command    string
	Args       string
	Route      string
	Deprecated bool
	Flags      []string
}

// Surface walks a command tree and returns every command, sorted by path.
func Surface(root *cobra.Command) []SurfaceEntry {
	var entries []SurfaceEntry
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		entries = append(entries, surfaceEntry(cmd))
		for _, child := range cmd.Commands() {
			if child.Name() != "help" {
				walk(child)
			}
		}
	}
	walk(root)

	sort.Slice(entries, func(i, j int) bool { return entries[i].Command < entries[j].Command })
	return entries
}

func surfaceEntry(cmd *cobra.Command) SurfaceEntry {
	var flags []string
	collect := func(f *pflag.Flag) {
		if f.Name != "help" && f.Name != "version" {
			flags = append(flags, f.Name)
		}
	}
	cmd.LocalNonPersistentFlags().VisitAll(collect)
	cmd.PersistentFlags().VisitAll(collect)
	sort.Strings(flags)

	return SurfaceEntry{
		Command:    cmd.CommandPath(),
		Args:       strings.Join(strings.Fields(cmd.Use)[1:], " "),
		Route:      Route(cmd),
		Deprecated: cmd.Deprecated != "",
		Flags:      flags,
	}
}

// FormatSurface renders entries as the tab-separated snapshot text.
func FormatSurface(entries []SurfaceEntry) string {
	var sb strings.Builder
	for _, e := range entries {
		status := "active"
		if e.Deprecated {
			status = "deprecated"
		}
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%s\n", e.Command, e.Args, e.Route, strings.Join(e.Flags, ","), status)
	}
	return sb.String()
}

// ParseSurface reads the snapshot text.
func ParseSurface(text string) ([]SurfaceEntry, error) {
	var entries []SurfaceEntry
	for i, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			return nil, fmt.Errorf("surface line %d: want 5 fields, got %d", i+1, len(fields))
		}
		entry := SurfaceEntry{Command: fields[0], Args: fields[1], Route: fields[2], Deprecated: fields[4] == "deprecated"}
		if fields[3] != "" {
			entry.Flags = strings.Split(fields[3], ",")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CheckSurface reports every change from base to live that breaks a script and
// has no recorded decision. A new command or flag is not a break.
func CheckSurface(base, live []SurfaceEntry, decisions SurfaceDecisions) error {
	liveByCommand := map[string]SurfaceEntry{}
	for _, e := range live {
		liveByCommand[e.Command] = e
	}

	var errs []error
	for _, want := range base {
		got, ok := liveByCommand[want.Command]
		if !ok {
			if !decisions.commandRemoved(want.Command) {
				errs = append(errs, fmt.Errorf("%w: %s", ErrCommandDisappeared, want.Command))
			}
			continue
		}
		if got.Args != want.Args && !decisions.commandMoved(want.Command) {
			errs = append(errs, fmt.Errorf("%w: %s: %q to %q", ErrArgsChanged, want.Command, want.Args, got.Args))
		}
		if want.Route != "" && got.Route != want.Route && !decisions.commandMoved(want.Command) {
			errs = append(errs, fmt.Errorf("%w: %s: %s to %s", ErrRouteChanged, want.Command, want.Route, got.Route))
		}
		for _, flag := range want.Flags {
			if !slices.Contains(got.Flags, flag) {
				errs = append(errs, fmt.Errorf("%w: %s --%s", ErrFlagDisappeared, want.Command, flag))
			}
		}
	}
	return errors.Join(errs...)
}

// CheckSnapshotComplete reports a live command that the snapshot does not list.
func CheckSnapshotComplete(snapshot, live []SurfaceEntry) error {
	listed := map[string]bool{}
	for _, e := range snapshot {
		listed[e.Command] = true
	}

	var errs []error
	for _, e := range live {
		if !listed[e.Command] {
			errs = append(errs, fmt.Errorf("%w: %s", ErrNotInSnapshot, e.Command))
		}
	}
	return errors.Join(errs...)
}

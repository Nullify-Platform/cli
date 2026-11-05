package commands

import (
	"strings"

	"github.com/spf13/cobra"
)

// MovedCommand records a command whose API route moved. The old name stays as a
// deprecated alias that calls the new route.
type MovedCommand struct {
	From string
	To   string
}

// RemovedCommand records a command whose route the API no longer serves.
type RemovedCommand struct {
	Command  string
	Route    string
	Evidence string
}

// RetiredFlag records a flag whose query parameter the API no longer accepts. The
// flag stays accepted with a deprecation notice, so a script that passes it still
// runs, and it has no effect.
type RetiredFlag struct {
	Command  string
	Flag     string
	Evidence string
}

// SurfaceDecisions is the record of every approved change to the command surface.
type SurfaceDecisions struct {
	Moved           []MovedCommand
	RemovedCommands []RemovedCommand
	RetiredFlags    []RetiredFlag
}

func (d SurfaceDecisions) commandMoved(command string) bool {
	for _, m := range d.Moved {
		if m.From == command {
			return true
		}
	}
	return false
}

func (d SurfaceDecisions) commandRemoved(command string) bool {
	for _, r := range d.RemovedCommands {
		if r.Command == command {
			return true
		}
	}
	return false
}

// ApplySurfaceDecisions adds a deprecated alias for every moved command and a
// deprecated no-op flag for every retired flag. Call it after all other commands
// are registered. A row whose target is absent has no effect here, and the surface
// check then reports the missing command or flag.
func ApplySurfaceDecisions(root *cobra.Command, decisions SurfaceDecisions) {
	registerMovedCommands(root, decisions.Moved)

	for _, r := range decisions.RetiredFlags {
		cmd, _, err := root.Find(strings.Fields(r.Command)[1:])
		if err != nil || cmd.CommandPath() != r.Command {
			continue
		}
		cmd.Flags().String(r.Flag, "", r.Evidence)
		_ = cmd.Flags().MarkDeprecated(r.Flag, r.Evidence)
	}
}

func registerMovedCommands(root *cobra.Command, moved []MovedCommand) {
	for _, m := range moved {
		target, _, err := root.Find(strings.Fields(m.To)[1:])
		if err != nil || target.CommandPath() != m.To {
			continue
		}

		from := strings.Fields(m.From)[1:]
		parent := ensureGroup(root, from[:len(from)-1])
		parent.AddCommand(aliasFor(target, from[len(from)-1], m.To))
	}
}

func ensureGroup(root *cobra.Command, path []string) *cobra.Command {
	parent := root
	for _, name := range path {
		child := findChild(parent, name)
		if child == nil {
			child = &cobra.Command{Use: name, Short: "Deprecated: see the moved commands in the changelog"}
			parent.AddCommand(child)
		}
		parent = child
	}
	return parent
}

func aliasFor(target *cobra.Command, name, to string) *cobra.Command {
	alias := &cobra.Command{
		Use:         strings.Join(append([]string{name}, strings.Fields(target.Use)[1:]...), " "),
		Short:       target.Short,
		Long:        target.Long,
		Args:        target.Args,
		RunE:        target.RunE,
		Annotations: target.Annotations,
		Deprecated:  "use `" + to + "`, which calls the new route",
	}
	alias.Flags().AddFlagSet(target.Flags())
	return alias
}

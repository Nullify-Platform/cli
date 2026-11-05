package mcp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// Errors for a change to the MCP tools with no recorded decision.
var (
	ErrToolDisappeared = errors.New("MCP tool disappeared without a recorded decision")
	ErrToolChanged     = errors.New("MCP tool changed its annotation or tool sets without a recorded decision")
)

// ToolDecisions records each deliberate break of the MCP tool surface, with the evidence.
type ToolDecisions struct {
	// Removed are tools that left.
	Removed map[string]string
	// Changed are tools that changed their annotation or their tool sets.
	Changed map[string]string
}

// Decisions holds the recorded decisions for the MCP tools.
var Decisions = ToolDecisions{
	Removed: map[string]string{
		"list_escalations": "GET /manager/escalations is gone from prod (#5596), so the tool only returned errors. list_action_items returns a different schema, so it is not an alias.",
	},
}

// ToolEntry is one line of the MCP tool snapshot.
type ToolEntry struct {
	Name string
	// Annotation is read-only, destructive, or write for a tool that changes state
	// but is not marked destructive.
	Annotation string
	Sets       []string
}

// ToolSurface returns every MCP tool with its access and its tool sets, sorted by name.
func ToolSurface() []ToolEntry {
	entries := map[string]*ToolEntry{}
	for _, set := range ValidToolSets() {
		s := NewServer(nil, ToolSet(set), Orgs{})

		for name, tool := range s.ListTools() {
			if entries[name] == nil {
				entries[name] = &ToolEntry{Name: name, Annotation: annotationOf(tool.Tool.Annotations)}
			}
			entries[name].Sets = append(entries[name].Sets, set)
		}
	}

	var surface []ToolEntry
	for _, entry := range entries {
		slices.Sort(entry.Sets)
		surface = append(surface, *entry)
	}
	slices.SortFunc(surface, func(a, b ToolEntry) int { return strings.Compare(a.Name, b.Name) })
	return surface
}

func annotationOf(a mcp.ToolAnnotation) string {
	switch {
	case a.ReadOnlyHint != nil && *a.ReadOnlyHint:
		return "read-only"
	case a.DestructiveHint != nil && *a.DestructiveHint:
		return "destructive"
	default:
		return "write"
	}
}

// FormatToolSurface renders entries as the tab-separated snapshot text.
func FormatToolSurface(entries []ToolEntry) string {
	var sb strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&sb, "%s\t%s\t%s\n", e.Name, e.Annotation, strings.Join(e.Sets, ","))
	}
	return sb.String()
}

// ParseToolSurface reads the snapshot text. An empty text has no tools.
func ParseToolSurface(text string) ([]ToolEntry, error) {
	var entries []ToolEntry
	for i, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("tool surface line %d: want 3 fields, got %d", i+1, len(fields))
		}
		entries = append(entries, ToolEntry{Name: fields[0], Annotation: fields[1], Sets: strings.Split(fields[2], ",")})
	}
	return entries, nil
}

// CheckToolSurface reports every tool in base that live does not have, or that
// has another annotation or other tool sets in live, unless decisions records it.
func CheckToolSurface(base, live []ToolEntry, decisions ToolDecisions) error {
	liveByName := map[string]ToolEntry{}
	for _, e := range live {
		liveByName[e.Name] = e
	}

	var errs []error
	for _, want := range base {
		got, ok := liveByName[want.Name]
		_, removed := decisions.Removed[want.Name]
		_, changed := decisions.Changed[want.Name]
		switch {
		case !ok && !removed:
			errs = append(errs, fmt.Errorf("%w: %s", ErrToolDisappeared, want.Name))
		case ok && !changed && (got.Annotation != want.Annotation || !slices.Equal(got.Sets, want.Sets)):
			errs = append(errs, fmt.Errorf("%w: %s: %s %v to %s %v", ErrToolChanged, want.Name, want.Annotation, want.Sets, got.Annotation, got.Sets))
		}
	}
	return errors.Join(errs...)
}

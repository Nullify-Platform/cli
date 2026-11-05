package mcp

// ToolSet controls which MCP tools are registered.
type ToolSet string

const (
	ToolSetDefault  ToolSet = "default"
	ToolSetAll      ToolSet = "all"
	ToolSetMinimal  ToolSet = "minimal"
	ToolSetFindings ToolSet = "findings"
	ToolSetAdmin    ToolSet = "admin"
	// ToolSetFindingsWrite adds the finding tools that are kept out of the default
	// set: archive, unarchive, mark and unmark false positive, and delete ticket.
	ToolSetFindingsWrite ToolSet = "findings-write"
)

// ValidToolSets returns all valid tool set names for flag validation.
func ValidToolSets() []string {
	return []string{
		string(ToolSetDefault),
		string(ToolSetAll),
		string(ToolSetMinimal),
		string(ToolSetFindings),
		string(ToolSetAdmin),
		string(ToolSetFindingsWrite),
	}
}

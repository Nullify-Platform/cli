package mcp

// ToolSet controls which MCP tools are registered.
type ToolSet string

const (
	ToolSetDefault  ToolSet = "default"
	ToolSetAll      ToolSet = "all"
	ToolSetMinimal  ToolSet = "minimal"
	ToolSetFindings ToolSet = "findings"
	ToolSetAdmin    ToolSet = "admin"
)

// ValidToolSets returns all valid tool set names for flag validation.
func ValidToolSets() []string {
	return []string{
		string(ToolSetDefault),
		string(ToolSetAll),
		string(ToolSetMinimal),
		string(ToolSetFindings),
		string(ToolSetAdmin),
	}
}
